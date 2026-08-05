"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 3: Cloud Server REST API (FastAPI)
Week 5 Update: Access Control & GDPR Consent Toggle (AAA Enforcement)

Exposes the secure ingestion/aggregation surface that a real cloud backend
would present to edge gateways and authorized analytics consumers.

Security & Compliance Notes (GDPR / CIA / AAA):
------------------------------------------------
- ``POST /api/v1/telemetry/ingest`` is the ONLY write path into storage, and it
  is strictly validated by Pydantic models to accept nothing but hex-encoded
  ``nonce``/``ciphertext`` plus routing metadata (data minimization by design —
  GDPR Art. 5(1)(c): no more data than necessary is ever accepted or stored).
- Rate limiting on the ingestion endpoint (default: 60 requests / minute per
  client IP) defends against bulk-flood / denial-of-service attacks that would
  exhaust disk space or CPU on the storage tier.
- ``GET /api/v1/telemetry/stored-ciphertexts`` intentionally requires NO special
  authorization, because it is designed to be safely public: it proves that
  even a stolen database dump or an unauthorized third-party API read yields
  only authenticated ciphertext ("encrypted noise"), never raw biometrics —
directly mitigating tactical performance espionage. Supports ``offset``/
  ``limit`` query parameters for pagination so large databases stay responsive.
- ``POST /api/v1/athlete/consent`` (NEW — Week 5): accepts athlete consent status
  updates (``player_id`` + ``privacy_toggle_consent`` flag) and stores them in
  the in-process ``ConsentRegistry``.  Any subsequent decryption request for a
  player with consent revoked is rejected with HTTP 403, implementing GDPR
  Art. 7(3) (right to withdraw consent) and Art. 17 (right to be forgotten).
- ``POST /api/v1/telemetry/authorize-decrypt`` (UPDATED — Week 5) now enforces
  a three-gate authorization chain before reconstructing any plaintext:

  1. **GDPR Consent Gate** — rejects with HTTP 403 if the athlete has revoked
     consent in the ``ConsentRegistry``, regardless of the caller's role.
  2. **RBAC Role Gate** — rejects with HTTP 403 if ``user_role`` is not in the
     ``AUTHORIZED_DECRYPT_ROLES`` allow-list (currently only ``TEAM_DOCTOR``).
  3. **Cryptographic Gate** — decryption proceeds only after both gates pass;
     a wrong AES key still yields HTTP 401 (``InvalidTag``).

  This models a production AAA (Authentication, Authorization, Accounting)
  workflow: API key = Authentication; consent + role = Authorization;
  structured server logs = Accounting.
- ``DELETE /api/v1/telemetry/records/{index}`` provides GDPR Art. 17 "right to
  erasure" for an individual stored record, protected by the shared API key.
- Running under ``uvicorn`` (ASGI) keeps the ingestion endpoint responsive and
  horizontally scalable, supporting the Availability leg of the CIA triad for
  continuous, real-time telemetry ingestion during a live match.
"""

from __future__ import annotations

import binascii
import collections
import threading
import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator

from cloud_server import AUTHORIZED_DECRYPT_ROLES, CloudServer, ConsentRegistry
from config import settings
from logging_config import configure_logging, get_logger
from secure_gateway import SecureGateway

configure_logging()
logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Simple in-process sliding-window rate limiter for the ingestion endpoint.
# Tracks request timestamps per client IP; rejects clients that exceed
# INGEST_RATE_LIMIT requests within INGEST_RATE_WINDOW_SECONDS.
# ---------------------------------------------------------------------------
_INGEST_RATE_LIMIT: int = 60          # max requests per window
_INGEST_RATE_WINDOW_SECONDS: float = 60.0  # rolling window duration

_rate_limit_store: Dict[str, collections.deque] = {}
_rate_limit_lock = threading.Lock()


def _check_ingest_rate_limit(client_ip: str) -> None:
    """
    Enforce a sliding-window rate limit for a given ``client_ip``.

    Raises:
        HTTPException: 429 Too Many Requests if the caller has exceeded
                       ``_INGEST_RATE_LIMIT`` requests in the last
                       ``_INGEST_RATE_WINDOW_SECONDS`` seconds.
    """
    now = time.monotonic()
    with _rate_limit_lock:
        if client_ip not in _rate_limit_store:
            _rate_limit_store[client_ip] = collections.deque()
        window: collections.deque = _rate_limit_store[client_ip]
        # Evict timestamps that have fallen outside the sliding window.
        while window and now - window[0] > _INGEST_RATE_WINDOW_SECONDS:
            window.popleft()
        if len(window) >= _INGEST_RATE_LIMIT:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Rate limit exceeded: maximum {_INGEST_RATE_LIMIT} ingestion "
                    f"requests per {_INGEST_RATE_WINDOW_SECONDS:.0f}s window."
                ),
            )
        window.append(now)


app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Week 5: GDPR Consent Management, Role-Based Access Control (RBAC), "
        "and AES-256-GCM protected athlete biometric telemetry pipeline."
    ),
    version="5.0.0",
)

cloud_server = CloudServer(db_path=settings.MOCK_DB_PATH)

# Week 5: global consent registry (single source of truth for GDPR consent state)
consent_registry = ConsentRegistry()


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """
    Structured request/response logging middleware.

    Logs method, path, status code, and latency for every request. Never
    logs request bodies (which may contain hex ciphertext/nonce — harmless,
    but kept out of logs anyway as a conservative default).
    """
    start = time.perf_counter()
    response = await call_next(request)
    duration_ms = (time.perf_counter() - start) * 1000
    logger.info(
        "%s %s -> %d (%.1fms)",
        request.method, request.url.path, response.status_code, duration_ms,
    )
    return response


async def require_api_key(x_api_key: Optional[str] = Header(default=None)) -> None:
    """
    FastAPI dependency enforcing a shared-secret `X-API-Key` header on
    sensitive endpoints (ingestion, authorized decryption).

    The public "stored-ciphertexts" endpoint deliberately omits this
    dependency, since it is designed to be safely exposed even to
    unauthenticated/unauthorized third parties (see module docstring).

    Raises:
        HTTPException: 401 if the header is missing or does not match
                        `settings.CLOUD_API_KEY`.
    """
    if not x_api_key or x_api_key != settings.CLOUD_API_KEY:
        logger.warning("Rejected request due to missing/invalid X-API-Key.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-API-Key header.",
        )


def _is_hex(value: str) -> bool:
    try:
        bytes.fromhex(value)
        return True
    except (ValueError, TypeError):
        return False


class TelemetryIngestRequest(BaseModel):
    """
    Strict Pydantic contract for the hex-encoded encrypted packet produced by
    `SecureGateway.encrypt_data()`. Deliberately contains NO plaintext
    biometric fields — enforcing data minimization at the API boundary.
    """

    gateway_id: str = Field(..., min_length=1, description="Originating edge gateway identifier.")
    device_id: Optional[str] = Field(None, description="Originating wearable device identifier.")
    player_id: Optional[str] = Field(None, description="Athlete identifier (context only, not PII value).")
    sent_at: Optional[str] = Field(None, description="UTC ISO-8601 timestamp bound into the AAD.")
    nonce: str = Field(..., description="Hex-encoded 96-bit AES-GCM nonce.")
    ciphertext: str = Field(..., description="Hex-encoded AES-256-GCM ciphertext (includes auth tag).")

    @field_validator("nonce", "ciphertext")
    @classmethod
    def _must_be_hex(cls, value: str) -> str:
        if not _is_hex(value):
            raise ValueError("must be a valid hex-encoded string")
        return value


class TelemetryIngestResponse(BaseModel):
    """Confirmation response returned after successful encrypted ingestion."""

    status: str
    message: str
    gateway_id: str
    stored_record_count: int


class StoredCiphertextsResponse(BaseModel):
    """Paginated response for the stored-ciphertexts listing endpoint."""

    total: int
    offset: int
    limit: int
    records: List[Dict[str, Any]]


class DeleteRecordResponse(BaseModel):
    """Confirmation response returned after successfully deleting a record."""

    status: str
    message: str
    deleted_record: Dict[str, Any]
    remaining_record_count: int


class AuthorizeDecryptRequest(BaseModel):
    """
    Request contract for authorized decryption of a previously ingested (or
    directly supplied) encrypted record. Requires the caller to present the
    correct pre-shared AES-256 key (hex-encoded, 32 bytes / 64 hex chars) —
    modeling an authenticated analyst/coaching-staff access path, distinct
    from the untrusted public storage tier.
    """

    record: TelemetryIngestRequest = Field(..., description="Encrypted packet to decrypt.")
    aes_key_hex: str = Field(
        ..., min_length=64, max_length=64, description="Hex-encoded 256-bit shared AES key."
    )
    max_age_seconds: Optional[float] = Field(
        None, description="Optional freshness window to reject stale/replayed packets."
    )

    @field_validator("aes_key_hex")
    @classmethod
    def _must_be_hex_key(cls, value: str) -> str:
        if not _is_hex(value):
            raise ValueError("aes_key_hex must be a valid hex-encoded string")
        return value


class AuthorizeDecryptResponse(BaseModel):
    """Response contract carrying the decrypted plaintext biometric payload."""

    status: str
    decrypted_payload: Any


class HealthResponse(BaseModel):
    """Response contract for the health-check / liveness probe endpoint."""

    status: str
    environment: str
    stored_record_count: int


# ---------------------------------------------------------------------------
# Week 5 — GDPR Consent Management Models
# ---------------------------------------------------------------------------

class ConsentUpdateRequest(BaseModel):
    """
    Request contract for the GDPR consent toggle endpoint.

    An athlete (via their ``AthleteDashboard`` client) sends their
    ``player_id`` and new ``privacy_toggle_consent`` flag.  The server
    records this in the ``ConsentRegistry`` and all subsequent
    ``authorize-decrypt`` calls for that player will respect the new state.
    """

    player_id: str = Field(..., min_length=1, description="Athlete unique identifier.")
    privacy_toggle_consent: bool = Field(
        ...,
        description=(
            "True = consent granted (authorized roles may decrypt). "
            "False = consent revoked (all decryption blocked per GDPR Art. 7(3))."
        ),
    )


class ConsentUpdateResponse(BaseModel):
    """Confirmation response returned after a successful consent state update."""

    status: str
    player_id: str
    privacy_toggle_consent: bool
    message: str


@app.get("/health", response_model=HealthResponse, tags=["ops"])
def health_check() -> HealthResponse:
    """
    Liveness/readiness probe for orchestrators (Docker healthcheck, Kubernetes
    probes, load balancers). Returns 200 with basic service status —
    standard practice for any production HTTP service.
    """
    return HealthResponse(
        status="ok",
        environment=settings.ENVIRONMENT,
        stored_record_count=len(cloud_server.get_all_stored_records()),
    )


@app.post(
    "/api/v1/telemetry/ingest",
    response_model=TelemetryIngestResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_api_key)],
)
def ingest_telemetry(
    request: Request,
    payload: TelemetryIngestRequest,
) -> TelemetryIngestResponse:
    """
    Ingest a single hex-encoded encrypted biometric telemetry packet from an
    edge `SecureGateway` and persist it to `mock_db.json`.

    Requires a valid `X-API-Key` header (edge gateways are provisioned with
    this shared secret out-of-band, e.g., during device enrollment).

    Rate-limited to prevent bulk-flood / DoS attacks that could exhaust
    storage resources (60 requests per minute per client IP by default).

    Data minimization: only `nonce`/`ciphertext` (plus routing metadata) are
    ever accepted or stored — no plaintext biometric field exists in the
    request schema, so none can ever reach storage.
    """
    client_ip = request.client.host if request.client else "unknown"
    _check_ingest_rate_limit(client_ip)

    record: Dict[str, Any] = payload.model_dump(exclude_none=True)

    try:
        cloud_server.store_encrypted_payload(record)
    except ValueError as exc:
        logger.error("Ingestion rejected for gateway_id=%s: %s", payload.gateway_id, exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    stored_count = len(cloud_server.get_all_stored_records())
    logger.info(
        "Ingested encrypted packet gateway_id=%s device_id=%s (total stored=%d)",
        payload.gateway_id, payload.device_id, stored_count,
    )
    return TelemetryIngestResponse(
        status="success",
        message="Encrypted telemetry packet stored successfully.",
        gateway_id=payload.gateway_id,
        stored_record_count=stored_count,
    )


@app.get(
    "/api/v1/telemetry/stored-ciphertexts",
    response_model=StoredCiphertextsResponse,
)
def get_stored_ciphertexts(
    offset: int = Query(default=0, ge=0, description="Zero-based index of the first record to return."),
    limit: int = Query(default=50, ge=1, le=200, description="Maximum number of records to return (1–200)."),
) -> StoredCiphertextsResponse:
    """
    Return a paginated slice of records currently stored in `mock_db.json`.

    Intentionally requires no authorization: this endpoint serves as a live
    proof-of-concept that a stolen database dump or unauthorized third-party
    API read discloses only authenticated ciphertext ("encrypted noise"),
    never raw athlete biometrics — mitigating tactical performance espionage.

    Use the ``offset`` and ``limit`` query parameters to page through large
    result sets without loading the entire database into memory at once.
    """
    page = cloud_server.get_stored_records_page(offset=offset, limit=limit)
    return StoredCiphertextsResponse(**page)


@app.delete(
    "/api/v1/telemetry/records/{index}",
    response_model=DeleteRecordResponse,
    dependencies=[Depends(require_api_key)],
)
def delete_record(index: int) -> DeleteRecordResponse:
    """
    Permanently delete a single stored encrypted record by its zero-based
    position in the database (GDPR Art. 17 — right to erasure).

    Requires a valid `X-API-Key` header. Only the ciphertext/nonce envelope
    is ever removed; no plaintext biometric data is involved.

    Args:
        index: Zero-based position of the record to delete.

    Raises:
        HTTPException: 404 if the given index is outside the valid range.
    """
    try:
        deleted = cloud_server.delete_record(index)
    except IndexError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    remaining = len(cloud_server.get_all_stored_records())
    logger.info(
        "Deleted record at index=%d (remaining=%d)", index, remaining
    )
    return DeleteRecordResponse(
        status="success",
        message=f"Record at index {index} permanently deleted (GDPR Art. 17 erasure).",
        deleted_record=deleted,
        remaining_record_count=remaining,
    )


# ---------------------------------------------------------------------------
# Week 5 — GDPR Consent Management Endpoint
# ---------------------------------------------------------------------------

@app.post(
    "/api/v1/athlete/consent",
    response_model=ConsentUpdateResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_api_key)],
    tags=["consent"],
)
def update_athlete_consent(payload: ConsentUpdateRequest) -> ConsentUpdateResponse:
    """
    Update an athlete's GDPR consent flag in the server-side ``ConsentRegistry``.

    This is the server-side complement to ``AthleteDashboard.update_consent()``.
    Once this endpoint is called with ``privacy_toggle_consent = False``, the
    server immediately begins blocking all ``authorize-decrypt`` requests for
    the specified ``player_id``, regardless of the caller's role.

    Implements:
    - GDPR Art. 7(3): Right to withdraw consent at any time.
    - GDPR Art. 17: Right to be forgotten (by blocking re-construction of
      plaintext biometrics until consent is re-granted).

    Requires a valid ``X-API-Key`` header (only provisioned gateways / coaching
    staff dashboards may update consent on behalf of the athlete system).
    """
    try:
        consent_registry.set_consent(payload.player_id, payload.privacy_toggle_consent)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc

    action = "GRANTED" if payload.privacy_toggle_consent else "REVOKED"
    logger.info(
        "GDPR consent %s for player_id=%s via /api/v1/athlete/consent",
        action, payload.player_id,
    )
    return ConsentUpdateResponse(
        status="success",
        player_id=payload.player_id,
        privacy_toggle_consent=payload.privacy_toggle_consent,
        message=(
            f"Consent {action} for athlete {payload.player_id}. "
            f"All subsequent decryption requests will respect this setting."
        ),
    )


@app.post(
    "/api/v1/telemetry/authorize-decrypt",
    response_model=AuthorizeDecryptResponse,
    dependencies=[Depends(require_api_key)],
)
def authorize_decrypt(
    request: AuthorizeDecryptRequest,
    user_role: str = Header(
        ...,
        description="Requesting party role (e.g., TEAM_DOCTOR, ANALYST, EXTERNAL_COMPANY).",
        alias="X-User-Role",
    ),
    player_id: str = Header(
        ...,
        description="Athlete player ID whose record is being decrypted.",
        alias="X-Player-Id",
    ),
) -> AuthorizeDecryptResponse:
    """
    Authorized decryption of a biometric record — Week 5 AAA-enforced path.

    The request passes through THREE sequential security gates before any
    plaintext is ever reconstructed:

    **Gate 1 — API Key Authentication** (enforced by the ``require_api_key``
    FastAPI dependency above; returns 401 if missing/wrong).

    **Gate 2 — GDPR Consent Check** (new in Week 5):
    Reads ``player_id`` from the ``X-Player-Id`` request header and queries
    the ``ConsentRegistry``.  If ``privacy_toggle_consent == False`` for this
    athlete, the request is rejected immediately with HTTP 403:
    ``"Access Denied: Athlete has revoked biometric consent under GDPR."
    No decryption key is touched; no plaintext is produced.

    **Gate 3 — Role-Based Access Control (RBAC)** (new in Week 5):
    Reads ``user_role`` from the ``X-User-Role`` request header and checks it
    against ``AUTHORIZED_DECRYPT_ROLES`` (allow-list in ``cloud_server.py``).
    Any role not on the list (e.g., ``ANALYST``, ``EXTERNAL_COMPANY``) is
    rejected with HTTP 403:
    ``"Access Denied: Insufficient Role Permissions."
    Only ``TEAM_DOCTOR`` is currently permitted.

    **Gate 4 — Cryptographic Decryption**:
    After passing the above checks, a ``SecureGateway`` instance is
    reconstructed with the supplied AES key and ``decrypt_data()`` is called.
    A wrong key still yields HTTP 401 (``cryptography.exceptions.InvalidTag``).
    """
    # ------------------------------------------------------------------ #
    # GATE 2: GDPR Consent Check                                          #
    # ------------------------------------------------------------------ #
    if not consent_registry.is_consent_granted(player_id):
        logger.warning(
            "GDPR consent check FAILED for player_id=%s user_role=%s — access denied.",
            player_id, user_role,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Athlete has revoked biometric consent under GDPR.",
        )

    # ------------------------------------------------------------------ #
    # GATE 3: Role-Based Access Control (RBAC)                            #
    # ------------------------------------------------------------------ #
    if user_role not in AUTHORIZED_DECRYPT_ROLES:
        logger.warning(
            "RBAC check FAILED: user_role=%s is not authorised to decrypt "
            "biometric data for player_id=%s.",
            user_role, player_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Insufficient Role Permissions.",
        )

    # ------------------------------------------------------------------ #
    # GATE 4: Cryptographic Decryption                                    #
    # ------------------------------------------------------------------ #
    try:
        aes_key = bytes.fromhex(request.aes_key_hex)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid aes_key_hex."
        ) from exc

    if len(aes_key) != 32:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="aes_key_hex must decode to exactly 32 bytes (256 bits).",
        )

    encrypted_packet = request.record.model_dump(exclude_none=True)
    max_age = request.max_age_seconds if request.max_age_seconds is not None else settings.MAX_PACKET_AGE_SECONDS

    try:
        gateway = SecureGateway(gateway_id=encrypted_packet["gateway_id"], aes_key=aes_key)
        decrypted_payload = gateway.decrypt_data(
            encrypted_packet, max_age_seconds=max_age
        )
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception as exc:  # cryptography.exceptions.InvalidTag, etc.
        logger.warning("Authorized decryption failed: %s", exc.__class__.__name__)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Decryption/authentication failed: {exc.__class__.__name__}",
        ) from exc

    logger.info(
        "Authorized decryption SUCCEEDED for player_id=%s gateway_id=%s user_role=%s",
        player_id,
        encrypted_packet.get("gateway_id"),
        user_role,
    )
    return AuthorizeDecryptResponse(status="success", decrypted_payload=decrypted_payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main_server:app", host=settings.HOST, port=settings.PORT, reload=True)
