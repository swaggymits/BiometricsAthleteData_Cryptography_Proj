"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 3: Cloud Server REST API (FastAPI)
Week 5 Update: Access Control & GDPR Consent Toggle (AAA Enforcement)
Week 6 Update: Audit Logging & Anti-Black Market Protection (AAA Accounting / GDPR Art. 5(2))
Week 7 Update: Local Hashed Ledger & Transfer Escrow Simulation (Integrity / CIA Triad)
Task 1 — Week 8 Update: Hybrid ECDH Key Exchange Endpoints
  — ClubKeyRegistry (in-memory, thread-safe club public-key store)
  — POST /api/v1/keys/register-club  (athlete authorizes a purchasing club)
  — POST /api/v1/keys/revoke-club    (athlete revokes a club's authorization)
  — POST /api/v1/telemetry/authorize-decrypt-hybrid (ECDH session-key decryption)

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
- ``POST /api/v1/telemetry/authorize-decrypt`` additionally writes a row to
  ``audit_log.csv`` (via ``AuditLogger``) on *every* call — success or denial —
  providing a tamper-evident access trail for forensic investigation of any
  potential biometric data leak (GDPR Art. 5(2); AAA Accounting leg).
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

# Week 8: ECDH hybrid imports
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator

from audit_logger import AuditLogger
from cloud_server import AUTHORIZED_DECRYPT_ROLES, CloudServer, ConsentRegistry
from config import settings
from ecdh_key_exchange import deserialize_public_key
from local_hashed_ledger import LocalHashedLedger
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
        "Week 7: Local Hashed Ledger & Transfer Escrow — SHA-256 blockchain "
        "committing athlete transfer events with GDPR consent gating, escrow "
        "verification, and full AAA audit trail across all endpoints."
    ),
    version="7.0.0",
)

cloud_server = CloudServer(db_path=settings.MOCK_DB_PATH)

# Week 5: global consent registry (single source of truth for GDPR consent state)
consent_registry = ConsentRegistry()

# Week 6: module-level audit logger — path configurable via AUDIT_LOG_PATH env var
# so Docker can persist the CSV to the /data named volume across restarts.
audit_logger = AuditLogger(log_file_path=settings.AUDIT_LOG_PATH)

# Week 7: module-level SHA-256 blockchain ledger — path configurable via LEDGER_FILE_PATH
# env var so Docker can persist the ledger to the /data named volume across restarts.
ledger = LocalHashedLedger(ledger_file_json=settings.LEDGER_FILE_PATH)


# ---------------------------------------------------------------------------
# Task 1 — Week 8: Club Key Registry
# ---------------------------------------------------------------------------

class ClubKeyRegistry:
    """
    Thread-safe in-memory registry mapping ``club_id`` → PEM public key bytes.

    Stores the NIST P-256 public keys that authorized purchasing clubs have
    submitted for ECDH key exchange. The athlete's ``AthleteDashboard`` acts
    as the authorization gatekeeper: clubs must be registered here before the
    gateway can use their key in ``encrypt_data_hybrid()``, and before the
    ``authorize-decrypt-hybrid`` endpoint will accept their private-key-based
    decryption requests.

    This is intentionally in-memory only (like ``ConsentRegistry``) for this
    academic prototype. A production system would persist keys to a dedicated,
    audited key-management service (e.g., Google Cloud KMS, AWS KMS).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._registry: Dict[str, bytes] = {}  # {club_id: pem_bytes}

    def register_club(
        self, club_id: str, public_key_pem: str
    ) -> None:
        """
        Store or update the PEM public key for the given club.

        Args:
            club_id (str): Unique club identifier.
            public_key_pem (str): PEM-encoded NIST P-256 public key string.

        Raises:
            ValueError: If ``club_id`` is empty or the PEM cannot be parsed as
                        a valid EC public key.
        """
        if not club_id or not isinstance(club_id, str):
            raise ValueError("club_id must be a non-empty string.")
        pem_bytes = public_key_pem.encode("utf-8") if isinstance(public_key_pem, str) else public_key_pem
        # Validate the key before storing — reject garbage PEM early.
        try:
            deserialize_public_key(pem_bytes)
        except Exception as exc:
            raise ValueError(
                f"Invalid EC public key PEM for club {club_id!r}: {exc}"
            ) from exc
        with self._lock:
            self._registry[club_id] = pem_bytes

    def revoke_club(self, club_id: str) -> bool:
        """
        Remove a club's public key from the registry.

        Returns:
            bool: ``True`` if the club was present and removed; ``False`` if not found.
        """
        with self._lock:
            if club_id in self._registry:
                del self._registry[club_id]
                return True
            return False

    def get_public_key_pem(self, club_id: str) -> bytes:
        """
        Retrieve the PEM public key for a registered club.

        Raises:
            KeyError: If ``club_id`` is not registered.
        """
        with self._lock:
            if club_id not in self._registry:
                raise KeyError(
                    f"Club {club_id!r} is not registered in the ClubKeyRegistry."
                )
            return self._registry[club_id]

    def is_registered(self, club_id: str) -> bool:
        """Return True if the club has a registered public key."""
        with self._lock:
            return club_id in self._registry

    def get_all_clubs(self) -> Dict[str, Any]:
        """Return a snapshot of all registered club IDs (keys omitted for brevity)."""
        with self._lock:
            return {"registered_clubs": sorted(self._registry.keys())}


# Module-level singleton — same pattern as consent_registry.
club_key_registry = ClubKeyRegistry()


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
    `SecureGateway.encrypt_data()` or `SecureGateway.encrypt_data_hybrid()`.
    Deliberately contains NO plaintext biometric fields — enforcing data
    minimization at the API boundary.

    Week 8 additions (optional fields for ECDH hybrid packets):
    - ``ephemeral_public_key_pem``: The gateway's ephemeral NIST P-256 public
      key (PEM string). Only present in hybrid-encrypted packets.
    - ``club_id``: The authorized purchasing club identifier bound into the
      HKDF session context. Only present in hybrid-encrypted packets.
    """

    gateway_id: str = Field(..., min_length=1, description="Originating edge gateway identifier.")
    device_id: Optional[str] = Field(None, description="Originating wearable device identifier.")
    player_id: Optional[str] = Field(None, description="Athlete identifier (context only, not PII value).")
    sent_at: Optional[str] = Field(None, description="UTC ISO-8601 timestamp bound into the AAD.")
    nonce: str = Field(..., description="Hex-encoded 96-bit AES-GCM nonce.")
    ciphertext: str = Field(..., description="Hex-encoded AES-256-GCM ciphertext (includes auth tag).")
    # Week 8: ECDH hybrid fields (optional — absent for legacy symmetric packets)
    ephemeral_public_key_pem: Optional[str] = Field(
        None,
        description="(Hybrid only) PEM-encoded NIST P-256 ephemeral public key of the originating gateway.",
    )
    club_id: Optional[str] = Field(
        None,
        description="(Hybrid only) Authorized purchasing club identifier.",
    )

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

    # Week 6 — Audit: record every successful telemetry ingestion event.
    audit_logger.log_access(
        user_id="system",
        user_role="GATEWAY",
        player_id=payload.player_id or "unknown",
        action="TELEMETRY_INGEST",
        status="SUCCESS",
        ip_address=client_ip,
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
def update_athlete_consent(
    request: Request,
    payload: ConsentUpdateRequest,
) -> ConsentUpdateResponse:
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

    # Week 6 — Audit: record consent grant/revoke as a distinct, traceable action.
    client_ip = request.client.host if request.client else "unknown"
    audit_logger.log_access(
        user_id="system",
        user_role="ATHLETE_DASHBOARD",
        player_id=payload.player_id,
        action=f"CONSENT_{action}",
        status="SUCCESS",
        ip_address=client_ip,
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
    http_request: Request,
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
    client_ip = http_request.client.host if http_request.client else "unknown"

    # ------------------------------------------------------------------ #
    # GATE 2: GDPR Consent Check                                          #
    # ------------------------------------------------------------------ #
    if not consent_registry.is_consent_granted(player_id):
        logger.warning(
            "GDPR consent check FAILED for player_id=%s user_role=%s — access denied.",
            player_id, user_role,
        )
        # Week 6 — Audit: log GDPR denial BEFORE raising to guarantee the
        # entry is always written even if the exception propagates upward.
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=player_id,
            action="VIEW_BIOMETRIC_DATA",
            status="DENIED_GDPR_403",
            ip_address=client_ip,
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
        # Week 6 — Audit: log RBAC denial BEFORE raising.
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=player_id,
            action="VIEW_BIOMETRIC_DATA",
            status="DENIED_RBAC_403",
            ip_address=client_ip,
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

    # Week 6 — Audit: successful decryption — the most sensitive event to trace.
    audit_logger.log_access(
        user_id=user_role,
        user_role=user_role,
        player_id=player_id,
        action="VIEW_BIOMETRIC_DATA",
        status="SUCCESS_200",
        ip_address=client_ip,
    )

    return AuthorizeDecryptResponse(status="success", decrypted_payload=decrypted_payload)


# ---------------------------------------------------------------------------
# Week 7 — Transfer Escrow & Hashed Ledger Endpoint
# ---------------------------------------------------------------------------

class TransferRequest(BaseModel):
    """
    Request contract for the athlete transfer endpoint.

    Represents a club-to-club player transfer request.  The endpoint applies
    a five-step gate before committing a block to the local SHA-256 ledger:
    GDPR consent, escrow verification, payload hashing, ledger append, audit.
    """

    player_id: str = Field(..., min_length=1, description="Athlete unique identifier.")
    selling_club: str = Field(..., min_length=1, description="Club initiating the transfer.")
    buying_club: str = Field(..., min_length=1, description="Club acquiring the athlete.")
    escrow_deposit_verified: bool = Field(
        ...,
        description=(
            "True = financial escrow deposit confirmed by the transfer authority. "
            "False = transfer is pending financial settlement and will be rejected."
        ),
    )


class TransferResponse(BaseModel):
    """Response returned after a successfully committed transfer block."""

    status: str
    message: str
    block: Dict[str, Any]
    chain_valid: bool


@app.post(
    "/api/v1/transfer/process",
    response_model=TransferResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_api_key)],
    tags=["transfer"],
)
def process_transfer(
    http_request: Request,
    payload: TransferRequest,
    user_role: str = Header(
        ...,
        description="Role of the party initiating the transfer (e.g., CLUB_ADMIN).",
        alias="X-User-Role",
    ),
) -> TransferResponse:
    """
    End-to-end athlete transfer endpoint — Week 7 unified pipeline.

    Chains all six prior modules into a single, auditable transfer flow:

    **Gate 1 — API Key Authentication** (``require_api_key`` dependency).

    **Gate 2 — GDPR Consent Check:**
    Queries the ``ConsentRegistry`` for ``player_id``.  If the athlete has
    revoked consent, the transfer is immediately blocked with HTTP 403 and
    a ``DENIED_GDPR_403`` audit entry is written.

    **Gate 3 — Escrow Verification:**
    If ``escrow_deposit_verified == False``, the transfer is blocked with
    HTTP 400 and a ``TRANSFER_DENIED_ESCROW`` audit entry is written.
    No biometric data is accessed or hashed before this gate.

    **Gate 4 — Data Lock & SHA-256 Fingerprint:**
    Fetches all encrypted records for ``player_id`` from ``mock_db.json``
    and computes a SHA-256 hash of the JSON-serialised list.  This hash
    is the tamper-evident fingerprint of the biometric data bundle that
    accompanies the transfer.

    **Gate 5 — Ledger Commit & Audit:**
    Calls ``LocalHashedLedger.append_transfer_block()`` to commit the
    transfer to the immutable SHA-256 chain, then writes a
    ``TRANSFER_BLOCK_CREATED / SUCCESS_200`` entry to the audit log.

    Returns the committed block and a real-time ``chain_valid`` flag from
    ``ledger.validate_chain()``, letting the caller verify chain integrity
    on every transfer.
    """
    import hashlib as _hashlib
    import json as _json

    client_ip = http_request.client.host if http_request.client else "unknown"

    # ------------------------------------------------------------------ #
    # GATE 2: GDPR Consent Check                                          #
    # ------------------------------------------------------------------ #
    if not consent_registry.is_consent_granted(payload.player_id):
        logger.warning(
            "Transfer BLOCKED (GDPR): player_id=%s user_role=%s",
            payload.player_id, user_role,
        )
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=payload.player_id,
            action="TRANSFER_PROCESS",
            status="DENIED_GDPR_403",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Transfer Denied: Athlete revoked GDPR consent.",
        )

    # ------------------------------------------------------------------ #
    # GATE 3: Escrow Verification                                         #
    # ------------------------------------------------------------------ #
    if not payload.escrow_deposit_verified:
        logger.warning(
            "Transfer BLOCKED (Escrow): player_id=%s user_role=%s",
            payload.player_id, user_role,
        )
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=payload.player_id,
            action="TRANSFER_PROCESS",
            status="TRANSFER_DENIED_ESCROW",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Transfer Pending: Escrow deposit not verified.",
        )

    # ------------------------------------------------------------------ #
    # GATE 4: Data Lock & SHA-256 Encrypted Payload Fingerprint           #
    # ------------------------------------------------------------------ #
    all_records = cloud_server.get_all_stored_records()
    player_records = [r for r in all_records if r.get("player_id") == payload.player_id]
    payload_json = _json.dumps(player_records, sort_keys=True, ensure_ascii=True)
    encrypted_payload_hash = _hashlib.sha256(payload_json.encode("utf-8")).hexdigest()

    logger.info(
        "Transfer data fingerprint for player_id=%s: sha256=%s... (%d records)",
        payload.player_id, encrypted_payload_hash[:16], len(player_records),
    )

    # ------------------------------------------------------------------ #
    # GATE 5: Ledger Commit                                               #
    # ------------------------------------------------------------------ #
    committed_block = ledger.append_transfer_block({
        "player_id": payload.player_id,
        "selling_club": payload.selling_club,
        "buying_club": payload.buying_club,
        "escrow_deposit_verified": payload.escrow_deposit_verified,
        "encrypted_payload_hash": encrypted_payload_hash,
    })

    chain_valid = ledger.validate_chain()

    logger.info(
        "Transfer block #%d committed: player_id=%s %s→%s chain_valid=%s",
        committed_block["index"],
        payload.player_id,
        payload.selling_club,
        payload.buying_club,
        chain_valid,
    )

    # ------------------------------------------------------------------ #
    # AUDIT: Record every successful transfer commitment.                 #
    # ------------------------------------------------------------------ #
    audit_logger.log_access(
        user_id=user_role,
        user_role=user_role,
        player_id=payload.player_id,
        action="TRANSFER_BLOCK_CREATED",
        status="SUCCESS_200",
        ip_address=client_ip,
    )

    return TransferResponse(
        status="success",
        message=(
            f"Transfer block #{committed_block['index']} committed. "
            f"{payload.selling_club} → {payload.buying_club} for {payload.player_id}."
        ),
        block=committed_block,
        chain_valid=chain_valid,
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main_server:app", host=settings.HOST, port=settings.PORT, reload=True)


# ---------------------------------------------------------------------------
# Task 1 — Week 8: ECDH Hybrid Key Management & Decryption Endpoints
# ---------------------------------------------------------------------------

class ClubKeyRegisterRequest(BaseModel):
    """
    Request contract for the club public-key registration endpoint.

    An athlete (via their ``AthleteDashboard`` client) submits the purchasing
    club's NIST P-256 public key PEM.  The server stores it in the
    ``ClubKeyRegistry`` so the gateway can use it for ECDH encryption and
    the ``authorize-decrypt-hybrid`` endpoint can validate decryption requests.
    """

    club_id: str = Field(..., min_length=1, description="Unique purchasing club identifier.")
    player_id: str = Field(..., min_length=1, description="Athlete authorizing the club.")
    club_public_key_pem: str = Field(
        ...,
        description="PEM-encoded NIST P-256 public key of the club (begins with '-----BEGIN PUBLIC KEY-----').",
    )


class ClubKeyRegisterResponse(BaseModel):
    """Confirmation returned after successfully registering a club key."""

    status: str
    club_id: str
    player_id: str
    message: str


class ClubKeyRevokeRequest(BaseModel):
    """Request contract for revoking a club's registered public key."""

    club_id: str = Field(..., min_length=1, description="Club whose key is being revoked.")
    player_id: str = Field(..., min_length=1, description="Athlete revoking the authorization.")


class ClubKeyRevokeResponse(BaseModel):
    """Confirmation returned after a club key revocation attempt."""

    status: str
    club_id: str
    was_registered: bool
    message: str


class AuthorizeDecryptHybridRequest(BaseModel):
    """
    Request contract for hybrid ECDH decryption of a biometric record.

    The requesting club supplies:
    - ``record``: The full hybrid-encrypted packet (including
      ``ephemeral_public_key_pem`` and ``club_id``).
    - ``club_private_key_pem``: The club's PEM-encoded NIST P-256 private key,
      used server-side to mirror the ECDH exchange and derive the session key.

    Security note for thesis: In a production deployment, the club's private
    key would NEVER leave their HSM or key vault. The decryption operation
    would be performed locally (client-side) using the session key the club
    derives independently. This server-side decryption path is an academic
    simplification demonstrating the key-derivation correctness.
    """

    record: TelemetryIngestRequest = Field(..., description="Hybrid-encrypted packet to decrypt.")
    club_private_key_pem: str = Field(
        ...,
        description="PEM-encoded NIST P-256 private key of the authorized club.",
    )
    max_age_seconds: Optional[float] = Field(
        None, description="Optional freshness window to reject stale/replayed packets."
    )


class AuthorizeDecryptHybridResponse(BaseModel):
    """Response carrying the decrypted plaintext biometric payload (hybrid path)."""

    status: str
    decrypted_payload: Any
    club_id: str


@app.post(
    "/api/v1/keys/register-club",
    response_model=ClubKeyRegisterResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_api_key)],
    tags=["ecdh-keys"],
)
def register_club_key(
    http_request: Request,
    payload: ClubKeyRegisterRequest,
) -> ClubKeyRegisterResponse:
    """
    Register a purchasing club's NIST P-256 public key (Task 1 / Week 8).

    This endpoint is called by the athlete (via their ``AthleteDashboard``)
    to authorize a specific purchasing club to receive their encrypted
    biometric telemetry. The club's public key PEM is validated and stored
    in the in-process ``ClubKeyRegistry``.

    Once registered, the club's key can be used by the edge gateway in
    ``POST /api/v1/telemetry/ingest`` (hybrid packets) and the club can
    decrypt via ``POST /api/v1/telemetry/authorize-decrypt-hybrid``.

    **Gate 1 — API Key Authentication** (``require_api_key`` dependency).

    **Gate 2 — GDPR Consent Check**: If the athlete has revoked consent,
    the registration is blocked with HTTP 403.

    Requires a valid ``X-API-Key`` header.
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    # Gate 2: GDPR consent — no club registration while consent is revoked.
    if not consent_registry.is_consent_granted(payload.player_id):
        logger.warning(
            "Club key registration BLOCKED (GDPR): player_id=%s club_id=%s",
            payload.player_id, payload.club_id,
        )
        audit_logger.log_access(
            user_id="system",
            user_role="ATHLETE_DASHBOARD",
            player_id=payload.player_id,
            action="CLUB_KEY_REGISTER",
            status="DENIED_GDPR_403",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Club key registration denied: athlete has revoked GDPR consent.",
        )

    try:
        club_key_registry.register_club(payload.club_id, payload.club_public_key_pem)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc

    logger.info(
        "Club key REGISTERED: club_id=%s player_id=%s",
        payload.club_id, payload.player_id,
    )
    audit_logger.log_access(
        user_id="system",
        user_role="ATHLETE_DASHBOARD",
        player_id=payload.player_id,
        action="CLUB_KEY_REGISTER",
        status="SUCCESS",
        ip_address=client_ip,
    )

    return ClubKeyRegisterResponse(
        status="success",
        club_id=payload.club_id,
        player_id=payload.player_id,
        message=(
            f"Club {payload.club_id!r} public key registered. "
            f"ECDH hybrid encryption is now enabled for player {payload.player_id!r}."
        ),
    )


@app.post(
    "/api/v1/keys/revoke-club",
    response_model=ClubKeyRevokeResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_api_key)],
    tags=["ecdh-keys"],
)
def revoke_club_key(
    http_request: Request,
    payload: ClubKeyRevokeRequest,
) -> ClubKeyRevokeResponse:
    """
    Revoke a purchasing club's public key (Task 1 / Week 8).

    Removes the club's key from the ``ClubKeyRegistry``.  Subsequent hybrid
    encrypt or ``authorize-decrypt-hybrid`` calls for this club will be
    rejected.  This implements per-club consent revocation at the
    cryptographic level — complementing the global GDPR consent toggle.

    Idempotent: revoking an already-unregistered club returns HTTP 200 with
    ``was_registered=False`` rather than raising an error.

    Requires a valid ``X-API-Key`` header.
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    was_registered = club_key_registry.revoke_club(payload.club_id)

    logger.info(
        "Club key REVOKED: club_id=%s player_id=%s was_registered=%s",
        payload.club_id, payload.player_id, was_registered,
    )
    audit_logger.log_access(
        user_id="system",
        user_role="ATHLETE_DASHBOARD",
        player_id=payload.player_id,
        action="CLUB_KEY_REVOKE",
        status="SUCCESS",
        ip_address=client_ip,
    )

    return ClubKeyRevokeResponse(
        status="success",
        club_id=payload.club_id,
        was_registered=was_registered,
        message=(
            f"Club {payload.club_id!r} key {'revoked' if was_registered else 'was not registered'}. "
            f"ECDH decryption is now {'blocked' if was_registered else 'already blocked'} for this club."
        ),
    )


@app.post(
    "/api/v1/telemetry/authorize-decrypt-hybrid",
    response_model=AuthorizeDecryptHybridResponse,
    dependencies=[Depends(require_api_key)],
    tags=["ecdh-keys"],
)
def authorize_decrypt_hybrid(
    http_request: Request,
    request: AuthorizeDecryptHybridRequest,
    user_role: str = Header(
        ...,
        description="Requesting party role (e.g., TEAM_DOCTOR, CLUB_ADMIN).",
        alias="X-User-Role",
    ),
    player_id: str = Header(
        ...,
        description="Athlete player ID whose record is being decrypted.",
        alias="X-Player-Id",
    ),
) -> AuthorizeDecryptHybridResponse:
    """
    Authorized ECDH hybrid decryption of a biometric record (Task 1 / Week 8).

    Implements the club-side of the ECDH handshake on the server to demonstrate
    key-derivation correctness.  Passes through FOUR security gates:

    **Gate 1 — API Key Authentication** (``require_api_key`` dependency).

    **Gate 2 — GDPR Consent Check**:
    Reads ``player_id`` from ``X-Player-Id`` header and queries the
    ``ConsentRegistry``.  If consent is revoked, returns HTTP 403.

    **Gate 3 — Club Authorization Check**:
    Verifies that the ``club_id`` embedded in the encrypted packet is
    currently registered in the ``ClubKeyRegistry``. An unregistered
    (or revoked) club returns HTTP 403. This ensures that even if a club
    obtains the raw ciphertext out-of-band, they cannot decrypt it unless
    the athlete has explicitly authorized them.

    **Gate 4 — ECDH Session-Key Derivation & AES-256-GCM Decryption**:
    Uses the club's submitted private key PEM to mirror the ECDH exchange,
    derive the session AES-256 key, and decrypt the payload. A wrong or
    mismatched key returns HTTP 401.
    """
    client_ip = http_request.client.host if http_request.client else "unknown"

    # Validate that this is actually a hybrid packet.
    encrypted_packet = request.record.model_dump(exclude_none=True)
    if "ephemeral_public_key_pem" not in encrypted_packet or "club_id" not in encrypted_packet:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Packet is missing 'ephemeral_public_key_pem' or 'club_id'. "
                   "Use /api/v1/telemetry/authorize-decrypt for legacy symmetric packets.",
        )

    club_id: str = encrypted_packet["club_id"]

    # ------------------------------------------------------------------ #
    # GATE 2: GDPR Consent Check                                          #
    # ------------------------------------------------------------------ #
    if not consent_registry.is_consent_granted(player_id):
        logger.warning(
            "Hybrid decrypt BLOCKED (GDPR): player_id=%s club_id=%s user_role=%s",
            player_id, club_id, user_role,
        )
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=player_id,
            action="VIEW_BIOMETRIC_DATA_HYBRID",
            status="DENIED_GDPR_403",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Athlete has revoked biometric consent under GDPR.",
        )

    # ------------------------------------------------------------------ #
    # GATE 3: Club Authorization Check                                    #
    # ------------------------------------------------------------------ #
    if not club_key_registry.is_registered(club_id):
        logger.warning(
            "Hybrid decrypt BLOCKED (Club not authorized): club_id=%s player_id=%s",
            club_id, player_id,
        )
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=player_id,
            action="VIEW_BIOMETRIC_DATA_HYBRID",
            status="DENIED_CLUB_NOT_AUTHORIZED_403",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Club {club_id!r} is not authorized by the athlete.",
        )

    # ------------------------------------------------------------------ #
    # GATE 4: ECDH Session-Key Derivation & AES-256-GCM Decryption        #
    # ------------------------------------------------------------------ #
    max_age = request.max_age_seconds if request.max_age_seconds is not None else settings.MAX_PACKET_AGE_SECONDS

    try:
        club_private_key_pem_bytes = request.club_private_key_pem.encode("utf-8")
        gateway = SecureGateway(
            gateway_id=encrypted_packet["gateway_id"]
        )
        decrypted_payload = gateway.decrypt_data_hybrid(
            encrypted_packet,
            club_private_key_pem=club_private_key_pem_bytes,
            max_age_seconds=max_age,
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    except Exception as exc:  # cryptography.exceptions.InvalidTag, etc.
        logger.warning(
            "Hybrid decryption FAILED for player_id=%s club_id=%s: %s",
            player_id, club_id, exc.__class__.__name__,
        )
        audit_logger.log_access(
            user_id=user_role,
            user_role=user_role,
            player_id=player_id,
            action="VIEW_BIOMETRIC_DATA_HYBRID",
            status="DENIED_INVALID_KEY_401",
            ip_address=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Hybrid decryption/authentication failed: {exc.__class__.__name__}",
        ) from exc

    logger.info(
        "Hybrid decryption SUCCEEDED: player_id=%s club_id=%s user_role=%s",
        player_id, club_id, user_role,
    )
    audit_logger.log_access(
        user_id=user_role,
        user_role=user_role,
        player_id=player_id,
        action="VIEW_BIOMETRIC_DATA_HYBRID",
        status="SUCCESS_200",
        ip_address=client_ip,
    )

    return AuthorizeDecryptHybridResponse(
        status="success",
        decrypted_payload=decrypted_payload,
        club_id=club_id,
    )
