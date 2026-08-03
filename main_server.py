"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 3: Cloud Server REST API (FastAPI)

Exposes the secure ingestion/aggregation surface that a real cloud backend
would present to edge gateways and authorized analytics consumers.

Security & Compliance Notes (GDPR / CIA Availability):
-------------------------------------------------------
- `POST /api/v1/telemetry/ingest` is the ONLY write path into storage, and it
  is strictly validated by Pydantic models to accept nothing but hex-encoded
  `nonce`/`ciphertext` plus routing metadata (data minimization by design —
  GDPR Art. 5(1)(c): no more data than necessary is ever accepted or stored).
- `GET /api/v1/telemetry/stored-ciphertexts` intentionally requires NO special
  authorization, because it is designed to be safely public: it proves that
  even a stolen database dump or an unauthorized third-party API read yields
  only authenticated ciphertext ("encrypted noise"), never raw biometrics —
  directly mitigating tactical performance espionage.
- `POST /api/v1/telemetry/authorize-decrypt` is the ONLY path where plaintext
  is ever reconstructed, and it requires the caller to supply the correct
  pre-shared AES key. This models a real "authorized analyst / coaching
  staff" decryption workflow, separate from the untrusted storage tier.
- Running under `uvicorn` (ASGI) keeps the ingestion endpoint responsive and
  horizontally scalable, supporting the Availability leg of the CIA triad for
  continuous, real-time telemetry ingestion during a live match.
"""

from __future__ import annotations

import binascii
import time
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from cloud_server import CloudServer
from config import settings
from logging_config import configure_logging, get_logger
from secure_gateway import SecureGateway

configure_logging()
logger = get_logger(__name__)

app = FastAPI(
    title=settings.APP_NAME,
    description=(
        "Week 3: Secure ingestion, encrypted-only storage, and authorized "
        "decryption API for AES-256-GCM protected athlete biometric telemetry."
    ),
    version="3.0.0",
)

cloud_server = CloudServer(db_path=settings.MOCK_DB_PATH)


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
def ingest_telemetry(payload: TelemetryIngestRequest) -> TelemetryIngestResponse:
    """
    Ingest a single hex-encoded encrypted biometric telemetry packet from an
    edge `SecureGateway` and persist it to `mock_db.json`.

    Requires a valid `X-API-Key` header (edge gateways are provisioned with
    this shared secret out-of-band, e.g., during device enrollment).

    Data minimization: only `nonce`/`ciphertext` (plus routing metadata) are
    ever accepted or stored — no plaintext biometric field exists in the
    request schema, so none can ever reach storage.
    """
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
    response_model=List[Dict[str, Any]],
)
def get_stored_ciphertexts() -> List[Dict[str, Any]]:
    """
    Return every record currently stored in `mock_db.json`.

    Intentionally requires no authorization: this endpoint serves as a live
    proof-of-concept that a stolen database dump or unauthorized third-party
    API read discloses only authenticated ciphertext ("encrypted noise"),
    never raw athlete biometrics — mitigating tactical performance espionage.
    """
    return cloud_server.get_all_stored_records()


@app.post(
    "/api/v1/telemetry/authorize-decrypt",
    response_model=AuthorizeDecryptResponse,
    dependencies=[Depends(require_api_key)],
)
def authorize_decrypt(request: AuthorizeDecryptRequest) -> AuthorizeDecryptResponse:
    """
    Simulate an authorized decryption workflow: given an encrypted record and
    the valid pre-shared AES-256 key, reconstruct a `SecureGateway` instance
    and call `SecureGateway.decrypt_data()` to recover the original plaintext
    biometric payload.

    Requires a valid `X-API-Key` header IN ADDITION to the correct AES key,
    modeling a two-factor authorized-analyst access path, distinct from the
    untrusted public storage tier.
    """
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
        "Authorized decryption succeeded for gateway_id=%s device_id=%s",
        encrypted_packet.get("gateway_id"), encrypted_packet.get("device_id"),
    )
    return AuthorizeDecryptResponse(status="success", decrypted_payload=decrypted_payload)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main_server:app", host=settings.HOST, port=settings.PORT, reload=True)
