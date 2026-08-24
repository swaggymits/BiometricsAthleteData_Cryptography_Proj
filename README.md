# Data Privacy in Elite Performance: Protecting Athlete Biometrics

Bachelor's Thesis project implementing a secure edge-to-cloud pipeline for protecting sensitive athlete biometric telemetry (heart rate, fatigue, glucose, GPS, injury risk) against **tactical performance espionage** using authenticated encryption (AES-256-GCM) and hybrid ECDH key exchange.

---

## Project Overview

Modern elite sports teams rely on wearable IoT sensors (WBAN — Wireless Body Area Network) to continuously monitor athlete biometrics in real time. If this telemetry is intercepted in plaintext, rival teams or malicious actors could exploit it to detect player exhaustion, tactical weaknesses, or injury risk during a live match.

This project implements a secure data pipeline that encrypts biometric data **immediately at the edge** (on the wearable/gateway) before it ever touches the network, using industry-standard authenticated encryption — extended with an ECDH-based hybrid encryption scheme for per-club, revocable key management during athlete transfers.

---

## Architecture

```
[Wearable Sensor]  --BLE-->  [Edge Gateway]  --Network-->  [Cloud Server / REST API]
 IoTDeviceMock                SecureGateway                 CloudServer + FastAPI
 (raw plaintext)          (AES-256-GCM / ECDH hybrid)    (encrypted-only storage)
```

The codebase is organized into focused Python packages:

- **`core/`** — Cryptographic primitives and data contracts (gateway/device-agnostic).
- **`edge/`** — Simulated wearable device and edge-to-cloud transmission pipeline.
- **`server/`** — Cloud server logic, FastAPI REST API, configuration, and logging.
- **`ledger/`** — SHA-256 hashed blockchain ledger for transfer escrow.
- **`evaluation/`** — Benchmarking, dashboards, and reporting.
- **`dataset/`** — Public Zenodo dataset adapter for realistic biometric simulation.
- **`tests/`** — Full unittest suite.

### Module Responsibilities

1. **`edge/iot_device.py` — `IoTDeviceMock`** simulates a wearable sensor generating raw biometric readings.
2. **`core/biometric_schema.py`** enforces a strict Data Schema contract on every payload before it is allowed to be encrypted — rejecting malformed or out-of-range telemetry.
3. **`core/secure_gateway.py` — `SecureGateway`** encrypts validated payloads with AES-256-GCM (unique nonce per message, authenticated tag for integrity/tamper-detection), and also supports **hybrid ECDH-derived session-key encryption** (`encrypt_data_hybrid` / `decrypt_data_hybrid`).
4. **`core/ecdh_key_exchange.py`** implements ephemeral NIST P-256 (secp256r1) ECDH key exchange and HKDF-SHA256 session-key derivation for the hybrid Asymmetric-Symmetric encryption architecture used in per-club athlete transfers.
5. **`edge/pipeline_week2.py`** wires the device and gateway together into an end-to-end tick-by-tick simulation.
6. **`server/cloud_server.py` — `CloudServer`** persists ONLY hex-encoded ciphertext/nonce to `mock_db.json` — a storage-isolation gate that architecturally forbids plaintext biometrics from ever being written to disk. Also hosts the **`ConsentRegistry`** (thread-safe, in-memory map of `player_id` → GDPR consent flag) and the **`ClubKeyRegistry`** (per-club NIST P-256 public key store for ECDH hybrid encryption/decryption authorization).
7. **`evaluation/athlete_dashboard.py` — `AthleteDashboard`** is the athlete-facing logic class implementing GDPR consent toggle (with HMAC-signed consent packets) and AAA authentication primitives.
8. **`core/audit_logger.py` — `AuditLogger`** is a lightweight, thread-safe CSV audit logger that records every data-access event (`TELEMETRY_INGEST`, `CONSENT_GRANTED`/`REVOKED`, `VIEW_BIOMETRIC_DATA`, `TRANSFER_*`, `CLUB_KEY_*`) with a UTC timestamp, user role, player ID, action, status, and client IP — fulfilling the *Accounting* leg of AAA and GDPR Art. 5(2) accountability.
9. **`ledger/local_hashed_ledger.py` — `LocalHashedLedger`** is a SHA-256 blockchain that commits every athlete transfer event as an immutable, cryptographically-chained block. Any retroactive modification of a transfer record invalidates the chain, directly implementing the **Integrity** leg of the CIA Triad and providing anti-black-market traceability for the transfer pipeline.
10. **`server/main_server.py`** exposes the Cloud Server as a FastAPI REST API: API-key authenticated ingestion, a public "stored ciphertexts" proof-of-encryption endpoint (with pagination + GDPR erasure delete), a GDPR consent management endpoint, an authorized decryption endpoint, a unified transfer endpoint chaining all modules, and ECDH hybrid key registration/revocation/decryption endpoints.
11. **`server/config.py`** centralizes all runtime configuration (env vars / `.env`), and **`server/logging_config.py`** provides structured, leveled logging — both standard practice for production services.
12. **`dataset/zenodo_dataset_loader.py`** downloads and maps the public *"Synthetic Triathlete Dataset for Injury Prediction Research (2024)"* (Zenodo DOI: `10.5281/zenodo.15401061`) to `BiometricPayload` records, enabling realistic (non-synthetic-only) evaluation.
13. **`evaluation/benchmark_evaluation.py`** and **`system_evaluation.py`** run automated latency, throughput, scalability, and GDPR edge-case benchmarks, producing `EVALUATION_RESULTS.json` and `SYSTEM_EVALUATION_RESULTS.json`.
14. **Docker / Docker Compose** package the API into a minimal, non-root, health-checked container image for reproducible deployment, plus a one-shot `benchmark` service that runs both evaluation scripts and copies results to `./results/` on the host.
15. **GitHub Actions CI** (`.github/workflows/ci.yml`) automatically lints, type-checks, tests, and Docker-builds the project on every push/PR.

---

## Project Structure

```
├── core/
│   ├── biometric_schema.py     # Strict Data Schema contract + validation (BiometricPayload)
│   ├── secure_gateway.py        # SecureGateway — AES-256-GCM + ECDH hybrid encryption/decryption
│   ├── ecdh_key_exchange.py      # NIST P-256 ECDH key exchange + HKDF-SHA256 session-key derivation
│   └── audit_logger.py            # AuditLogger — CSV access audit log (GDPR Art. 5(2))
├── edge/
│   ├── iot_device.py               # IoTDeviceMock — simulated wearable sensor
│   ├── pipeline_week2.py            # Integration pipeline: IoTDeviceMock -> SecureGateway
│   └── live_test_client.py           # Manual live-server smoke test client (real HTTP requests)
├── server/
│   ├── main_server.py                 # FastAPI REST API: ingest / consent / decrypt / transfer / ECDH keys
│   ├── cloud_server.py                 # CloudServer (encrypted-only storage), ConsentRegistry, ClubKeyRegistry
│   ├── config.py                        # Centralized settings (env vars / .env) via pydantic-settings
│   └── logging_config.py                 # Structured logging setup
├── ledger/
│   └── local_hashed_ledger.py              # LocalHashedLedger — SHA-256 blockchain for transfers
├── evaluation/
│   ├── athlete_dashboard.py                  # AthleteDashboard — GDPR consent toggle & AAA auth
│   ├── benchmark_evaluation.py                # Automated benchmarking suite (evaluation metrics)
│   ├── verify_month1_pipeline.py               # End-to-end benchmark & verification (Phase 1)
│   ├── zenodo_report.py                         # Zenodo dataset evaluation report generator
│   └── EVALUATION_RESULTS.json                   # Quantitative benchmark output
├── dataset/
│   └── zenodo_dataset_loader.py                    # Zenodo public dataset adapter (BiometricPayload mapping)
├── tests/
│   ├── test_week1.py                                # Schema validation + encryption unit/integration tests
│   ├── test_pipeline_week3.py                         # End-to-end test: IoT -> Gateway -> Cloud API
│   ├── test_pipeline_week5.py                          # GDPR Consent & RBAC integration tests
│   ├── test_pipeline_week6.py                           # Audit Logging & Anti-Black Market integration tests
│   ├── test_pipeline_week7.py                            # Hashed Ledger & Transfer Escrow integration tests
│   ├── test_pipeline_week8.py                             # ECDH hybrid encryption integration tests
│   ├── test_full_system_week8.py                           # Master regression + evaluation-results integrity tests
│   └── test_zenodo_integration.py                            # Zenodo dataset loader integration tests
├── system_evaluation.py                                       # Latency / throughput / scalability / GDPR benchmark
├── run_all.py                                                  # Master runner: full test suite + pipeline demo
├── run_benchmarks.py                                            # Docker benchmark runner (copies results to ./results/)
├── conftest.py                                                   # pytest configuration / fixtures
├── requirements.txt                                               # Python dependencies
├── Dockerfile                                                       # Multi-stage, non-root, health-checked container image
├── docker-compose.yml                                                # cloud-server + one-shot benchmark services
├── .env.example                                                       # Template for local environment configuration
├── pyproject.toml                                                      # ruff / mypy configuration
├── .pre-commit-config.yaml                                              # Pre-commit hooks (lint/format on commit)
├── .github/workflows/ci.yml                                              # CI: lint, type-check, test, Docker build
├── .vscode/launch.json                                                    # VS Code Run & Debug configurations
├── docs/                                                                   # THESIS_MANUSCRIPT_RESULTS.md + test automation reports
└── README.md
```

---

## Official Data Schema

| Data Type   | Field Name      | Description                              | Frequency    | Expected Size |
|-------------|-----------------|-------------------------------------------|--------------|---------------|
| Integer     | `heart_rate`    | Heart rate (BPM)                          | 1 / sec      | 2 Bytes       |
| Float       | `fatigue_index` | Muscular fatigue index (%)                | 1 / 30 secs  | 4 Bytes       |
| Float       | `glucose_level` | Blood glucose level (mg/dL)               | 1 / 5 mins   | 4 Bytes       |
| JSON Object | `gps_telemetry` | Coordinates & Speed (Lat, Long, Speed)    | 1 / sec      | ~32 Bytes     |
| Float       | `injury_risk`   | Injury probability (0.0 - 1.0)            | Real-time    | 4 Bytes       |

Enforced by `validate_biometric_payload()` in `core/biometric_schema.py`, which acts as a "shape gate" prior to encryption.

The **`dataset/zenodo_dataset_loader.py`** adapter maps the public *Synthetic Triathlete Dataset for Injury Prediction Research (2024)* (Zenodo, DOI `10.5281/zenodo.15401061`, CC-BY 4.0) into this exact schema, allowing the pipeline to be evaluated against realistic physiological data rather than purely synthetic values.

---

## Security Design

- **Confidentiality** — AES-256 encryption ensures biometric payloads are unreadable to eavesdroppers, in both symmetric and ECDH-hybrid modes.
- **Integrity & Authenticity** — AES-GCM (AEAD) appends a 128-bit authentication tag; any tampering during transit causes decryption to fail (`cryptography.exceptions.InvalidTag`).
- **Replay Protection / Semantic Security** — A fresh cryptographically random 96-bit nonce (`os.urandom(12)`) is generated per encryption, so identical plaintext never produces identical ciphertext.
- **Hybrid Asymmetric-Symmetric Key Exchange (ECDH)** — Ephemeral NIST P-256 key pairs are generated per session; ECDH + HKDF-SHA256 (RFC 5869) derive a 32-byte AES-256 session key bound to the session context (`gateway_id`, `player_id`, `club_id`), preventing cross-session key reuse/confusion. This enables per-club, individually-revocable encryption keys for athlete transfer scenarios, without exposing a long-lived symmetric master key.
- **API Authentication** — `/telemetry/ingest`, `/athlete/consent`, `/telemetry/authorize-decrypt`, `/transfer/process`, and all `/keys/*` endpoints require a shared-secret `X-API-Key` header, so only provisioned gateways/analysts can write, update consent, decrypt, or manage club keys. `/telemetry/stored-ciphertexts` is deliberately left public as a live proof that stored data is encrypted-only.
- **Data Minimization (GDPR Art. 5(1)(c))** — the storage layer (`CloudServer`) architecturally refuses to persist any field that isn't a hex-encoded ciphertext/nonce or benign routing metadata.
- **Right to Erasure (GDPR Art. 17)** — `DELETE /api/v1/telemetry/records/{index}` permanently removes a single stored encrypted record by index.
- **GDPR Consent Management (Art. 7 & 17)** — `AthleteDashboard.update_consent(False)` triggers `POST /api/v1/athlete/consent` which updates the `ConsentRegistry`. Any subsequent `authorize-decrypt` (symmetric or hybrid) call, or `transfer/process` / club-key registration call, for that athlete is immediately rejected with HTTP 403, regardless of the requester's role. HMAC-SHA256-signed consent packets provide a tamper-evident audit trail.
- **Role-Based Access Control / RBAC** — Only `user_role = "TEAM_DOCTOR"` (sent via `X-User-Role` header) may obtain decrypted biometrics. All other roles (`ANALYST`, `EXTERNAL_COMPANY`, etc.) are rejected at the authorization layer with HTTP 403, enforcing the principle of least privilege.
- **Per-Club Key Revocation** — The `ClubKeyRegistry` lets an athlete authorize (`/keys/register-club`) or revoke (`/keys/revoke-club`) a specific club's decryption capability independently of the global GDPR consent flag, so a club that no longer employs the athlete can be cryptographically cut off from future hybrid-encrypted telemetry.
- **Ledger Integrity (CIA — Integrity)** — `LocalHashedLedger` chains every transfer as a SHA-256 block referencing the previous block's hash; `validate_chain()` detects any retroactive tampering.

---

## Configuration

All runtime configuration is environment-driven (Twelve-Factor App style) via `server/config.py` / `pydantic-settings`. Copy the example file and adjust as needed:

```zsh
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` / `staging` / `production` |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | uvicorn bind address |
| `MOCK_DB_PATH` | `mock_db.json` | Path to the JSON mock persistence layer |
| `AUDIT_LOG_PATH` | `audit_log.csv` | Path to CSV audit log; Docker overrides to `/data/audit_log.csv` |
| `LEDGER_FILE_PATH` | `ledger_file.json` | Path to SHA-256 transfer ledger; Docker overrides to `/data/ledger_file.json` |
| `CLOUD_API_KEY` | `dev-only-insecure-change-me` | Shared secret required via `X-API-Key` header |
| `MAX_PACKET_AGE_SECONDS` | `300` | Default replay-protection freshness window |

**Generate a strong production API key:**

```zsh
venv/bin/python -c "import secrets; print(secrets.token_hex(32))"
```

---

## Getting Started

### 1. Set up the virtual environment

```zsh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

### 2. Run everything (tests + pipeline demo) in one command

```zsh
venv/bin/python run_all.py
```

This will:
1. Auto-discover and run **all** `test_*.py` files under `tests/` (schema validation, encryption/decryption, ECDH hybrid, REST API, GDPR/RBAC, ledger, and Zenodo integration tests).
2. If all tests pass, run the **Week 2 pipeline demo** (`edge/pipeline_week2.py`) — 5 simulated biometric readings, each encrypted and verified leak-free.

### 3. Run just the test suite

```zsh
venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
```

or, using pytest (a `conftest.py` is provided at the project root):

```zsh
venv/bin/python -m pytest tests/ -v
```

### 4. Run just the pipeline demo

```zsh
venv/bin/python -m edge.pipeline_week2
```

### 5. Run the Cloud Server REST API

```zsh
venv/bin/python -m server.main_server
```

This starts a uvicorn server at `http://localhost:8000`. Interactive API docs (Swagger UI) are available at `http://localhost:8000/docs`. Endpoints:

- `GET /health` — liveness/readiness probe (no auth required).
- `POST /api/v1/telemetry/ingest` *(requires `X-API-Key` header)* — accepts a hex-encoded encrypted packet (`gateway_id`, `nonce`, `ciphertext`, ...; symmetric or ECDH-hybrid) and stores it in `mock_db.json`.
- `GET /api/v1/telemetry/stored-ciphertexts` *(public, paginated via `offset`/`limit`)* — returns records from `mock_db.json`; proves the store only ever contains encrypted noise.
- `DELETE /api/v1/telemetry/records/{index}` *(requires `X-API-Key` header)* — permanently deletes a stored record by index (GDPR Art. 17 erasure).
- `POST /api/v1/athlete/consent` *(requires `X-API-Key` header)* — accepts `{player_id, privacy_toggle_consent}` and updates the server-side `ConsentRegistry`. Setting `privacy_toggle_consent=false` immediately blocks all decryption/transfer/club-key operations for that athlete.
- `POST /api/v1/telemetry/authorize-decrypt` *(requires `X-API-Key` + `X-User-Role` + `X-Player-Id` headers)* — enforces GDPR consent check and RBAC role check before decrypting a symmetric AES-256-GCM packet; only `TEAM_DOCTOR` role may obtain plaintext.
- `POST /api/v1/transfer/process` *(requires `X-API-Key` + `X-User-Role` headers)* — GDPR consent + escrow verification + SHA-256 payload fingerprint + immutable ledger commit for an athlete transfer.
- `POST /api/v1/keys/register-club` *(requires `X-API-Key` header)* — registers a purchasing club's NIST P-256 public key (subject to GDPR consent) for ECDH hybrid encryption.
- `POST /api/v1/keys/revoke-club` *(requires `X-API-Key` header)* — revokes a club's registered public key, blocking future hybrid decryption for that club.
- `POST /api/v1/telemetry/authorize-decrypt-hybrid` *(requires `X-API-Key` + `X-User-Role` + `X-Player-Id` headers)* — GDPR consent + club-authorization + ECDH session-key derivation + AES-256-GCM decryption of a hybrid-encrypted packet.

Test it with `curl` (using the default dev API key from `.env.example`):

```zsh
curl http://localhost:8000/health
curl -X POST http://localhost:8000/api/v1/telemetry/ingest \
  -H "Content-Type: application/json" -H "X-API-Key: dev-only-insecure-change-me" \
  -d '{"gateway_id":"GW-01","nonce":"aa..","ciphertext":"bb.."}'
curl http://localhost:8000/api/v1/telemetry/stored-ciphertexts
```

Or run the bundled live smoke-test client against the running server (generates real biometric data end-to-end):

```zsh
venv/bin/python -m edge.live_test_client
```

### 6. Run the end-to-end integration tests (per module)

```zsh
venv/bin/python -m unittest tests.test_pipeline_week3 -v   # Cloud Server REST API
venv/bin/python -m unittest tests.test_pipeline_week5 -v   # GDPR Consent & RBAC
venv/bin/python -m unittest tests.test_pipeline_week6 -v   # Audit Logging
venv/bin/python -m unittest tests.test_pipeline_week7 -v   # Hashed Ledger & Transfer Escrow
venv/bin/python -m unittest tests.test_pipeline_week8 -v   # ECDH Hybrid Encryption
venv/bin/python -m unittest tests.test_zenodo_integration -v  # Zenodo dataset adapter
```

### 7. Run the Month 1 end-to-end benchmark & verification

```zsh
venv/bin/python evaluation/verify_month1_pipeline.py             # default 20 ticks
venv/bin/python evaluation/verify_month1_pipeline.py --ticks 50  # custom iteration count
```

This script runs the **complete pipeline in-process** (no server required) and prints a structured benchmark report covering:
- AES-256-GCM encryption latency vs raw JSON serialisation
- Payload size overhead (raw JSON → hex ciphertext)
- API ingestion latency (min / avg / max / σ)
- Authorized decryption round-trip integrity
- Database isolation assertion (0 plaintext keywords in `mock_db.json`)

### 8. Run the automated benchmarking suite & system evaluation

```zsh
venv/bin/python evaluation/benchmark_evaluation.py   # writes evaluation/EVALUATION_RESULTS.json
venv/bin/python system_evaluation.py                 # latency, throughput, scalability, GDPR edge-case; writes SYSTEM_EVALUATION_RESULTS.json
```

### 9. Run with Docker

```zsh
docker compose up --build
```

This builds a minimal, non-root, health-checked container image and starts the API on `http://localhost:8000`, persisting `mock_db.json`, `audit_log.csv`, and `ledger_file.json` on a named Docker volume (`/data`). Set a strong `CLOUD_API_KEY` via an `.env` file or environment variable before deploying beyond local dev.

To run the one-shot benchmark container (executes `evaluation/benchmark_evaluation.py` + `system_evaluation.py` and copies JSON results to `./results/` on the host):

```zsh
docker compose run --rm benchmark
```

### 10. Run & Debug from VS Code

Open the **Run and Debug** panel and choose one of the pre-configured launch options in `.vscode/launch.json` to run the full project, individual test modules, or the currently open file with breakpoints.

---

## Continuous Integration

Every push/PR triggers `.github/workflows/ci.yml`, which:
1. Lints the codebase with [`ruff`](https://docs.astral.sh/ruff/).
2. Type-checks with [`mypy`](https://mypy-lang.org/).
3. Runs the full test suite (`tests/`).
4. Builds the production Docker image, catching container-level regressions.

A `.pre-commit-config.yaml` is also provided to run linting/formatting checks locally before each commit.

---

## Requirements

- Python 3.9+ (Docker image uses Python 3.11)
- [`cryptography`](https://cryptography.io/) >= 42.0.0 — AES-256-GCM, NIST P-256 ECDH, HKDF-SHA256
- [`fastapi`](https://fastapi.tiangolo.com/) >= 0.110.0
- [`uvicorn`](https://www.uvicorn.org/) >= 0.28.0
- [`pydantic`](https://docs.pydantic.dev/) >= 2.0.0
- [`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) >= 2.2.0
- [`httpx`](https://www.python-httpx.org/) >= 0.27.0 (required by FastAPI's `TestClient`)
- [`requests`](https://requests.readthedocs.io/) >= 2.31.0 (used by `edge/live_test_client.py` and the Zenodo dataset loader)
- Docker (optional, for containerized deployment)

---

## Roadmap

- ✅ **Week 1** — Environment setup & core encryption module (`SecureGateway`, AES-256-GCM).
- ✅ **Week 2** — IoT device mocking & edge transmission pipeline (`IoTDeviceMock`, `pipeline_week2.py`).
- ✅ **Week 3** — Cloud Server & Secure REST APIs (`CloudServer`, `main_server.py`, encrypted-only storage, authorized decryption).
- ✅ **Week 4** — End-of-Month 1 integration, benchmarking & verification (`verify_month1_pipeline.py`).
- ✅ **Week 5** — Access Control & GDPR Consent Toggle (`AthleteDashboard`, `ConsentRegistry`, `POST /api/v1/athlete/consent`, RBAC on `authorize-decrypt`).
- ✅ **Week 6** — Audit Logging & Anti-Black Market Protection (`AuditLogger`, `audit_log.csv`, full AAA Accounting trail on all endpoints).
- ✅ **Week 7** — Local Hashed Ledger & Transfer Escrow Simulation (`LocalHashedLedger`, SHA-256 blockchain, `POST /api/v1/transfer/process`, MITM tampering detection).
- ✅ **Week 8** — End-to-End Evaluation & Benchmarking (`benchmark_evaluation.py`, `test_full_system_week8.py`, `EVALUATION_RESULTS.json`, `THESIS_MANUSCRIPT_RESULTS.md`).
- ✅ **Post-Week 8 Extensions** — Hybrid ECDH key exchange & per-club key management (`ecdh_key_exchange.py`, `ClubKeyRegistry`, `/api/v1/keys/*`, `authorize-decrypt-hybrid`); public Zenodo dataset integration (`zenodo_dataset_loader.py`, DOI `10.5281/zenodo.15401061`); paginated ciphertext listing & GDPR erasure endpoint (`DELETE /api/v1/telemetry/records/{index}`); project-wide restructuring into `core/`, `edge/`, `server/`, `ledger/`, `evaluation/`, `dataset/`, and `tests/` packages; standalone `system_evaluation.py` latency/throughput/scalability/GDPR benchmark; Docker Compose `benchmark` service.

> 🎓 All CIA Triad, AAA, and GDPR requirements from the original 8-week roadmap are fulfilled, with additional hybrid-cryptography and real-world-dataset extensions layered on top. See `docs/THESIS_MANUSCRIPT_RESULTS.md` for the full thesis write-up and quantitative results.

---

## Disclaimer

This is an academic thesis prototype. It simulates hardware/network behavior in software and is not intended for production deployment without further security hardening (e.g., proper key management/HSM integration, mutual TLS, certificate-based device authentication).
