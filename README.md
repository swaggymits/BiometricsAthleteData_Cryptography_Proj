# Data Privacy in Elite Performance: Protecting Athlete Biometrics

Bachelor's Thesis project implementing a secure edge-to-cloud pipeline for protecting sensitive athlete biometric telemetry (heart rate, fatigue, glucose, GPS, injury risk) against **tactical performance espionage** using authenticated encryption (AES-256-GCM).

---

## Project Overview

Modern elite sports teams rely on wearable IoT sensors (WBAN — Wireless Body Area Network) to continuously monitor athlete biometrics in real time. If this telemetry is intercepted in plaintext, rival teams or malicious actors could exploit it to detect player exhaustion, tactical weaknesses, or injury risk during a live match.

This project implements, week by week, a secure data pipeline that encrypts biometric data **immediately at the edge** (on the wearable/gateway) before it ever touches the network, using industry-standard authenticated encryption.

---

## Architecture

```
[Wearable Sensor]  --BLE-->  [Edge Gateway]  --Network-->  [Cloud Server / REST API]
 IoTDeviceMock                SecureGateway                 CloudServer + FastAPI
 (raw plaintext)          (AES-256-GCM encryption)      (encrypted-only storage)
```

1. **`IoTDeviceMock`** simulates a wearable sensor generating raw biometric readings.
2. **`biometric_schema.py`** enforces a strict Data Schema contract on every payload before it is allowed to be encrypted — rejecting malformed or out-of-range telemetry.
3. **`SecureGateway`** encrypts validated payloads with AES-256-GCM (unique nonce per message, authenticated tag for integrity/tamper-detection).
4. **`pipeline_week2.py`** wires the device and gateway together into an end-to-end tick-by-tick simulation.
5. **`CloudServer`** (`cloud_server.py`) persists ONLY hex-encoded ciphertext/nonce to `mock_db.json` — a storage-isolation gate that architecturally forbids plaintext biometrics from ever being written to disk.
6. **`main_server.py`** exposes the Cloud Server as a FastAPI REST API: API-key authenticated ingestion, a public "stored ciphertexts" proof-of-encryption endpoint, and an authorized decryption endpoint gated by the pre-shared AES key.
7. **`config.py`** centralizes all runtime configuration (env vars / `.env`), and **`logging_config.py`** provides structured, leveled logging — both standard practice for production services.
8. **Docker / Docker Compose** package the API into a minimal, non-root, health-checked container image for reproducible deployment.
9. **GitHub Actions CI** (`.github/workflows/ci.yml`) automatically lints, type-checks, tests, and Docker-builds the project on every push/PR.

---

## Project Structure

```
├── biometric_schema.py       # Strict Data Schema contract + validation (BiometricPayload)
├── secure_gateway.py          # SecureGateway class — AES-256-GCM encryption/decryption
├── iot_device.py               # IoTDeviceMock class — simulated wearable sensor
├── pipeline_week2.py           # Integration pipeline: IoTDeviceMock -> SecureGateway
├── cloud_server.py              # CloudServer class — encrypted-only persistent mock storage
├── main_server.py                # FastAPI REST API: ingest / stored-ciphertexts / authorize-decrypt
├── config.py                      # Centralized settings (env vars / .env) via pydantic-settings
├── logging_config.py               # Structured logging setup
├── live_test_client.py              # Manual live-server smoke test client (real HTTP requests)
├── run_all.py                        # Master runner: all tests + pipeline demo in one command
├── test_week1.py                      # Unit/integration tests (schema validation + encryption)
├── test_pipeline_week3.py              # End-to-end test: IoT -> Gateway -> Cloud API
├── requirements.txt                     # Python dependencies
├── Dockerfile                             # Multi-stage, non-root, health-checked container image
├── docker-compose.yml                      # Local/prod-like container orchestration
├── .env.example                             # Template for local environment configuration
├── pyproject.toml                            # ruff / mypy configuration
├── .github/workflows/ci.yml                   # CI: lint, type-check, test, Docker build
├── .vscode/launch.json                         # VS Code Run & Debug configurations
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

Enforced by `validate_biometric_payload()` in `biometric_schema.py`, which acts as a "shape gate" prior to encryption.

---

## Security Design

- **Confidentiality** — AES-256 encryption ensures biometric payloads are unreadable to eavesdroppers.
- **Integrity & Authenticity** — AES-GCM (AEAD) appends a 128-bit authentication tag; any tampering during transit causes decryption to fail (`cryptography.exceptions.InvalidTag`).
- **Replay Protection / Semantic Security** — A fresh cryptographically random 96-bit nonce (`os.urandom(12)`) is generated per encryption, so identical plaintext never produces identical ciphertext.
- **API Authentication** — `/ingest` and `/authorize-decrypt` require a shared-secret `X-API-Key` header, so only provisioned gateways/analysts can write or decrypt data. `/stored-ciphertexts` is deliberately left public as a live proof that stored data is encrypted-only.
- **Data Minimization (GDPR Art. 5(1)(c))** — the storage layer (`CloudServer`) architecturally refuses to persist any field that isn't a hex-encoded ciphertext/nonce or benign routing metadata.

---

## Configuration

All runtime configuration is environment-driven (Twelve-Factor App style) via `config.py` / `pydantic-settings`. Copy the example file and adjust as needed:

```zsh
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` / `staging` / `production` |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | uvicorn bind address |
| `MOCK_DB_PATH` | `mock_db.json` | Path to the JSON mock persistence layer |
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
1. Auto-discover and run **all** `test_*.py` files (schema validation + encryption/decryption + REST API tests).
2. If all tests pass, run the **Week 2 pipeline demo** — 5 simulated biometric readings, each encrypted and verified leak-free.

### 3. Run just the test suite

```zsh
venv/bin/python -m unittest discover -p "test_*.py" -v
```

### 4. Run just the pipeline demo

```zsh
venv/bin/python pipeline_week2.py
```

### 5. Run the Week 3 Cloud Server REST API

```zsh
venv/bin/python main_server.py
```

This starts a uvicorn server at `http://localhost:8000`. Interactive API docs (Swagger UI) are available at `http://localhost:8000/docs`. Endpoints:

- `GET /health` — liveness/readiness probe (no auth required).
- `POST /api/v1/telemetry/ingest` *(requires `X-API-Key` header)* — accepts a hex-encoded encrypted packet (`gateway_id`, `nonce`, `ciphertext`, ...) and stores it in `mock_db.json`.
- `GET /api/v1/telemetry/stored-ciphertexts` *(public)* — returns everything in `mock_db.json`; proves the store only ever contains encrypted noise.
- `POST /api/v1/telemetry/authorize-decrypt` *(requires `X-API-Key` header)* — given an encrypted record and the correct 256-bit shared AES key (hex), returns the recovered plaintext biometric payload.

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
venv/bin/python live_test_client.py
```

### 6. Run just the Week 3 end-to-end integration test

```zsh
venv/bin/python -m unittest test_pipeline_week3 -v
```

### 7. Run with Docker

```zsh
docker compose up --build
```

This builds a minimal, non-root, health-checked container image and starts the API on `http://localhost:8000`, persisting `mock_db.json` in a named Docker volume. Set a strong `CLOUD_API_KEY` via an `.env` file or environment variable before deploying beyond local dev.

### 8. Run & Debug from VS Code

Open the **Run and Debug** panel and choose one of the pre-configured launch options:

- **Python: Run Entire Project (run_all.py)** — runs all tests + pipeline demo.
- **Python: Debug test_week1.py (unittest)** — debug the test suite with breakpoints.
- **Python: Current File** — debug whichever file is currently open.

---

## Continuous Integration

Every push/PR triggers `.github/workflows/ci.yml`, which:
1. Lints the codebase with [`ruff`](https://docs.astral.sh/ruff/).
2. Type-checks with [`mypy`](https://mypy-lang.org/).
3. Runs the full test suite on Python 3.9 and 3.11.
4. Builds the production Docker image, catching container-level regressions.

---

## Requirements

- Python 3.9+
- [`cryptography`](https://cryptography.io/) >= 42.0.0
- [`fastapi`](https://fastapi.tiangolo.com/) >= 0.110.0
- [`uvicorn`](https://www.uvicorn.org/) >= 0.28.0
- [`pydantic`](https://docs.pydantic.dev/) >= 2.0.0
- [`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) >= 2.2.0
- [`httpx`](https://www.python-httpx.org/) >= 0.27.0 (required by FastAPI's `TestClient`)
- [`requests`](https://requests.readthedocs.io/) >= 2.31.0 (used by `live_test_client.py`)
- Docker (optional, for containerized deployment)

---

## Roadmap

- ✅ **Week 1** — Environment setup & core encryption module (`SecureGateway`, AES-256-GCM).
- ✅ **Week 2** — IoT device mocking & edge transmission pipeline (`IoTDeviceMock`, `pipeline_week2.py`).
- ✅ **Week 3** — Cloud Server & Secure REST APIs (`CloudServer`, `main_server.py`, encrypted-only storage, authorized decryption).
- 🔜 **Future weeks** — Key management/rotation, secure storage hardening, access control, performance benchmarking.

---

## Disclaimer

This is an academic thesis prototype. It simulates hardware/network behavior in software and is not intended for production deployment without further security hardening (e.g., proper key management/HSM integration, mutual TLS, certificate-based device authentication).
