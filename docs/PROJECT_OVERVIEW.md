# Project Overview — Data Privacy in Elite Performance: Protecting Athlete Biometrics

> A complete, detailed technical reference describing the purpose, architecture, technologies, modules, security model, and test/evaluation strategy of this Bachelor's Thesis project.

---

## 1. What is this project, and why does it exist?

This is a **Bachelor's Thesis prototype** that simulates a real-world **edge-to-cloud data pipeline** for protecting sensitive **athlete biometric telemetry** — heart rate, muscular fatigue, blood glucose, GPS location/speed, and injury-risk probability.

### The problem it solves

Modern elite sports clubs use wearable IoT sensors (a **Wireless Body Area Network**, or **WBAN**) to continuously monitor athletes during training and matches. This data is extremely sensitive:

- If a rival team intercepts it in real time, they can detect that a player is exhausted, injured, or tactically weak, and exploit that during a live match — this is the threat the project calls **"tactical performance espionage."**
- Biometric data is also **personal health data** under the **GDPR**, meaning athletes have legal rights over who can access it and when.
- When athletes transfer between clubs, their historical biometric data needs to move with them in a way that is auditable and cannot be quietly leaked to a "black market" of scouting data.

### The solution this project builds

A pipeline that:
1. **Encrypts biometric data immediately at the edge** (on the wearable/gateway), before it ever touches the network, using **AES-256-GCM** authenticated encryption.
2. Optionally uses a **hybrid ECDH (Elliptic-Curve Diffie-Hellman) key exchange** so that different clubs can be given their own **revocable** decryption capability, without sharing one static master key.
3. Stores **only ciphertext** in the cloud — never plaintext — enforced architecturally, not just by convention.
4. Enforces **GDPR consent** and **Role-Based Access Control (RBAC)** before any data is ever decrypted.
5. Logs every access attempt (successful or denied) to an **immutable audit trail** (CSV).
6. Uses a **SHA-256 hashed blockchain ledger** to make athlete transfer records tamper-evident.
7. Is **quantitatively benchmarked** (latency, throughput, scalability, storage overhead, GDPR edge cases, ECDH correctness, ledger tamper detection) to produce real numbers for the thesis write-up.

This is explicitly an **academic prototype**, not a production system — it simulates hardware/network behavior in software (e.g., the "wearable device" and "network" are just Python objects and an in-process FastAPI test client / HTTP server), but the cryptography, access-control logic, and audit mechanisms are implemented with real, industry-standard libraries and correct security reasoning.

---

## 2. High-Level Architecture

```
[Wearable Sensor]  --BLE-->  [Edge Gateway]  --Network-->  [Cloud Server / REST API]
 IoTDeviceMock                SecureGateway                 CloudServer + FastAPI
 (raw plaintext)          (AES-256-GCM / ECDH hybrid)    (encrypted-only storage)
```

Three trust zones:

1. **Edge (Device + Gateway)** — where plaintext exists only momentarily, and is destroyed by encryption before any network transmission.
2. **Network / Transport** — encrypted packets travel here; even a full wiretap yields nothing but ciphertext.
3. **Cloud** — the storage and decryption-authorization layer, which enforces GDPR consent, RBAC, and produces an audit trail before ever reconstructing plaintext.

---

## 3. Technologies Used

| Technology | Role |
|---|---|
| **Python 3.9+** (Docker image uses 3.11) | Primary language for the entire codebase |
| **[`cryptography`](https://cryptography.io/) ≥ 42.0.0** | AES-256-GCM authenticated encryption, NIST P-256 (secp256r1) ECDH key exchange, HKDF-SHA256 key derivation, PEM key (de)serialization |
| **[`FastAPI`](https://fastapi.tiangolo.com/) ≥ 0.110.0** | REST API framework exposing the Cloud Server as HTTP endpoints |
| **[`uvicorn`](https://www.uvicorn.org/) ≥ 0.28.0** | ASGI server that runs the FastAPI app |
| **[`pydantic`](https://docs.pydantic.dev/) ≥ 2.0.0** | Request/response schema validation & serialization for the API |
| **[`pydantic-settings`](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) ≥ 2.2.0** | Environment-variable-driven configuration (Twelve-Factor App style) |
| **[`httpx`](https://www.python-httpx.org/) ≥ 0.27.0** | Required by FastAPI's `TestClient` for in-process API testing |
| **[`requests`](https://requests.readthedocs.io/) ≥ 2.31.0** | Used by the live HTTP smoke-test client and the Zenodo dataset downloader |
| **`unittest`** (Python standard library) | The full test suite (`tests/`) |
| **`pytest`** | Alternative test runner (a `conftest.py` is provided at the project root) |
| **Docker / Docker Compose** | Containerized deployment (`Dockerfile`, `docker-compose.yml`) — multi-stage, non-root, health-checked image |
| **GitHub Actions CI** | Automated lint (`ruff`), type-check (`mypy`), test, and Docker build on every push/PR |
| **JSON files** (`mock_db.json`, `ledger_file.json`) | Lightweight local persistence, standing in for a real production database |
| **CSV** (`audit_log.csv`) | Human-readable, tool-friendly (Excel/pandas/SIEM) append-only audit trail |
| **Zenodo public dataset** (DOI `10.5281/zenodo.15401061`) | Real (non-purely-synthetic) triathlete physiological data used for realistic evaluation |

No frontend framework, database engine, or GUI toolkit is used — the project is explicitly backend/logic-only, matching the instructor's specification that components like `AthleteDashboard` be "pure-Python, non-GUI, logic-only."

---

## 4. Project Structure (Directory-by-Directory)

```
├── core/         Cryptographic primitives & data contracts (device/gateway-agnostic)
├── edge/         Simulated wearable device + edge-to-cloud transmission pipeline
├── server/       Cloud server logic, FastAPI REST API, configuration, logging
├── ledger/       SHA-256 hashed blockchain ledger for transfer escrow
├── evaluation/   Benchmarking, athlete dashboard logic, reporting
├── dataset/      Public Zenodo dataset adapter for realistic biometric simulation
├── tests/        Full unittest suite (one file per weekly milestone/feature)
├── docs/         Thesis manuscript results + this overview document
├── results/      Snapshot copies of the JSON evaluation outputs
```

### `core/` — Cryptography & Data Contracts

- **`biometric_schema.py`** — Defines `BiometricPayload` (a `TypedDict`) and `validate_biometric_payload()`, a strict "shape gate" that every payload must pass **before** it can be encrypted. It enforces:
  - `heart_rate`: integer, 0–65535 (BPM)
  - `fatigue_index`: float, 0.0–100.0 (%)
  - `glucose_level`: float, non-negative (mg/dL)
  - `gps_telemetry`: nested object with `lat` (-90–90), `lon` (-180–180), `speed_kmh` (non-negative)
  - `injury_risk`: float, 0.0–1.0
  
  Malformed or out-of-range data is rejected with `TypeError`/`ValueError` before it ever reaches the cryptographic layer.

- **`secure_gateway.py`** — The `SecureGateway` class. Its core job is **AES-256-GCM** authenticated encryption/decryption of validated biometric payloads:
  - `encrypt_data()` / `decrypt_data()` — the classic symmetric path: a single pre-shared 256-bit AES key, a fresh random 96-bit nonce per message (`os.urandom(12)`), and Associated Authenticated Data (AAD) built from `gateway_id`, `device_id`, `player_id`, and `sent_at` — binding the ciphertext to its transmission context so it can't be replayed/relabeled under a different identity.
  - `encrypt_data_hybrid()` / `decrypt_data_hybrid()` — the **ECDH hybrid path** (see below): instead of one static AES key, a **session-specific** AES-256 key is derived per (gateway, athlete, club) combination via an ephemeral ECDH exchange + HKDF-SHA256, then used exactly like the symmetric path for the actual AES-GCM encryption.
  - Maintains an in-memory set of used nonces and will refuse to encrypt (raising `ValueError`) rather than risk a catastrophic nonce-reuse under AES-GCM.

- **`ecdh_key_exchange.py`** — Standalone cryptographic primitives for the hybrid scheme:
  - `generate_ec_keypair()` — generates a fresh **ephemeral NIST P-256 (secp256r1)** key pair using the OS CSPRNG.
  - `serialize_public_key()` / `deserialize_public_key()` — PEM (SubjectPublicKeyInfo) encode/decode, with strict type validation (rejects non-EC keys).
  - `derive_session_key()` — performs the actual ECDH scalar multiplication between one party's private key and the other's public key, then feeds the raw shared secret through **HKDF-SHA256** (RFC 5869) with a fixed salt and a **session-specific "info" string** (`build_session_info(gateway_id, player_id, club_id)`), producing a uniformly random 32-byte AES-256 key that is cryptographically bound to that specific session — preventing key confusion across different clubs/athletes/gateways even if EC key material were ever reused.

  Why NIST P-256? It is natively supported by `cryptography`'s OpenSSL backend, is the dominant curve in TLS 1.3/FIDO2/JWK, and offers a 128-bit security level — comfortably enough for short-lived telemetry sessions.

- **`audit_logger.py`** — The `AuditLogger` class: a lightweight, thread-safe, stdlib-only (`csv`, `threading`, `datetime`) CSV writer. Every access-relevant event across the whole system (`TELEMETRY_INGEST`, `CONSENT_GRANTED`/`REVOKED`, `VIEW_BIOMETRIC_DATA`, `TRANSFER_*`, `CLUB_KEY_*`, etc.) is appended as a new row with: UTC timestamp, user ID, user role, player ID, action, status (e.g., `SUCCESS_200`, `DENIED_GDPR_403`, `DENIED_RBAC_403`), and client IP. This satisfies the **Accounting** leg of the AAA (Authentication, Authorization, Accounting) security model and **GDPR Art. 5(2)** (accountability principle) — the controller must be able to *demonstrate* compliance, and this file is the demonstrable evidence.

### `edge/` — Simulated Wearable & Edge Pipeline

- **`iot_device.py`** — `IoTDeviceMock`: simulates a single wearable sensor unit attached to one athlete. `generate_biometrics()` produces one "tick" of randomized-but-realistic raw telemetry (heart rate 60–185 BPM, fatigue 10–95%, glucose 70–140 mg/dL, GPS jitter, injury risk 0.01–0.99). This output is intentionally **plaintext**, representing the real-world vulnerability window between sensor capture and gateway encryption — the exact window the rest of the system is designed to close as fast as possible.

- **`pipeline_week2.py`** — Wires `IoTDeviceMock` and `SecureGateway` together: `adapt_to_schema()` maps the device's raw nested reading into the flat `BiometricPayload` shape, then encrypts it. Includes a runnable demo (`python -m edge.pipeline_week2`) simulating 5 biometric readings, each encrypted and verified round-trip.

- **`live_test_client.py`** — A manual smoke-test client that makes **real HTTP requests** (via `requests`) against a running `uvicorn` server instance, exercising the entire pipeline end-to-end outside of the in-process test suite.

### `server/` — Cloud Server & REST API

- **`cloud_server.py`** — Two key classes:
  - `CloudServer` — the storage backend. It reads/writes `mock_db.json` and enforces a hard **allow-list** of persistable fields (`gateway_id`, `device_id`, `player_id`, `sent_at`, `nonce`, `ciphertext`, `received_at`, plus the ECDH-specific `ephemeral_public_key_pem`/`club_id`). Anything outside that allow-list — i.e., any accidental plaintext field — is rejected before it ever touches disk. It also requires `nonce`/`ciphertext` to be valid hex strings. Writes are atomic (write to a `.tmp` file, then `os.replace()`) so a crash never corrupts the DB.
  - `ConsentRegistry` — a thread-safe, in-memory `player_id → bool` map representing each athlete's live GDPR consent state. This is the single source of truth consulted before any decryption is permitted.
  - `AUTHORIZED_DECRYPT_ROLES` — an explicit allow-list (`{"TEAM_DOCTOR"}`) implementing least-privilege RBAC: only this role may ever receive decrypted biometrics.

- **`main_server.py`** — The FastAPI application exposing everything as a REST API. Key endpoints:
  - `GET /health` — liveness/readiness probe, no auth.
  - `POST /api/v1/telemetry/ingest` *(API key required)* — accepts an encrypted packet (symmetric or hybrid) and stores it.
  - `GET /api/v1/telemetry/stored-ciphertexts` *(public, paginated)* — proves the store contains only ciphertext.
  - `DELETE /api/v1/telemetry/records/{index}` *(API key required)* — GDPR Art. 17 "right to erasure."
  - `POST /api/v1/athlete/consent` *(API key required)* — updates the `ConsentRegistry`.
  - `POST /api/v1/telemetry/authorize-decrypt` *(API key + role + player headers)* — the **4-gate** symmetric decryption path: API key → GDPR consent → RBAC role → AES-GCM decrypt.
  - `POST /api/v1/transfer/process` *(API key + role)* — the **5-gate** athlete-transfer pipeline: API key → GDPR consent → escrow verification → SHA-256 fingerprint of the athlete's stored records → immutable ledger commit → audit log.
  - `POST /api/v1/keys/register-club` / `POST /api/v1/keys/revoke-club` *(API key required)* — manage the `ClubKeyRegistry` (a club's registered NIST P-256 public key), gated by GDPR consent on registration.
  - `POST /api/v1/telemetry/authorize-decrypt-hybrid` *(API key + role + player headers)* — the **4-gate** ECDH hybrid decryption path: API key → GDPR consent → club-authorization check (is this club currently registered?) → ECDH session-key re-derivation + AES-GCM decrypt using the club's supplied private key.

  Also defines the in-process `ClubKeyRegistry` class (thread-safe `club_id → PEM public key` map).

- **`config.py`** — Centralizes all runtime configuration via `pydantic-settings`, reading from environment variables / a `.env` file (`ENVIRONMENT`, `LOG_LEVEL`, `HOST`/`PORT`, `MOCK_DB_PATH`, `AUDIT_LOG_PATH`, `LEDGER_FILE_PATH`, `CLOUD_API_KEY`, `MAX_PACKET_AGE_SECONDS`).

- **`logging_config.py`** — Structured, leveled logging setup shared across the server.

### `ledger/` — Hashed Blockchain for Transfer Escrow

- **`local_hashed_ledger.py`** — `LocalHashedLedger`: a minimal **SHA-256 blockchain** persisted to `ledger_file.json`.
  - `append_transfer_block()` — builds a new block containing `player_id`, `selling_club`, `buying_club`, `escrow_deposit_verified`, `encrypted_payload_hash`, `previous_hash` (linking to the prior block), computes its own SHA-256 `hash`, and appends it atomically.
  - `validate_chain()` — walks every block and re-verifies (a) its own stored hash matches a fresh SHA-256 recomputation, and (b) its `previous_hash` matches the preceding block's actual hash. If **any** historical block is edited after the fact (e.g., someone tries to quietly change which club purchased a player), the chain validation immediately flips from `True` to `False` — directly implementing the **Integrity** leg of the **CIA Triad** and giving anti-black-market traceability for the transfer pipeline.
  - `get_chain()` — returns the full chain for inspection/API responses.

### `evaluation/` — Athlete-Facing Logic, Benchmarking & Reporting

- **`athlete_dashboard.py`** — `AthleteDashboard`: a **pure-Python, non-GUI** class representing the athlete's own client-side controls:
  - `authenticate()` — simple credential check modeling an AAA "Authentication" step (stands in for a real OAuth2/OIDC identity provider).
  - `update_consent()` — toggles `privacy_toggle_consent` and returns an **HMAC-SHA256-signed** consent packet (tamper-evident: bound to `player_id` + UTC timestamp) that can be POSTed to `/api/v1/athlete/consent`.
  - `authorize_club()` / `revoke_club()` / `get_authorized_club_key()` — the athlete's own control plane over which clubs may receive an ECDH session key, gated by both explicit per-club authorization **and** live GDPR consent.

- **`benchmark_evaluation.py`** — Automated Week-8 benchmark suite covering 7 instructor-specified metrics (successful/failed request rate, per-endpoint response times, encryption/decryption overhead, throughput, storage overhead) across 100 iterations, producing `EVALUATION_RESULTS.json` and a Markdown table.

- **`verify_month1_pipeline.py`** — An end-to-end, in-process verification & benchmark script for the "Month 1" milestone (no server required): measures AES-GCM latency vs. raw JSON, payload size overhead, ingestion latency stats, decryption round-trip integrity, and confirms zero plaintext keywords ever appear in `mock_db.json`.

- **`zenodo_report.py`** — Generates a report specifically about the Zenodo dataset integration/evaluation.

### `dataset/` — Realistic Data via Public Research Dataset

- **`zenodo_dataset_loader.py`** — `ZenodoDatasetLoader`: downloads `athletes.csv` from the public **"Synthetic Triathlete Dataset for Injury Prediction Research (2024)"** (Zenodo DOI `10.5281/zenodo.15401061`, CC-BY 4.0, no account/token required) and maps each row into a `BiometricPayload`:
  - `heart_rate` ← `resting_hr` (clamped 40–185 BPM)
  - `fatigue_index` ← derived from `hrv_baseline` (higher HRV → lower fatigue)
  - `glucose_level` ← estimated from `vo2max` + `resting_hr` via a heuristic exercise-physiology formula
  - `injury_risk` ← `stress_factor`, clamped to [0.0, 1.0]
  - `gps_telemetry` ← synthetically jittered around the Kona Ironman World Championship venue (19.6400°N, 155.9969°W), since the source dataset has no GPS column — clearly documented as synthetic.
  
  This lets the whole pipeline be evaluated against **real physiological data distributions** rather than purely synthetic random numbers, strengthening the credibility of the benchmark results.

### `system_evaluation.py` (project root) — Final System-Level Benchmark Suite

The most comprehensive evaluation script, run standalone (`python system_evaluation.py`), using an **in-process FastAPI `TestClient`** (no live network needed) and falling back to `IoTDeviceMock` synthetic data if Zenodo is unreachable. It runs 4 benchmarks and writes `SYSTEM_EVALUATION_RESULTS.json` plus a Markdown report ready to paste into the thesis:

1. **Benchmark 1 — End-to-End Latency**: measures wall-clock time (mean/median/p95/p99) across the full happy path — Gateway AES-256-GCM encryption → server ingestion → authorized decryption — over `N_LATENCY_ITERATIONS` (50) real Zenodo athlete payloads.
2. **Benchmark 2 — Scalability & Throughput**: simulates 10, 50, and 100 **concurrent virtual IoT devices** (via `ThreadPoolExecutor`), each sending several packets, and reports requests/second and per-concurrency-level average/p95 ingest latency.
3. **Benchmark 3 — GDPR Consent Revoke Edge-Case**: while a batch ingestion runs in a background thread, a second thread fires a GDPR consent revoke **mid-flight**, then asserts that literally every subsequent `authorize-decrypt` call for that athlete is rejected with HTTP 403 — proving the consent gate is atomic and race-condition-safe (protected by a `threading.Lock` inside `ConsentRegistry`).
4. **Benchmark 4 — ECDH Hybrid Encryption & Ledger Integrity** *(added later, see below)*: runs 25 full ECDH-hybrid encrypt→ingest→decrypt round-trips end-to-end, measures their timing, confirms that **revoking a club's key immediately blocks its ability to decrypt** (HTTP 403), commits a real transfer block to the SHA-256 ledger, then **deliberately tampers with the ledger file on disk** and confirms `validate_chain()` correctly flips from `True` to `False` — proving the anti-black-market tamper-detection mechanism actually works, not just that it exists in code.

### Why Benchmark 4 was added

The original three benchmarks thoroughly covered the **symmetric AES-256-GCM** path, GDPR consent, RBAC, latency, and throughput — but two entire subsystems that exist in the codebase (`ecdh_key_exchange.py`, `encrypt_data_hybrid`/`decrypt_data_hybrid`, `ClubKeyRegistry`, and `LocalHashedLedger.validate_chain()`) had **no quantitative evaluation at all**. Benchmark 4 closes that gap so the thesis can claim, with actual numbers, that:
- The ECDH hybrid encryption pipeline works correctly end-to-end (25/25 successful round-trips in the latest run).
- Per-club key revocation is enforced immediately and correctly (`club_revocation_enforced: true`).
- The hashed ledger's tamper-detection is not just theoretical — the code was actually caught detecting a real on-disk tamper (`ledger_tamper_detected: true`).

### `docs/` — Written Documentation

- **`THESIS_MANUSCRIPT_RESULTS.md`** — the full thesis write-up and quantitative results narrative.
- **`# Full Test Automation Results — All 7 S.md`** — automated test run reports.
- **`PROJECT_OVERVIEW.md`** *(this file)* — a complete technical reference to the whole system.

### Root-level scripts

- **`run_all.py`** — master runner: auto-discovers and runs **every** `test_*.py` file under `tests/`, and if all pass, runs the Week 2 pipeline demo.
- **`run_benchmarks.py`** — the Docker benchmark runner; copies JSON results to `./results/` on the host.
- **`system_evaluation.py`** — described above.
- **`conftest.py`** — pytest configuration/fixtures shared across the test suite.

---

## 5. The Official Biometric Data Schema

| Data Type | Field Name | Description | Frequency | Expected Size |
|---|---|---|---|---|
| Integer | `heart_rate` | Heart rate (BPM) | 1 / sec | 2 Bytes |
| Float | `fatigue_index` | Muscular fatigue index (%) | 1 / 30 secs | 4 Bytes |
| Float | `glucose_level` | Blood glucose level (mg/dL) | 1 / 5 mins | 4 Bytes |
| JSON Object | `gps_telemetry` | Coordinates & speed (lat, lon, speed) | 1 / sec | ~32 Bytes |
| Float | `injury_risk` | Injury probability (0.0–1.0) | Real-time | 4 Bytes |

Enforced by `validate_biometric_payload()` — every reading, whether from the mock IoT device or the Zenodo dataset adapter, is mapped exactly to this shape before it can be encrypted.

---

## 6. Security Design — Detailed

| Property | Mechanism |
|---|---|
| **Confidentiality** | AES-256-GCM (symmetric path) or ECDH-derived session AES-256 keys (hybrid path); biometric payloads are unreadable to any eavesdropper. |
| **Integrity & Authenticity** | AES-GCM is an AEAD cipher: it appends a 128-bit authentication tag. Any bit of tampering during transit causes decryption to raise `cryptography.exceptions.InvalidTag`. |
| **Replay Protection / Semantic Security** | A fresh cryptographically random 96-bit nonce (`os.urandom(12)`) is generated per message; the gateway tracks used nonces and refuses to reuse one. Identical plaintext never produces identical ciphertext. |
| **Context Binding (AAD)** | `gateway_id`, `device_id`, `player_id`, and `sent_at` are baked into the AES-GCM Associated Authenticated Data, so a valid ciphertext can't be silently relabeled to a different device/athlete/time. |
| **Hybrid Asymmetric-Symmetric Key Exchange** | Ephemeral NIST P-256 key pairs per session; ECDH + HKDF-SHA256 derive a session AES-256 key bound to `(gateway_id, player_id, club_id)` — enabling **per-club, individually revocable** encryption without a long-lived shared master key. |
| **API Authentication** | Every write/decrypt/manage endpoint requires a shared-secret `X-API-Key` header. Only `/telemetry/stored-ciphertexts` is deliberately public — as a live, checkable proof that stored data is ciphertext-only. |
| **Data Minimization (GDPR Art. 5(1)(c))** | `CloudServer` architecturally refuses to persist any field outside its allow-list; plaintext biometrics can never reach disk even by accident. |
| **Right to Erasure (GDPR Art. 17)** | `DELETE /api/v1/telemetry/records/{index}` permanently deletes a stored record by index. |
| **GDPR Consent Management (Art. 7 & 17)** | `AthleteDashboard.update_consent(False)` → `POST /api/v1/athlete/consent` → `ConsentRegistry`. Every subsequent decrypt/transfer/club-key call for that athlete is immediately rejected with HTTP 403, atomically and regardless of the caller's role. |
| **Role-Based Access Control (RBAC)** | Only `X-User-Role: TEAM_DOCTOR` may ever receive decrypted biometrics; every other role (e.g., `ANALYST`, `EXTERNAL_COMPANY`) is rejected with HTTP 403 — principle of least privilege. |
| **Per-Club Key Revocation** | `ClubKeyRegistry` lets an athlete authorize or revoke a specific club's decryption capability independently of the global GDPR toggle, so a club that no longer employs the athlete can be cryptographically cut off. |
| **Ledger Integrity (CIA — Integrity)** | `LocalHashedLedger` chains every transfer as a SHA-256 block referencing the previous block's hash; `validate_chain()` detects any retroactive tampering. |
| **Accounting / Traceability** | `AuditLogger` records every access attempt — success or denial — to an append-only CSV, satisfying GDPR Art. 5(2) accountability and enabling anti-black-market forensic investigation. |

---

## 7. Testing Strategy

The `tests/` package contains a `unittest`-based suite, one file roughly per weekly project milestone, discoverable and runnable via either:

```zsh
venv/bin/python -m unittest discover -s tests -p "test_*.py" -v
# or
venv/bin/python -m pytest tests/ -v
```

| Test file | Focus |
|---|---|
| `test_week1.py` | Biometric schema validation + AES-256-GCM encryption/decryption unit & integration tests. |
| `test_pipeline_week3.py` | Cloud Server REST API: full ingest→store→decrypt pipeline, ciphertext-only exposure proof, wrong-key rejection, non-hex ciphertext rejection, missing API key rejection, pagination, GDPR erasure endpoint, health check. |
| `test_pipeline_week5.py` | GDPR consent toggle & RBAC integration tests. |
| `test_pipeline_week6.py` | Audit logging & anti-black-market integration tests. |
| `test_pipeline_week7.py` | Hashed ledger & transfer escrow integration tests, including simulated MITM tampering detection. |
| `test_pipeline_week8.py` | ECDH hybrid encryption integration tests. |
| `test_full_system_week8.py` | Master regression suite — reruns all prior weeks' tests, plus integrity checks on the `EVALUATION_RESULTS.json` file itself (all expected metric keys present, response times populated for every endpoint, storage-overhead fields present, 100% successful/failed request rate assertions where applicable). |
| `test_zenodo_integration.py` | Zenodo public dataset loader integration tests (download, parsing, schema mapping correctness). |

Running `python run_all.py` auto-discovers and executes **all** of the above, and — only if every single test passes — proceeds to run the Week 2 pipeline demo (5 simulated biometric readings, each encrypted and verified leak-free) as a final visual sanity check.

### Evaluation vs. Testing — the distinction

- **`tests/`** answers: *"Does the system behave correctly (pass/fail)?"* — unit and integration correctness.
- **`benchmark_evaluation.py`** and **`system_evaluation.py`** answer: *"How well/fast/efficiently does it behave, and does it hold up under concurrency and adversarial edge cases?"* — quantitative, numeric evaluation, producing the JSON/Markdown artifacts that feed directly into the thesis manuscript's results chapter.

---

## 8. Configuration & Deployment

All runtime configuration is environment-driven (Twelve-Factor App style), via `server/config.py`:

| Variable | Default | Purpose |
|---|---|---|
| `ENVIRONMENT` | `development` | `development` / `staging` / `production` |
| `LOG_LEVEL` | `INFO` | Python logging level |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | uvicorn bind address |
| `MOCK_DB_PATH` | `mock_db.json` | JSON persistence layer path |
| `AUDIT_LOG_PATH` | `audit_log.csv` | CSV audit log path |
| `LEDGER_FILE_PATH` | `ledger_file.json` | Hashed transfer ledger path |
| `CLOUD_API_KEY` | `dev-only-insecure-change-me` | Shared secret required via `X-API-Key` |
| `MAX_PACKET_AGE_SECONDS` | `300` | Default replay-protection freshness window |

**Docker**: A multi-stage, non-root, health-checked `Dockerfile` packages the API. `docker-compose.yml` defines the `cloud-server` service plus a one-shot `benchmark` service that runs both evaluation scripts inside the container and copies the resulting JSON files to `./results/` on the host — making the quantitative results reproducible on any machine with Docker, independent of the developer's local Python setup.

**CI/CD**: `.github/workflows/ci.yml` runs on every push/PR: lint (`ruff`) → type-check (`mypy`) → full test suite → Docker image build, catching regressions before merge.

---

## 9. Roadmap / How the project evolved (weekly milestones)

- **Week 1** — Environment setup & core encryption module (`SecureGateway`, AES-256-GCM).
- **Week 2** — IoT device mocking & edge transmission pipeline.
- **Week 3** — Cloud Server & secure REST API (encrypted-only storage, authorized decryption).
- **Week 4** — End-of-Month-1 integration, benchmarking & verification.
- **Week 5** — Access control & GDPR consent toggle (`AthleteDashboard`, `ConsentRegistry`, RBAC).
- **Week 6** — Audit logging & anti-black-market protection (`AuditLogger`, full AAA "Accounting" trail).
- **Week 7** — Local hashed ledger & transfer escrow simulation (SHA-256 blockchain, MITM tampering detection).
- **Week 8** — End-to-end evaluation & benchmarking (`benchmark_evaluation.py`, master regression tests, thesis manuscript results).
- **Post-Week-8 extensions**:
  - Hybrid ECDH key exchange & per-club key management (`ecdh_key_exchange.py`, `ClubKeyRegistry`, `authorize-decrypt-hybrid`).
  - Public Zenodo dataset integration for realistic evaluation data.
  - Paginated ciphertext listing & GDPR erasure endpoint.
  - Project-wide restructuring into `core/`, `edge/`, `server/`, `ledger/`, `evaluation/`, `dataset/`, `tests/` packages.
  - Standalone `system_evaluation.py` (latency/throughput/scalability/GDPR benchmark), later extended with **Benchmark 4** to also cover ECDH hybrid encryption correctness and ledger tamper detection quantitatively.
  - Docker Compose `benchmark` service for reproducible, containerized evaluation runs.

All CIA Triad (Confidentiality, Integrity, Availability), AAA (Authentication, Authorization, Accounting), and GDPR requirements from the original roadmap are fulfilled, with additional hybrid-cryptography and real-world-dataset extensions layered on top.

---

## 10. Key Takeaways for Understanding the Project

1. **It is a defense-in-depth system**, not a single trick: encryption, schema validation, storage isolation, consent checks, RBAC, audit logging, and a tamper-evident ledger are all separate, independently testable layers that must each pass before sensitive data is ever exposed.
2. **Every security claim is backed by both a unit/integration test (`tests/`) and a quantitative benchmark (`system_evaluation.py` / `benchmark_evaluation.py`)** — the project doesn't just implement security features, it measures and proves them (e.g., proving the ledger really does detect tampering, not just that the code exists to do so).
3. **Two encryption modes coexist by design**: a simple static-key symmetric mode (fast, simple, good for a single trusted analytics backend) and an ECDH hybrid mode (slightly more overhead, but enables fine-grained, revocable, per-club access — essential for the realistic scenario of athletes transferring between clubs).
4. **The Zenodo dataset integration elevates the thesis from "purely synthetic toy data" to "evaluated against real published physiological data,"** strengthening the credibility of the benchmark numbers.
5. **The whole system can be exercised without any live network or database** — `FastAPI`'s `TestClient` runs the full HTTP stack in-process, which is why the test suite and evaluation scripts run quickly and deterministically, while `docker-compose up` / `edge/live_test_client.py` demonstrate the same logic over a real network socket when needed.
