# Chapter 4 & 5 — Implementation & Evaluation
## Thesis: *Data Privacy in Elite Performance: Protecting Athlete Biometrics*

> **Author:** Mitsaggaspanagiotes  
> **Academic Year:** 2025–2026  
> **Status:** Week 8 — Final Evaluation Complete ✅

---

## 4. System Architecture & Implementation

### 4.1 Overview

The implemented system is a seven-module Python pipeline that protects athlete
biometric data from the point of IoT sensor capture through edge encryption,
authenticated cloud storage, GDPR-compliant access control, complete audit
traceability, and immutable transfer-ledger commitment. All modules are
integrated into a single FastAPI REST API (v7.0.0) and containerised with
Docker for reproducible deployment.

The pipeline enforces the **CIA Triad** (Confidentiality, Integrity,
Availability) and the **AAA security framework** (Authentication,
Authorization, Accounting) at every stage, while maintaining full compliance
with the relevant articles of the **General Data Protection Regulation
(GDPR)**.

---

### 4.2 End-to-End Data Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                     ATHLETE BIOMETRICS PIPELINE                     │
└─────────────────────────────────────────────────────────────────────┘

  [EDGE LAYER]                [CLOUD API LAYER]            [DATA LAYER]
  ─────────────               ──────────────────           ────────────

  ┌──────────────┐            ┌──────────────────┐
  │ IoTDeviceMock│──generate─▶│  SecureGateway   │
  │  (Week 2)    │ biometrics │  AES-256-GCM     │──encrypt──▶ ciphertext
  └──────────────┘            │  (Week 1)        │
                              └────────┬─────────┘
                                       │ POST /api/v1/telemetry/ingest
                                       ▼
                              ┌──────────────────┐
                              │   CloudServer    │──store──▶ mock_db.json
                              │  (Week 3)        │            (ciphertext only)
                              └────────┬─────────┘
                                       │
                         ┌─────────────┼─────────────┐
                         │             │             │
                         ▼             ▼             ▼
                  ┌───────────┐ ┌──────────┐ ┌────────────┐
                  │Consent    │ │  RBAC    │ │ AuditLogger│
                  │Registry   │ │  Check   │ │  (Week 6)  │
                  │(Week 5)   │ │(Week 5)  │ └─────┬──────┘
                  └─────┬─────┘ └────┬─────┘       │
                        │            │              │ audit_log.csv
                        └─────┬──────┘              ▼
                              │            ┌────────────────┐
                              ▼            │LocalHashedLedger│
                    GDPR + RBAC Gate       │   (Week 7)     │
                    ── PASS ──▶ decrypt    └────────────────┘
                    ── FAIL ──▶ HTTP 403    ledger_file.json
                                            (SHA-256 chain)
```

---

### 4.3 Module Breakdown

| Module | File | Week | Primary Responsibility |
|---|---|---|---|
| `IoTDeviceMock` | `iot_device.py` | 2 | Simulates WBAN biometric sensor — generates realistic physiological readings (heart rate, fatigue index, glucose, GPS, injury risk) |
| `SecureGateway` | `secure_gateway.py` | 1 | AES-256-GCM edge encryption with 12-byte IV and authenticated associated data (AAD) binding gateway/device/player context |
| `CloudServer` | `cloud_server.py` | 3 | Encrypted-only storage (never stores plaintext); JSON persistence layer with atomic writes |
| `ConsentRegistry` | `cloud_server.py` | 5 | Thread-safe in-memory GDPR consent map; single source of truth for consent state across all endpoints |
| `AthleteDashboard` | `athlete_dashboard.py` | 5 | Athlete-facing consent toggle with HMAC-SHA256 signed consent packets |
| `AuditLogger` | `audit_logger.py` | 6 | CSV-based audit trail logging every data-access event with UTC timestamp, role, action, status, IP |
| `LocalHashedLedger` | `local_hashed_ledger.py` | 7 | SHA-256 blockchain for athlete transfer records; Genesis Block + append-only chain with MITM tamper detection |
| `main_server` | `main_server.py` | 3–7 | FastAPI v7.0.0 REST API integrating all modules; 5 endpoints, rate limiting, API-key auth |

---

### 4.4 Biometric Data Schema

The `BiometricPayload` captured by `IoTDeviceMock` and validated by
`adapt_to_schema()` (`pipeline_week2.py`) before encryption:

| Field | Type | Range / Format | Security Note |
|---|---|---|---|
| `heart_rate` | `int` | 60–185 BPM | Medical indicator; classified sensitive data under GDPR Art. 9 |
| `fatigue_index` | `float` | 10.0–95.0 % | Performance intelligence; primary espionage target |
| `glucose_level` | `int` | 70–140 mg/dL | Biometric health marker |
| `gps_telemetry.latitude` | `float` | –90.0 to 90.0 | Positional data; tactical espionage risk |
| `gps_telemetry.longitude` | `float` | –180.0 to 180.0 | Positional data |
| `gps_telemetry.speed_m_s` | `float` | 0.0–9.5 m/s | Sprint velocity; competitive performance data |
| `injury_risk` | `float` | 0.01–0.99 | Aggregate injury probability; transfer negotiation leverage |

All fields are AES-256-GCM encrypted at the edge **before** transmission.
The cloud server **never** receives or stores plaintext biometrics.

---

### 4.5 REST API Route Summary

| Method | Endpoint | Auth Required | Description |
|---|---|---|---|
| `POST` | `/api/v1/telemetry/ingest` | API Key | Ingest an encrypted biometric packet from the gateway |
| `GET` | `/api/v1/telemetry/stored-ciphertexts` | None | List stored ciphertexts (proof-of-encryption, no PII) |
| `POST` | `/api/v1/athlete/consent` | API Key | Grant or revoke GDPR consent for a player |
| `POST` | `/api/v1/telemetry/authorize-decrypt` | API Key + Role | Decrypt a stored record (gated by GDPR + RBAC) |
| `POST` | `/api/v1/transfer/process` | API Key + Role | Process a club-to-club transfer (gated by GDPR + Escrow + Ledger) |

---

### 4.6 Security Parameter Summary

| Parameter | Value | Standard |
|---|---|---|
| Symmetric cipher | AES-256-GCM | NIST SP 800-38D |
| Key size | 256 bits (32 bytes) | NIST SP 800-57 |
| IV / Nonce size | 96 bits (12 bytes) | Recommended for GCM |
| Authentication tag | 128 bits (16 bytes) | GCM default |
| AAD fields | gateway_id, device_id, player_id, sent_at | Context binding |
| Hash function | SHA-256 | FIPS PUB 180-4 |
| Consent signing | HMAC-SHA256 | RFC 2104 |
| Replay protection window | 300 seconds (configurable) | Custom sliding window |
| Rate limiting | 60 req / 60-second window | Custom sliding window |
| Transfer ledger | SHA-256 blockchain | Custom (educational) |

---

## 5. Evaluation & Performance Analysis

### 5.1 Experimental Setup

The evaluation was conducted on a MacOS development machine using the
FastAPI `TestClient` (Starlette in-process ASGI), which eliminates TCP
round-trip overhead to isolate **application-level** latency — the metric
that is directly attributable to the cryptographic and data-processing logic
implemented across Weeks 1–7. All timing measurements use
`time.perf_counter()` (nanosecond resolution). Each metric was computed over
**100 iterations** to ensure statistical stability.

---

### 5.2 Evaluation Metrics Results

The following table presents the complete evaluation results obtained by
running `benchmark_evaluation.py` against the full 7-module pipeline:

| # | Metric | Measured Value |
|---|--------|---------------|
| 1 | Successful Request Rate (valid inputs) | **100.0%** |
| 2 | Failed Request Rate (expected 4xx — RBAC/GDPR blocked) | **100.0%** |
| 3a | Avg API Response Time — `/api/v1/telemetry/ingest` | **1.88 ms** |
| 3b | Avg API Response Time — `/api/v1/athlete/consent` | **1.26 ms** |
| 3c | Avg API Response Time — `/api/v1/telemetry/authorize-decrypt` | **2.86 ms** |
| 3d | Avg API Response Time — `/api/v1/transfer/process` | **3.34 ms** |
| 4 | AES-256-GCM Encryption Overhead vs. raw JSON serialisation | **0.009 ms** |
| 5 | AES-256-GCM Decryption Overhead | **0.006 ms** |
| 6 | Peak Throughput (batch ingestion, rate limiter bypassed) | **375.0 req/sec** |
| 7a | Storage — Raw Biometric JSON | **252 bytes** |
| 7b | Storage — AES-256-GCM Ciphertext Envelope | **720 bytes** |
| 7c | Storage — Audit Log CSV Row | **109 bytes** |
| 7d | Storage — SHA-256 Ledger Block | **408 bytes** |
| 7e | Ciphertext Storage Overhead vs. Raw Payload | **+185.7%** |

> *Source: `EVALUATION_RESULTS.json`, generated by `benchmark_evaluation.py` (100 iterations, 2026-08-07)*

---

### 5.3 Performance Analysis

#### 5.3.1 Encryption Overhead — Operationally Negligible

The measured AES-256-GCM encryption overhead of **0.009 ms** (9 microseconds)
confirms the core performance hypothesis of this thesis: **military-grade
cryptographic protection can be applied to real-time biometric streams without
introducing perceptible latency**. This finding is consistent with the
literature on hardware-accelerated AES, which benefits from AES-NI CPU
extensions available on modern x86 and ARM architectures.

For reference, a professional sports data acquisition system typically samples
at 100–500 Hz (one reading every 2–10 ms). An encryption overhead of 0.009 ms
represents less than **0.5%** of the minimum inter-sample interval — completely
imperceptible in any real-time application scenario.

The decryption overhead of **0.006 ms** is similarly negligible, confirming
that authorised clinicians and coaching staff can access decrypted records
effectively instantaneously, with no operational impact on decision-making
during a match or recovery assessment.

#### 5.3.2 API Response Times — Sub-5 ms Across All Endpoints

All four API endpoints respond within **3.5 ms** on average. The
`/authorize-decrypt` endpoint (2.86 ms) and `/transfer/process` (3.34 ms)
are the most computationally intensive because they combine:

1. GDPR consent lookup (in-memory `ConsentRegistry`)
2. RBAC role validation
3. Cryptographic key parsing and AES-256-GCM decryption (decrypt endpoint)
4. SHA-256 payload hashing + blockchain ledger append + `validate_chain()` (transfer endpoint)

Despite these combined operations, all endpoints comfortably satisfy the
sub-100 ms latency threshold typical for real-time sports IT systems.

#### 5.3.3 Throughput — 375 req/sec

The measured peak throughput of **375 requests/second** demonstrates that
the system can process an entire squad of 25 athletes transmitting at
15 Hz (375 readings/sec combined) in real time. In practice, the deployed
rate limiter enforces a conservative 60 requests per 60-second window per
client IP — a deliberate trade-off prioritising security (DDoS/replay
protection) over raw throughput.

#### 5.3.4 Storage Overhead — The Cost of Confidentiality

The ciphertext envelope (720 bytes) is **185.7% larger** than the raw
biometric payload (252 bytes). This overhead is attributable to:

| Component | Size (approx.) | Purpose |
|---|---|---|
| 12-byte nonce (base64) | ~16 bytes | GCM initialization vector |
| 128-bit GCM auth tag | included in ciphertext | Authenticated encryption tag |
| Envelope metadata | ~296 bytes | gateway_id, device_id, player_id, sent_at |
| Base64 encoding | ~14% bloat | JSON-safe representation of binary data |

For a 25-player squad transmitting at 10 Hz over a 90-minute match:
- **Raw data:** 25 × 10 × 5400 × 252 bytes ≈ **342 MB**
- **Encrypted envelopes:** 25 × 10 × 5400 × 720 bytes ≈ **972 MB**

This ~630 MB overhead per match is entirely acceptable for modern cloud
storage economics, particularly given that the trade-off delivers complete
**Confidentiality** protection for Art. 9 GDPR special-category health data.

---

## 6. Theoretical Framework Mapping

### 6.1 CIA Triad Compliance Table

| CIA Pillar | Mechanism | Module | Implementation Detail |
|---|---|---|---|
| **Confidentiality** | AES-256-GCM Edge Encryption | `SecureGateway` | All biometric data encrypted at source before leaving the IoT device boundary; cloud server stores ciphertext only |
| **Confidentiality** | GDPR Consent Gate | `ConsentRegistry` | `POST /api/v1/telemetry/authorize-decrypt` blocked if `privacy_toggle_consent == False` |
| **Confidentiality** | RBAC Enforcement | `main_server.py` | Only `TEAM_DOCTOR` and `HEAD_COACH` roles may decrypt; `ANALYST` and `EXTERNAL_COMPANY` receive HTTP 403 |
| **Integrity** | SHA-256 Blockchain | `LocalHashedLedger` | Each transfer block contains SHA-256 of previous block; `validate_chain()` detects any single-character modification |
| **Integrity** | Authenticated Encryption | `SecureGateway` | AES-GCM authentication tag verifies ciphertext has not been tampered with in transit or at rest |
| **Integrity** | Atomic File Writes | `CloudServer`, `LocalHashedLedger` | Write to `.tmp` + `os.replace()` — no partial writes corrupt the data store |
| **Availability** | FastAPI Rate Limiter | `main_server.py` | Sliding-window rate limiter (60 req/60 s) prevents DoS attacks from exhausting cloud resources |
| **Availability** | Docker Health Check | `Dockerfile` | `HEALTHCHECK` on `/health` every 30 s with `restart: unless-stopped` ensures automatic recovery |
| **Availability** | Persistent Volumes | `docker-compose.yml` | `mock_db.json`, `audit_log.csv`, `ledger_file.json` all persisted to `/data` volume — survive container restarts |

---

### 6.2 AAA (Authentication, Authorization, Accounting) Table

| AAA Leg | Mechanism | Module | Implementation Detail |
|---|---|---|---|
| **Authentication** | API Key validation | `main_server.py` | `X-API-Key` header checked on every protected endpoint via `require_api_key` dependency |
| **Authentication** | Athlete login status | `AthleteDashboard` | `authenticate(credentials)` validates username/password against credential store; sets `login_status = True` |
| **Authentication** | HMAC-signed consent packets | `AthleteDashboard` | Consent updates are HMAC-SHA256 signed with a device-local key, binding the decision to `player_id` + UTC timestamp |
| **Authorization** | RBAC role check | `cloud_server.py` | `AUTHORIZED_DECRYPT_ROLES = {"TEAM_DOCTOR", "HEAD_COACH"}` enforced before any decryption |
| **Authorization** | GDPR consent gate | `ConsentRegistry` | `is_consent_granted(player_id)` checked before decrypt AND before transfer — consent revocation overrides all roles |
| **Authorization** | Escrow verification gate | `main_server.py` | `escrow_deposit_verified` boolean must be `True` for transfer; prevents ledger commitment before financial settlement |
| **Accounting** | Access audit log | `AuditLogger` | Every endpoint call writes a timestamped CSV row: `timestamp, user_id, user_role, player_id, action, status, ip_address` |
| **Accounting** | Transfer ledger | `LocalHashedLedger` | Every committed transfer is a permanent, tamper-evident blockchain block — immutable evidence of data movement |
| **Accounting** | Server access log | `logging_config.py` | Structured JSON-formatted Python logger records every request with method, path, status, latency |

---

### 6.3 GDPR Principles Compliance Table

| GDPR Principle | Article | Implementation | Module |
|---|---|---|---|
| **Lawfulness, Fairness & Transparency** | Art. 5(1)(a) | API key + role-based access ensures data is only processed by authorised parties for documented purposes | `main_server.py` |
| **Purpose Limitation** | Art. 5(1)(b) | `AUTHORIZED_DECRYPT_ROLES` restricts access to medical/coaching staff; transfer endpoint only hashes, never exposes raw decrypted data | `cloud_server.py` |
| **Data Minimisation** | Art. 5(1)(c) | `BiometricPayload` schema captures only clinically relevant fields (7 fields); no free-text PII collected | `pipeline_week2.py` |
| **Accuracy** | Art. 5(1)(d) | Schema validation (`adapt_to_schema()`) rejects malformed payloads before storage | `pipeline_week2.py` |
| **Storage Limitation** | Art. 5(1)(e) | Each stored record contains `player_id` + `gateway_id` for identification; no duplication of raw plaintext | `cloud_server.py` |
| **Integrity & Confidentiality** | Art. 5(1)(f) | AES-256-GCM encryption + SHA-256 ledger chain + atomic writes enforce confidentiality and integrity at every layer | `SecureGateway`, `LocalHashedLedger` |
| **Accountability** | Art. 5(2) | `AuditLogger` records every data access event with actor, timestamp, action, status, and IP address | `audit_logger.py` |
| **Consent** | Art. 6(1)(a) & Art. 7 | `privacy_toggle_consent` boolean — athlete can grant or revoke at any time via `POST /api/v1/athlete/consent` | `AthleteDashboard`, `ConsentRegistry` |
| **Right to Withdraw Consent** | Art. 7(3) | Revocation immediately blocks all decryption requests (no grace period); `ConsentRegistry` is the single real-time authority | `ConsentRegistry` |
| **Protection by Design** | Art. 25 | Encryption is the default — the server *cannot* receive plaintext biometrics; the API schema rejects unencrypted payloads | `CloudServer`, `main_server.py` |
| **Special Category Data** | Art. 9 | Health and biometric data recognised as special category; stricter role-based gating (`TEAM_DOCTOR` / `HEAD_COACH` only) applied | `cloud_server.py` |

---

## 7. Security Threat Analysis

### 7.1 Threat Model — Addressed Attack Vectors

| Attack Vector | Threat | Countermeasure | Status |
|---|---|---|---|
| Tactical Performance Espionage | Opponent intercepts raw biometric stream during match | AES-256-GCM encryption at IoT edge — plaintext never transmitted | ✅ Mitigated |
| Man-in-the-Middle (Network) | Attacker modifies ciphertext in transit | GCM authentication tag; `InvalidTag` exception raised on tampered ciphertext | ✅ Mitigated |
| Man-in-the-Middle (Ledger) | Attacker modifies a transfer record post-commitment | SHA-256 chain validation; any single-character change invalidates all subsequent blocks | ✅ Mitigated (tested) |
| Replay Attack | Attacker re-submits a captured ingest packet | `sent_at` timestamp + 300-second freshness window; replays older than 5 min rejected | ✅ Mitigated |
| Unauthorised Data Access (RBAC) | `EXTERNAL_COMPANY` or `ANALYST` accesses athlete medical data | Role check against `AUTHORIZED_DECRYPT_ROLES`; HTTP 403 + audit entry for all violations | ✅ Mitigated (tested) |
| Athlete Data Sold Without Consent | Club sells biometric data without GDPR approval | GDPR consent gate on decrypt + transfer endpoint; revoked consent blocks all access immediately | ✅ Mitigated (tested) |
| Denial of Service | Flood of ingest requests exhausts server resources | Sliding-window rate limiter: 60 req / 60s per IP; HTTP 429 after threshold | ✅ Mitigated |
| Black Market Transfer | Club transfers athlete without financial settlement | `escrow_deposit_verified` gate; no ledger block committed before escrow confirmed | ✅ Mitigated (tested) |

---

## 8. Test Coverage Summary

| Test Suite | Week | Tests | Result |
|---|---|---|---|
| `test_week1.py` | 1–2 | 55 | ✅ All passed |
| `test_pipeline_week3.py` | 3 | 15 | ✅ All passed |
| `test_pipeline_week5.py` | 5 | 15 | ✅ All passed |
| `test_pipeline_week6.py` | 6 | 21 | ✅ All passed |
| `test_pipeline_week7.py` | 7 | 28 | ✅ All passed |
| `test_full_system_week8.py` | 8 | 13 (+ 114 regression) | ✅ All passed |
| **TOTAL** | **1–8** | **147** | **✅ 100% Pass Rate** |

---

## 9. Conclusion

This thesis has demonstrated that **military-grade biometric data protection
is achievable at negligible operational cost** for professional sports
organisations. The implemented system:

1. **Encrypts all biometric data at the IoT edge** (AES-256-GCM, 0.009 ms overhead)
   before it can be intercepted on the wireless channel.

2. **Enforces GDPR compliance by design** — the cloud server is architecturally
   incapable of receiving or storing plaintext health data; consent revocation
   propagates immediately across all endpoints.

3. **Provides complete AAA accountability** — every data access event is
   logged with actor, timestamp, status, and IP address, enabling forensic
   investigation of any suspected black-market data sale.

4. **Guarantees transfer integrity** — the SHA-256 ledger chain ensures that
   once a transfer is committed, no retroactive modification of the transferred
   biometric data bundle can go undetected.

5. **Operates at production-viable scale** — 375 req/sec throughput, all
   endpoints under 3.5 ms, with full Docker containerisation and CI/CD
   integration.

The measured AES-256-GCM overhead of **0.009 ms** — less than 0.5% of a
typical IoT sensor sampling interval — confirms that privacy-by-design need
not be a constraint on real-time sports science. This system provides a
viable, deployable blueprint for protecting athlete biometric data while
preserving the performance intelligence that professional sports organisations
depend upon.

---

*Document generated: 2026-08-07 | Benchmark source: `EVALUATION_RESULTS.json` | Tests: `test_full_system_week8.py` (147 tests, 100% pass rate)*
