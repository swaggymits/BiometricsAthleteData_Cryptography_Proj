# Data Privacy in Elite Performance: Protecting Athlete Biometrics

Bachelor's Thesis project implementing a secure edge-to-cloud pipeline for protecting sensitive athlete biometric telemetry (heart rate, fatigue, glucose, GPS, injury risk) against **tactical performance espionage** using authenticated encryption (AES-256-GCM).

---

## Project Overview

Modern elite sports teams rely on wearable IoT sensors (WBAN — Wireless Body Area Network) to continuously monitor athlete biometrics in real time. If this telemetry is intercepted in plaintext, rival teams or malicious actors could exploit it to detect player exhaustion, tactical weaknesses, or injury risk during a live match.

This project implements, week by week, a secure data pipeline that encrypts biometric data **immediately at the edge** (on the wearable/gateway) before it ever touches the network, using industry-standard authenticated encryption.

---

## Architecture

```
[Wearable Sensor]  --BLE-->  [Edge Gateway]  --Network-->  [Cloud Server]
 IoTDeviceMock                SecureGateway                 (future work)
 (raw plaintext)          (AES-256-GCM encryption)
```

1. **`IoTDeviceMock`** simulates a wearable sensor generating raw biometric readings.
2. **`biometric_schema.py`** enforces a strict Data Schema contract on every payload before it is allowed to be encrypted — rejecting malformed or out-of-range telemetry.
3. **`SecureGateway`** encrypts validated payloads with AES-256-GCM (unique nonce per message, authenticated tag for integrity/tamper-detection).
4. **`pipeline_week2.py`** wires the device and gateway together into an end-to-end tick-by-tick simulation.

---

## Project Structure

```
├── biometric_schema.py     # Strict Data Schema contract + validation (BiometricPayload)
├── secure_gateway.py        # SecureGateway class — AES-256-GCM encryption/decryption
├── iot_device.py             # IoTDeviceMock class — simulated wearable sensor
├── pipeline_week2.py         # Integration pipeline: IoTDeviceMock -> SecureGateway
├── run_all.py                 # Master runner: all tests + pipeline demo in one command
├── test_week1.py               # Unit/integration tests (schema validation + encryption)
├── requirements.txt             # Python dependencies
├── .vscode/launch.json           # VS Code Run & Debug configurations
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

---

## Getting Started

### 1. Set up the virtual environment

```zsh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Run everything (tests + pipeline demo) in one command

```zsh
venv/bin/python run_all.py
```

This will:
1. Auto-discover and run **all** `test_*.py` files (schema validation + encryption/decryption tests).
2. If all tests pass, run the **Week 2 pipeline demo** — 5 simulated biometric readings, each encrypted and verified leak-free.

### 3. Run just the test suite

```zsh
venv/bin/python -m unittest test_week1 -v
```

### 4. Run just the pipeline demo

```zsh
venv/bin/python pipeline_week2.py
```

### 5. Run & Debug from VS Code

Open the **Run and Debug** panel and choose one of the pre-configured launch options:

- **Python: Run Entire Project (run_all.py)** — runs all tests + pipeline demo.
- **Python: Debug test_week1.py (unittest)** — debug the test suite with breakpoints.
- **Python: Current File** — debug whichever file is currently open.

---

## Requirements

- Python 3.9+
- [`cryptography`](https://cryptography.io/) >= 42.0.0

---

## Roadmap

- ✅ **Week 1** — Environment setup & core encryption module (`SecureGateway`, AES-256-GCM).
- ✅ **Week 2** — IoT device mocking & edge transmission pipeline (`IoTDeviceMock`, `pipeline_week2.py`).
- 🔜 **Future weeks** — Cloud server ingestion, key management/rotation, secure storage, access control, performance benchmarking.

---

## Disclaimer

This is an academic thesis prototype. It simulates hardware/network behavior in software and is not intended for production deployment without further security hardening (e.g., proper key management/HSM integration, mutual TLS, certificate-based device authentication).
