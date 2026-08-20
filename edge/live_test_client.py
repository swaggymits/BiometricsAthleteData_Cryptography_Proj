"""
Ad-hoc live test client (manual verification, not part of the automated test
suite): generates REAL biometric readings from IoTDeviceMock, encrypts them
with SecureGateway, and sends them to a LIVE running main_server.py instance
via real HTTP requests (requires the server to already be running).

Usage:
    venv/bin/python -m uvicorn main_server:app &
    venv/bin/python live_test_client.py
"""

from __future__ import annotations

import json

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.config import settings
from edge.iot_device import IoTDeviceMock
from edge.pipeline_week2 import adapt_to_schema
from core.secure_gateway import SecureGateway

BASE_URL = "http://localhost:8000"
API_KEY_HEADERS = {"X-API-Key": settings.CLOUD_API_KEY}

ATHLETES = [
    ("IOT-WBAN-001", "PLAYER-07"),
    ("IOT-WBAN-002", "PLAYER-10"),
    ("IOT-WBAN-003", "PLAYER-23"),
]


def main() -> None:
    shared_key = AESGCM.generate_key(bit_length=256)
    gateway = SecureGateway(gateway_id="GW-LIVE-01", aes_key=shared_key)

    sent_records = []

    print("=" * 80)
    print("LIVE TEST: Real biometric data -> AES-256-GCM -> FastAPI Cloud Server")
    print("=" * 80)

    for device_id, player_id in ATHLETES:
        device = IoTDeviceMock(device_id=device_id, player_id=player_id)
        raw_reading = device.generate_biometrics()
        schema_payload = adapt_to_schema(raw_reading)

        packet = gateway.encrypt_data(
            schema_payload, device_id=device.device_id, player_id=device.player_id
        )

        print(f"\n--- Athlete {player_id} ({device_id}) ---")
        print(f"[RAW PLAINTEXT] heart_rate={schema_payload['heart_rate']} "
              f"fatigue={schema_payload['fatigue_index']} "
              f"glucose={schema_payload['glucose_level']} "
              f"injury_risk={schema_payload['injury_risk']}")

        resp = requests.post(f"{BASE_URL}/api/v1/telemetry/ingest", json=packet, headers=API_KEY_HEADERS)
        print(f"[POST /ingest] status={resp.status_code} body={resp.json()}")
        assert resp.status_code == 201, f"Ingest failed: {resp.text}"

        sent_records.append((schema_payload, packet))

    print("\n" + "=" * 80)
    print("VERIFYING: GET /stored-ciphertexts must expose ONLY encrypted noise")
    print("=" * 80)
    resp = requests.get(f"{BASE_URL}/api/v1/telemetry/stored-ciphertexts")
    assert resp.status_code == 200
    envelope = resp.json()
    stored = envelope["records"]  # paginated response: {total, offset, limit, records}
    stored_text = json.dumps(stored)
    print(f"Stored record count: {len(stored)} (total in DB: {envelope['total']})")

    for schema_payload, _packet in sent_records:
        for field in ("heart_rate", "fatigue_index", "glucose_level", "injury_risk"):
            marker = f'"{field}": {schema_payload[field]}'
            assert marker not in stored_text, f"LEAK DETECTED: {marker}"
    print("[VERIFIED] No plaintext biometric values found in stored ciphertexts. ✅")

    print("\n" + "=" * 80)
    print("VERIFYING: authorize-decrypt with CORRECT key recovers original data")
    print("=" * 80)
    for schema_payload, packet in sent_records:
        resp = requests.post(
            f"{BASE_URL}/api/v1/telemetry/authorize-decrypt",
            json={"record": packet, "aes_key_hex": shared_key.hex()},
            headers=API_KEY_HEADERS,
        )
        assert resp.status_code == 200, resp.text
        decrypted = resp.json()["decrypted_payload"]
        assert decrypted == schema_payload, "Decrypted payload mismatch!"
        print(f"[OK] {packet['player_id']}: decrypted payload matches original exactly.")

    print("\n" + "=" * 80)
    print("VERIFYING: authorize-decrypt with WRONG key is rejected (401)")
    print("=" * 80)
    wrong_key = AESGCM.generate_key(bit_length=256)
    resp = requests.post(
        f"{BASE_URL}/api/v1/telemetry/authorize-decrypt",
        json={"record": sent_records[0][1], "aes_key_hex": wrong_key.hex()},
        headers=API_KEY_HEADERS,
    )
    print(f"[POST /authorize-decrypt] wrong key -> status={resp.status_code} "
          f"body={resp.json()}")
    assert resp.status_code == 401

    print("\n" + "=" * 80)
    print("✅ LIVE TEST COMPLETE: All real-data checks passed against the running server.")
    print("=" * 80)


if __name__ == "__main__":
    main()
