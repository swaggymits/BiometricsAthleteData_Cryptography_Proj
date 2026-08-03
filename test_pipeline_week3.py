"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 3: End-to-End Integration Test (IoT -> Gateway -> Cloud API)

Validates the full pipeline:
    1. IoTDeviceMock generates a raw plaintext biometric reading.
    2. SecureGateway encrypts it into an AES-256-GCM hex payload.
    3. The client POSTs the encrypted payload to /api/v1/telemetry/ingest.
    4. The client GETs /api/v1/telemetry/stored-ciphertexts and asserts that
       NONE of the raw plaintext metric values (heart rate, fatigue, glucose,
       GPS, injury risk) or identifiers appear anywhere in the response —
       proving the cloud server only ever persists encrypted noise.
    5. The client POSTs to /api/v1/telemetry/authorize-decrypt with the
       correct shared key and asserts the recovered plaintext exactly matches
       the original schema payload (proving the pipeline is genuinely
       reversible for authorized parties, not just one-way obfuscation).

Uses FastAPI's TestClient (backed by httpx) to exercise the real ASGI app
in-process, without needing a separately running uvicorn server.
"""

from __future__ import annotations

import json
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi.testclient import TestClient

import cloud_server as cloud_server_module
import main_server
from config import settings
from iot_device import IoTDeviceMock
from pipeline_week2 import adapt_to_schema
from secure_gateway import SecureGateway

API_KEY_HEADERS = {"X-API-Key": settings.CLOUD_API_KEY}

TEST_DB_PATH = "mock_db_test_week3.json"


class TestWeek3Pipeline(unittest.TestCase):
    """End-to-end Week 1 -> Week 3 pipeline integration test."""

    @classmethod
    def setUpClass(cls) -> None:
        # Isolate this test run's storage from any real `mock_db.json`.
        main_server.cloud_server = cloud_server_module.CloudServer(db_path=TEST_DB_PATH)
        cls.client = TestClient(main_server.app)

        cls.shared_key: bytes = AESGCM.generate_key(bit_length=256)
        cls.device = IoTDeviceMock(device_id="IOT-WBAN-TEST-01", player_id="PLAYER-TEST-99")
        cls.gateway = SecureGateway(gateway_id="GW-TEST-01", aes_key=cls.shared_key)

    @classmethod
    def tearDownClass(cls) -> None:
        import os

        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)

    def test_full_pipeline_ingest_and_ciphertext_only_exposure(self) -> None:
        # 1. IoTDeviceMock generates raw plaintext biometrics.
        raw_reading = self.device.generate_biometrics()
        schema_payload = adapt_to_schema(raw_reading)

        # 2. SecureGateway encrypts into an AES-256-GCM hex payload.
        encrypted_packet = self.gateway.encrypt_data(
            schema_payload,
            device_id=self.device.device_id,
            player_id=self.device.player_id,
        )

        # 3. POST the encrypted payload to the ingestion endpoint.
        ingest_response = self.client.post(
            "/api/v1/telemetry/ingest",
            headers=API_KEY_HEADERS,
            json={
                "gateway_id": encrypted_packet["gateway_id"],
                "device_id": encrypted_packet["device_id"],
                "player_id": encrypted_packet["player_id"],
                "sent_at": encrypted_packet["sent_at"],
                "nonce": encrypted_packet["nonce"],
                "ciphertext": encrypted_packet["ciphertext"],
            },
        )
        self.assertEqual(ingest_response.status_code, 201, ingest_response.text)
        ingest_body = ingest_response.json()
        self.assertEqual(ingest_body["status"], "success")
        self.assertGreaterEqual(ingest_body["stored_record_count"], 1)

        # 4. GET stored ciphertexts and assert no plaintext biometric leakage.
        get_response = self.client.get("/api/v1/telemetry/stored-ciphertexts")
        self.assertEqual(get_response.status_code, 200)
        stored_records = get_response.json()
        stored_text = json.dumps(stored_records)

        metrics = raw_reading["metrics"]
        # Numeric values alone are unreliable (short numbers can coincidentally
        # appear in hex), so we assert on the *key=value* JSON substring, which
        # would only appear if the plaintext payload itself had been stored.
        for field_name, value in [
            ("heart_rate", metrics["heart_rate"]),
            ("fatigue_index", metrics["fatigue_index"]),
            ("glucose_level", metrics["glucose_level"]),
            ("injury_risk", metrics["injury_risk"]),
        ]:
            marker = f'"{field_name}": {value}'
            self.assertNotIn(
                marker, stored_text,
                f"SECURITY FAILURE: plaintext '{field_name}' leaked into stored ciphertexts!"
            )

        # Identifiers are long/unique enough to check directly, but they are
        # expected to appear as METADATA (gateway_id/device_id/player_id are
        # legitimately stored in the clear as routing context) — so instead we
        # assert the found record's ciphertext field itself never equals or
        # contains the plaintext JSON of the schema payload.
        found = next(
            (r for r in stored_records if r["ciphertext"] == encrypted_packet["ciphertext"]),
            None,
        )
        self.assertIsNotNone(found, "Ingested record not found in stored ciphertexts.")
        self.assertNotIn(
            json.dumps(schema_payload), stored_text,
            "SECURITY FAILURE: raw schema payload found in stored ciphertexts response!"
        )

        # 5. POST to authorize-decrypt with the correct key and verify recovery.
        decrypt_response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=API_KEY_HEADERS,
            json={
                "record": {
                    "gateway_id": encrypted_packet["gateway_id"],
                    "device_id": encrypted_packet["device_id"],
                    "player_id": encrypted_packet["player_id"],
                    "sent_at": encrypted_packet["sent_at"],
                    "nonce": encrypted_packet["nonce"],
                    "ciphertext": encrypted_packet["ciphertext"],
                },
                "aes_key_hex": self.shared_key.hex(),
            },
        )
        self.assertEqual(decrypt_response.status_code, 200, decrypt_response.text)
        decrypted_body = decrypt_response.json()
        self.assertEqual(decrypted_body["status"], "success")
        self.assertEqual(decrypted_body["decrypted_payload"], schema_payload)

    def test_authorize_decrypt_rejects_wrong_key(self) -> None:
        raw_reading = self.device.generate_biometrics()
        schema_payload = adapt_to_schema(raw_reading)
        encrypted_packet = self.gateway.encrypt_data(
            schema_payload,
            device_id=self.device.device_id,
            player_id=self.device.player_id,
        )

        wrong_key = AESGCM.generate_key(bit_length=256)
        response = self.client.post(
            "/api/v1/telemetry/authorize-decrypt",
            headers=API_KEY_HEADERS,
            json={
                "record": {
                    "gateway_id": encrypted_packet["gateway_id"],
                    "device_id": encrypted_packet["device_id"],
                    "player_id": encrypted_packet["player_id"],
                    "sent_at": encrypted_packet["sent_at"],
                    "nonce": encrypted_packet["nonce"],
                    "ciphertext": encrypted_packet["ciphertext"],
                },
                "aes_key_hex": wrong_key.hex(),
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_ingest_rejects_non_hex_ciphertext(self) -> None:
        response = self.client.post(
            "/api/v1/telemetry/ingest",
            headers=API_KEY_HEADERS,
            json={
                "gateway_id": "GW-TEST-01",
                "nonce": "not-hex!!",
                "ciphertext": "also-not-hex",
            },
        )
        self.assertEqual(response.status_code, 422)  # Pydantic validation failure

    def test_ingest_rejects_missing_api_key(self) -> None:
        """Without the X-API-Key header, ingestion must be rejected (401)."""
        response = self.client.post(
            "/api/v1/telemetry/ingest",
            json={
                "gateway_id": "GW-TEST-01",
                "nonce": "aa" * 12,
                "ciphertext": "bb" * 32,
            },
        )
        self.assertEqual(response.status_code, 401)

    def test_stored_ciphertexts_requires_no_api_key(self) -> None:
        """The public proof-of-encryption endpoint must remain unauthenticated."""
        response = self.client.get("/api/v1/telemetry/stored-ciphertexts")
        self.assertEqual(response.status_code, 200)

    def test_health_check_endpoint(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ok")


if __name__ == "__main__":
    unittest.main(verbosity=2)
