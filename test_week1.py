"""
Unit and Integration Tests for Week 1: Core Encryption Module
"""

import unittest
from cryptography.exceptions import InvalidTag
from secure_gateway import SecureGateway
from biometric_schema import validate_biometric_payload


class TestBiometricSchemaValidation(unittest.TestCase):
    """
    Test suite for the strict instructor-mandated Data Schema validation,
    covering type/range enforcement for each field prior to encryption.
    """

    def setUp(self) -> None:
        self.valid_payload = {
            "heart_rate": 165,
            "fatigue_index": 82.5,
            "glucose_level": 95.3,
            "gps_telemetry": {"lat": 51.5074, "lon": -0.1278, "speed_kmh": 31.4},
            "injury_risk": 0.42,
        }

    def test_valid_payload_passes(self) -> None:
        """A fully schema-compliant payload must validate without error."""
        result = validate_biometric_payload(self.valid_payload)
        self.assertEqual(result, self.valid_payload)

    def test_missing_field_raises_value_error(self) -> None:
        """Removing a required field must raise ValueError."""
        payload = dict(self.valid_payload)
        del payload["glucose_level"]
        with self.assertRaises(ValueError):
            validate_biometric_payload(payload)

    def test_wrong_type_heart_rate_raises_type_error(self) -> None:
        """heart_rate must be an Integer, not a Float/str."""
        payload = dict(self.valid_payload)
        payload["heart_rate"] = 165.5
        with self.assertRaises(TypeError):
            validate_biometric_payload(payload)

    def test_injury_risk_out_of_range_raises_value_error(self) -> None:
        """injury_risk must remain within [0.0, 1.0]."""
        payload = dict(self.valid_payload)
        payload["injury_risk"] = 1.5
        with self.assertRaises(ValueError):
            validate_biometric_payload(payload)

    def test_gps_telemetry_missing_subfield_raises_value_error(self) -> None:
        """gps_telemetry must contain lat, lon, and speed_kmh."""
        payload = dict(self.valid_payload)
        payload["gps_telemetry"] = {"lat": 51.5074, "lon": -0.1278}
        with self.assertRaises(ValueError):
            validate_biometric_payload(payload)

    def test_non_dict_payload_raises_type_error(self) -> None:
        """Passing a non-dict payload must raise TypeError."""
        with self.assertRaises(TypeError):
            validate_biometric_payload("not a dict")  # type: ignore[arg-type]


class TestWeek1SecureGateway(unittest.TestCase):
    """
    Test suite for validating the SecureGateway encryption module.
    """

    def setUp(self) -> None:
        """Set up test environment with a fresh gateway instance."""
        self.gateway_id = "GW-EDGE-01"
        self.gateway = SecureGateway(self.gateway_id)
        # Schema-compliant payload per the instructor's official Data Schema:
        # heart_rate (Integer), fatigue_index (Float, %), glucose_level (Float, mg/dL),
        # gps_telemetry (JSON Object: lat, lon, speed_kmh), injury_risk (Float, 0.0-1.0)
        self.sample_biometric_data = {
            "heart_rate": 165,
            "fatigue_index": 82.5,
            "glucose_level": 95.3,
            "gps_telemetry": {"lat": 51.5074, "lon": -0.1278, "speed_kmh": 31.4},
            "injury_risk": 0.42,
        }

    def test_gateway_initialization(self) -> None:
        """Verify gateway initialization, ID assignment, and 256-bit AES key generation."""
        self.assertEqual(self.gateway.gateway_id, self.gateway_id)
        self.assertIsInstance(self.gateway.aes_key, bytes)
        # AES-256 key must be exactly 32 bytes (256 bits)
        self.assertEqual(len(self.gateway.aes_key), 32)

    def test_encryption_and_decryption_dictionary(self) -> None:
        """
        Verify dictionary payload encryption:
        1. Encrypted packet has expected keys (gateway_id, nonce, ciphertext).
        2. Ciphertext is not plain text and contains no raw strings.
        3. Decrypted output strictly matches the original input dictionary.
        """
        packet = self.gateway.encrypt_data(
            self.sample_biometric_data, device_id="IOT-001", player_id="PLAYER-1"
        )

        # Check packet structure
        self.assertEqual(packet["gateway_id"], self.gateway_id)
        self.assertIn("nonce", packet)
        self.assertIn("ciphertext", packet)
        self.assertIn("sent_at", packet)

        # Verify hex encoding format
        nonce_bytes = bytes.fromhex(packet["nonce"])
        ciphertext_bytes = bytes.fromhex(packet["ciphertext"])
        self.assertEqual(len(nonce_bytes), 12)  # 96-bit nonce standard for GCM

        # Assert ciphertext is not readable plain text
        self.assertNotIn("165", packet["ciphertext"])
        self.assertNotIn("heart_rate", packet["ciphertext"])
        self.assertNotIn("82.5", packet["ciphertext"])

        # Decrypt payload
        decrypted_data = self.gateway.decrypt_data(packet)

        # Verify strict match with original biometric dictionary
        self.assertIsInstance(decrypted_data, dict)
        self.assertEqual(decrypted_data, self.sample_biometric_data)

    def test_encryption_and_decryption_string(self) -> None:
        """Verify string payload encryption and decryption."""
        raw_string = "ALERT: Player P-10 fatigue threshold exceeded (88.0%)"
        packet = self.gateway.encrypt_data(raw_string)

        self.assertNotIn("P-10", packet["ciphertext"])
        decrypted_data = self.gateway.decrypt_data(packet)
        self.assertEqual(decrypted_data, raw_string)

    def test_encrypt_data_rejects_non_schema_compliant_dict(self) -> None:
        """
        Verify that encrypt_data() enforces the strict Data Schema and refuses
        to encrypt a malformed dictionary payload (e.g., missing/invalid fields).
        """
        malformed_payload = {
            "heart_rate": "not-an-integer",
            "fatigue_index": 82.5,
            "glucose_level": 95.3,
            "gps_telemetry": {"lat": 51.5074, "lon": -0.1278, "speed_kmh": 31.4},
            "injury_risk": 0.42,
        }
        with self.assertRaises(TypeError):
            self.gateway.encrypt_data(malformed_payload)

    def test_nonce_uniqueness_and_semantic_security(self) -> None:
        """
        Verify that encrypting identical data twice generates distinct nonces
        and distinct ciphertexts (semantic security / replay protection).
        """
        packet1 = self.gateway.encrypt_data(self.sample_biometric_data)
        packet2 = self.gateway.encrypt_data(self.sample_biometric_data)

        self.assertNotEqual(packet1["nonce"], packet2["nonce"])
        self.assertNotEqual(packet1["ciphertext"], packet2["ciphertext"])

    def test_tamper_resistance_and_integrity_check(self) -> None:
        """
        Verify that tampering with either the ciphertext or the nonce
        causes AES-GCM tag verification failure (raises InvalidTag).
        """
        packet = self.gateway.encrypt_data(
            self.sample_biometric_data, device_id="IOT-001", player_id="PLAYER-1"
        )

        # Tamper with the ciphertext (flip hex characters)
        ciphertext_hex = packet["ciphertext"]
        tampered_char = "0" if ciphertext_hex[0] != "0" else "1"
        tampered_ciphertext = tampered_char + ciphertext_hex[1:]
        tampered_packet = dict(packet)
        tampered_packet["ciphertext"] = tampered_ciphertext

        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data(tampered_packet)

        # Tamper with the nonce
        nonce_hex = packet["nonce"]
        tampered_nonce_char = "0" if nonce_hex[0] != "0" else "1"
        tampered_nonce_packet = dict(packet)
        tampered_nonce_packet["nonce"] = tampered_nonce_char + nonce_hex[1:]

        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data(tampered_nonce_packet)

    def test_context_binding_rejects_reattributed_packet(self) -> None:
        """
        Verify that AAD context binding prevents "cut-and-paste" attacks: a
        genuine ciphertext re-attributed to a different device_id/player_id
        must fail authentication (InvalidTag), even though the ciphertext
        and nonce bytes themselves are untouched.
        """
        packet = self.gateway.encrypt_data(
            self.sample_biometric_data, device_id="IOT-001", player_id="PLAYER-1"
        )

        spoofed_packet = dict(packet)
        spoofed_packet["player_id"] = "PLAYER-99"  # relabel to a different athlete

        with self.assertRaises(InvalidTag):
            self.gateway.decrypt_data(spoofed_packet)

    def test_shared_key_interoperability_between_gateways(self) -> None:
        """
        Verify that two independent SecureGateway instances constructed with
        the SAME pre-shared key can genuinely interoperate: one encrypts
        (edge) and the other decrypts (cloud), proving real edge-to-cloud
        transmission is possible (not merely self-encrypt/self-decrypt).
        """
        shared_key = self.gateway.aes_key
        sender = SecureGateway("GW-EDGE-01", aes_key=shared_key)
        receiver = SecureGateway("GW-EDGE-01", aes_key=shared_key)

        packet = sender.encrypt_data(
            self.sample_biometric_data, device_id="IOT-001", player_id="PLAYER-1"
        )
        decrypted = receiver.decrypt_data(packet)
        self.assertEqual(decrypted, self.sample_biometric_data)

    def test_rejects_invalid_shared_key_length(self) -> None:
        """Constructing a gateway with a key that isn't exactly 32 bytes must fail."""
        with self.assertRaises(ValueError):
            SecureGateway("GW-EDGE-01", aes_key=b"too-short-key")

    def test_replay_protection_rejects_stale_packet(self) -> None:
        """
        Verify that decrypt_data() rejects a packet older than max_age_seconds,
        mitigating delayed replay attacks.
        """
        packet = self.gateway.encrypt_data(self.sample_biometric_data)
        stale_packet = dict(packet)
        stale_packet["sent_at"] = "2000-01-01T00:00:00Z"  # far in the past

        with self.assertRaises(ValueError):
            self.gateway.decrypt_data(stale_packet, max_age_seconds=60.0)

        # A freshly encrypted packet must NOT be rejected under the same window.
        fresh_decrypted = self.gateway.decrypt_data(packet, max_age_seconds=60.0)
        self.assertEqual(fresh_decrypted, self.sample_biometric_data)


if __name__ == "__main__":
    unittest.main()
