"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 2: IoT Device -> Secure Gateway Transmission Pipeline

This script simulates the full edge-layer data flow for a single athlete:

    [Wearable Sensor (IoTDeviceMock)] --BLE--> [Edge Gateway (SecureGateway)] --Network-->

It demonstrates why encryption MUST happen immediately at the edge, before any
network hop: raw biometric telemetry (heart rate, fatigue, GPS, injury risk)
reveals tactical performance information that rival teams or eavesdroppers
could exploit if intercepted in plaintext (e.g., detecting player exhaustion
or injury risk in real time during a live match).

Pipeline Steps (per tick):
1. IoTDeviceMock.generate_biometrics() captures a raw plaintext reading.
2. The raw reading is adapted to the strict `BiometricPayload` Data Schema
   (flattened metrics + unit conversion) expected by `SecureGateway`.
3. SecureGateway.encrypt_data() immediately encrypts the adapted payload
   using AES-256-GCM (unique nonce per tick).
4. The plaintext and ciphertext are compared to prove no sensitive metric
   values are recoverable from the encrypted packet in plain text.
"""

from __future__ import annotations

import time
from typing import Any, Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from edge.iot_device import IoTDeviceMock
from core.secure_gateway import SecureGateway


def adapt_to_schema(raw_reading: Dict[str, Any]) -> Dict[str, Any]:
    """
    Adapt a raw IoTDeviceMock reading into the strict biometric Data Schema
    required by `SecureGateway.encrypt_data()` / `validate_biometric_payload()`.

    The wearable device nests metrics under "metrics" and reports GPS speed in
    m/s (latitude/longitude/speed_m_s). The gateway's schema expects a flat
    structure with speed in km/h (lat/lon/speed_kmh). Device/player metadata
    and the capture timestamp are preserved as additional (non-schema) fields
    so they survive encryption alongside the mandatory metrics.

    Args:
        raw_reading (Dict[str, Any]): Output of `IoTDeviceMock.generate_biometrics()`.

    Returns:
        Dict[str, Any]: Schema-compliant payload ready for `SecureGateway.encrypt_data()`.
    """
    metrics = raw_reading["metrics"]
    gps = metrics["gps_telemetry"]

    return {
        # Metadata (not part of the strict schema, but preserved for traceability)
        "device_id": raw_reading["device_id"],
        "player_id": raw_reading["player_id"],
        "timestamp": raw_reading["timestamp"],
        # Mandatory schema fields
        "heart_rate": metrics["heart_rate"],
        "fatigue_index": metrics["fatigue_index"],
        "glucose_level": metrics["glucose_level"],
        "gps_telemetry": {
            "lat": gps["latitude"],
            "lon": gps["longitude"],
            "speed_kmh": round(gps["speed_m_s"] * 3.6, 2),  # m/s -> km/h
        },
        "injury_risk": metrics["injury_risk"],
    }


def assert_no_plaintext_leak(schema_payload: Dict[str, Any], ciphertext_hex: str) -> None:
    """
    Verify that none of the sensitive metric values appear as recognizable
    plaintext byte sequences inside the ciphertext, proving AES-256-GCM
    successfully obfuscates the biometric telemetry (mitigating tactical
    performance espionage).

    Note: The check is performed against the RAW CIPHERTEXT BYTES (not the
    hex-encoded string). Searching for short numeric substrings within a hex
    STRING is unreliable, since short digit sequences (e.g., "154") can occur
    purely by chance within any sufficiently long hex string. Searching for
    the UTF-8 encoded byte pattern within the actual ciphertext bytes is the
    statistically meaningful test for genuine plaintext leakage.

    Args:
        schema_payload (Dict[str, Any]): The plaintext payload prior to encryption.
        ciphertext_hex (str): Hex-encoded ciphertext from the encrypted packet.

    Raises:
        AssertionError: If any sensitive value leaks into the ciphertext bytes.
    """
    ciphertext_bytes = bytes.fromhex(ciphertext_hex)

    # Only check identifiers/strings long enough to make random byte-collision
    # statistically negligible (e.g., device_id, player_id). Short numeric
    # metrics (e.g., "154") are excluded from byte-level checks since 2-3
    # character sequences have a non-negligible chance of appearing in any
    # sufficiently long random byte stream, making them unreliable indicators.
    sensitive_identifiers = [
        schema_payload["player_id"],
        schema_payload["device_id"],
        schema_payload["timestamp"],
    ]
    for value in sensitive_identifiers:
        encoded_value = value.encode("utf-8")
        assert encoded_value not in ciphertext_bytes, (
            f"SECURITY FAILURE: identifier '{value}' leaked into ciphertext!"
        )

    # For numeric metrics, verify the exact JSON key=value substring (e.g.,
    # '"heart_rate": 154') does NOT appear as UTF-8 bytes — this is a far
    # stronger and more meaningful check than a bare number by itself.
    numeric_checks = {
        "heart_rate": schema_payload["heart_rate"],
        "fatigue_index": schema_payload["fatigue_index"],
        "glucose_level": schema_payload["glucose_level"],
        "injury_risk": schema_payload["injury_risk"],
    }
    for field_name, field_value in numeric_checks.items():
        marker = f'"{field_name}": {field_value}'.encode()
        assert marker not in ciphertext_bytes, (
            f"SECURITY FAILURE: '{field_name}' value leaked into ciphertext!"
        )


def run_pipeline(ticks: int = 5, delay_seconds: float = 1.0) -> None:
    """
    Run a continuous tick-by-tick simulation of edge biometric capture and
    immediate AES-256-GCM encryption, printing each stage for demonstration.

    A second, independent `SecureGateway` instance (constructed with the SAME
    pre-shared key) plays the role of the receiving Cloud Server, proving the
    ciphertext is genuinely decryptable end-to-end and not merely a self-test.

    Args:
        ticks (int): Number of consecutive biometric samples to generate.
        delay_seconds (float): Delay between simulated sensor ticks (seconds).
    """
    device = IoTDeviceMock(device_id="IOT-WBAN-001", player_id="PLAYER-77")

    # Both ends share the same 256-bit key out-of-band (e.g., provisioned during
    # device enrollment), exactly like a real edge-gateway <-> cloud-server pair.
    shared_key = AESGCM.generate_key(bit_length=256)
    edge_gateway = SecureGateway(gateway_id="GW-EDGE-01", aes_key=shared_key)
    cloud_server = SecureGateway(gateway_id="GW-EDGE-01", aes_key=shared_key)

    print("=" * 80)
    print(f"Starting Edge Transmission Pipeline | Device: {device.device_id} | "
          f"Athlete: {device.player_id}")
    print("=" * 80)

    for tick in range(1, ticks + 1):
        print(f"\n--- Tick {tick}/{ticks} ---")

        # 1. Capture raw plaintext biometric reading from the wearable sensor.
        raw_reading = device.generate_biometrics()
        print("[BLE OUTPUT | RAW PLAINTEXT] :", raw_reading)

        # 2. Adapt raw reading to the strict schema expected by SecureGateway.
        schema_payload = adapt_to_schema(raw_reading)

        # 3. Encrypt immediately at the edge (AES-256-GCM), binding device/player
        #    identity into the authenticated (AAD) context.
        encrypted_packet = edge_gateway.encrypt_data(
            schema_payload,
            device_id=device.device_id,
            player_id=device.player_id,
        )
        print("[ENCRYPTED PACKET | READY FOR CLOUD TRANSMISSION]")
        print(f"    gateway_id : {encrypted_packet['gateway_id']}")
        print(f"    device_id  : {encrypted_packet['device_id']}")
        print(f"    player_id  : {encrypted_packet['player_id']}")
        print(f"    sent_at    : {encrypted_packet['sent_at']}")
        print(f"    nonce      : {encrypted_packet['nonce']}")
        print(f"    ciphertext : {encrypted_packet['ciphertext']}")

        # 4. Verify no sensitive metric is recoverable from the ciphertext.
        assert_no_plaintext_leak(schema_payload, encrypted_packet["ciphertext"])
        print("[VERIFIED] No plaintext biometric values leaked into ciphertext. "
              "Tactical espionage risk mitigated.")

        # 5. Simulate the network hop: the Cloud Server receives the packet and
        #    decrypts it, proving the full edge-to-cloud flow actually works
        #    (not just a self-encrypt/self-verify demo).
        decrypted_payload = cloud_server.decrypt_data(encrypted_packet, max_age_seconds=60.0)
        assert decrypted_payload == schema_payload, (
            "SECURITY FAILURE: decrypted payload does not match original plaintext!"
        )
        print("[CLOUD SERVER] Decrypted & authenticated packet successfully; "
              "payload matches original telemetry exactly.")

        if tick < ticks:
            time.sleep(delay_seconds)

    print("\n" + "=" * 80)
    print(f"Pipeline completed: {ticks} biometric readings captured, encrypted, "
          f"transmitted, and verified end-to-end.")
    print("=" * 80)


if __name__ == "__main__":
    run_pipeline(ticks=5, delay_seconds=1.0)
