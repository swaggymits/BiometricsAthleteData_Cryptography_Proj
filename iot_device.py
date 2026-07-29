"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 2: IoT Device Mocking (Edge Wearable / WBAN Sensor Simulation)

This module simulates a Wireless Body Area Network (WBAN) wearable sensor
attached to an athlete (e.g., GPS vest, chest-strap heart rate monitor,
continuous glucose monitor). In a real deployment, this hardware would
stream raw telemetry over Bluetooth Low Energy (BLE) to an edge gateway
device before any encryption is applied.

Security Context:
------------------
The data produced here is intentionally UNENCRYPTED plaintext, mirroring
the real-world vulnerability window between sensor capture and gateway
encryption. This is the exact "espionage attack surface" that Week 1's
`SecureGateway` (AES-256-GCM) is designed to close: raw biometric output
must never leave the edge device boundary in plaintext form once it is
handed to the gateway for transmission.
"""

from __future__ import annotations
import random
from datetime import datetime, timezone
from typing import Dict, Any


class IoTDeviceMock:
    """
    Simulated IoT wearable biometric sensor (edge device) attached to an athlete.

    Represents a single physical hardware unit (WBAN sensor node) responsible for
    capturing raw physiological and positional telemetry at the edge, prior to
    any cryptographic processing by the `SecureGateway`.

    Attributes:
        device_id (str): Unique hardware identifier of the wearable device
                          (e.g., "IOT-WBAN-001").
        player_id (str): Unique identifier of the athlete wearing the device
                          (e.g., "PLAYER-77").
    """

    def __init__(self, device_id: str, player_id: str) -> None:
        """
        Initialize the IoT device mock.

        Args:
            device_id (str): Unique hardware identifier for this sensor unit.
            player_id (str): Unique identifier of the athlete being monitored.

        Raises:
            ValueError: If either device_id or player_id is empty or not a string.
        """
        if not device_id or not isinstance(device_id, str):
            raise ValueError("device_id must be a non-empty string.")
        if not player_id or not isinstance(player_id, str):
            raise ValueError("player_id must be a non-empty string.")

        self.device_id: str = device_id
        self.player_id: str = player_id

    def generate_biometrics(self) -> Dict[str, Any]:
        """
        Generate a single simulated raw biometric telemetry reading ("tick").

        Mimics one sampling cycle of a wearable sensor bundle, producing
        randomized but realistic physiological and GPS values. This raw
        payload is plaintext and MUST be handed to `SecureGateway.encrypt_data()`
        immediately upon generation to minimize the plaintext exposure window
        (mitigating tactical performance espionage).

        Returns:
            Dict[str, Any]: A dictionary strictly following the schema:
                {
                    "device_id": str,
                    "player_id": str,
                    "timestamp": str (ISO 8601 UTC),
                    "metrics": {
                        "heart_rate": int (60-185 BPM),
                        "fatigue_index": float (10.0-95.0 %, 2 decimals),
                        "glucose_level": int (70-140 mg/dL),
                        "gps_telemetry": {
                            "latitude": float,
                            "longitude": float,
                            "speed_m_s": float
                        },
                        "injury_risk": float (0.01-0.99)
                    }
                }
        """
        timestamp: str = datetime.now(timezone.utc).isoformat()

        heart_rate: int = random.randint(60, 185)
        fatigue_index: float = round(random.uniform(10.0, 95.0), 2)
        glucose_level: int = random.randint(70, 140)

        # Simulated GPS jitter around a fixed stadium/pitch reference point.
        latitude: float = round(random.uniform(-90.0, 90.0), 6)
        longitude: float = round(random.uniform(-180.0, 180.0), 6)
        speed_m_s: float = round(random.uniform(0.0, 9.5), 2)  # Elite sprint ~9.5 m/s

        injury_risk: float = round(random.uniform(0.01, 0.99), 2)

        return {
            "device_id": self.device_id,
            "player_id": self.player_id,
            "timestamp": timestamp,
            "metrics": {
                "heart_rate": heart_rate,
                "fatigue_index": fatigue_index,
                "glucose_level": glucose_level,
                "gps_telemetry": {
                    "latitude": latitude,
                    "longitude": longitude,
                    "speed_m_s": speed_m_s,
                },
                "injury_risk": injury_risk,
            },
        }
