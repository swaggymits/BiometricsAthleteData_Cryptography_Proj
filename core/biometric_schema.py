"""
Biometric Data Schema Definition
Week 1 (Addendum): Strict Data Contract for Athlete Telemetry Payloads

This module enforces the exact data schema mandated by the project instructor,
ensuring that every payload passed into `SecureGateway.encrypt_data()` is
structurally and semantically valid BEFORE encryption. This prevents malformed
or malicious data from ever entering the cryptographic pipeline, and guarantees
that decrypted payloads on the receiving end (Cloud Server) can be trusted to
match a known, predictable structure.

--------------------------------------------------------------------------
Official Data Schema (as specified by course instructor):
--------------------------------------------------------------------------
Data Type     | Field Name      | Description                              | Frequency     | Expected Size
------------- | ---------------- | ----------------------------------------- | ------------- | --------------
Integer       | heart_rate       | Heart rate (BPM)                          | 1 / sec       | 2 Bytes
Float         | fatigue_index    | Muscular fatigue index (%)                | 1 / 30 secs   | 4 Bytes
Float         | glucose_level    | Blood glucose level (mg/dL)               | 1 / 5 mins    | 4 Bytes
JSON Object   | gps_telemetry    | Coordinates & Speed (Lat, Long, Speed)     | 1 / sec       | ~32 Bytes
Float         | injury_risk      | Injury probability (0.0 - 1.0)            | Real-time     | 4 Bytes
"""

from __future__ import annotations

from typing import TypedDict


class GPSTelemetry(TypedDict):
    """Structured GPS payload nested inside the biometric schema."""
    lat: float
    lon: float
    speed_kmh: float


class BiometricPayload(TypedDict):
    """
    Strict TypedDict contract representing a single athlete biometric reading,
    matching the official Data Schema table exactly (field names, types).
    """
    heart_rate: int
    fatigue_index: float
    glucose_level: float
    gps_telemetry: GPSTelemetry
    injury_risk: float


# Valid numeric bounds derived from the schema's real-world constraints.
_HEART_RATE_MIN, _HEART_RATE_MAX = 0, 65535  # Fits within 2 bytes (unsigned short)
_INJURY_RISK_MIN, _INJURY_RISK_MAX = 0.0, 1.0


def validate_biometric_payload(payload: dict) -> BiometricPayload:
    """
    Validate a raw dictionary against the strict biometric Data Schema.

    Enforces field presence, correct Python types, and realistic value ranges
    for each field as defined by the instructor's schema table. This acts as
    a "shape gate" prior to encryption: any malformed telemetry (e.g., wrong
    type, missing field, out-of-range value) is rejected immediately rather
    than being silently encrypted and transmitted.

    Args:
        payload (dict): Raw candidate biometric data.

    Returns:
        BiometricPayload: The same data, confirmed schema-compliant.

    Raises:
        TypeError: If payload is not a dict, or a field has the wrong type.
        ValueError: If a required field is missing or a value is out of range.
    """
    if not isinstance(payload, dict):
        raise TypeError("payload must be a dictionary conforming to BiometricPayload.")

    required_fields = (
        "heart_rate",
        "fatigue_index",
        "glucose_level",
        "gps_telemetry",
        "injury_risk",
    )
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise ValueError(f"Missing required schema field(s): {', '.join(missing)}")

    # --- heart_rate: Integer, 2 Bytes (BPM) ---
    heart_rate = payload["heart_rate"]
    if not isinstance(heart_rate, int) or isinstance(heart_rate, bool):
        raise TypeError("heart_rate must be an Integer (BPM).")
    if not (_HEART_RATE_MIN <= heart_rate <= _HEART_RATE_MAX):
        raise ValueError(f"heart_rate must be within [{_HEART_RATE_MIN}, {_HEART_RATE_MAX}].")

    # --- fatigue_index: Float, 4 Bytes (%) ---
    fatigue_index = payload["fatigue_index"]
    if not isinstance(fatigue_index, (int, float)) or isinstance(fatigue_index, bool):
        raise TypeError("fatigue_index must be a Float (%).")
    if not (0.0 <= float(fatigue_index) <= 100.0):
        raise ValueError("fatigue_index must be a percentage within [0.0, 100.0].")

    # --- glucose_level: Float, 4 Bytes (mg/dL) ---
    glucose_level = payload["glucose_level"]
    if not isinstance(glucose_level, (int, float)) or isinstance(glucose_level, bool):
        raise TypeError("glucose_level must be a Float (mg/dL).")
    if float(glucose_level) < 0.0:
        raise ValueError("glucose_level must be a non-negative value (mg/dL).")

    # --- gps_telemetry: JSON Object (Lat, Long, Speed), ~32 Bytes ---
    gps_telemetry = payload["gps_telemetry"]
    if not isinstance(gps_telemetry, dict):
        raise TypeError("gps_telemetry must be a JSON Object with lat, lon, speed_kmh.")
    gps_required = ("lat", "lon", "speed_kmh")
    gps_missing = [field for field in gps_required if field not in gps_telemetry]
    if gps_missing:
        raise ValueError(f"gps_telemetry missing field(s): {', '.join(gps_missing)}")
    for gps_field in gps_required:
        value = gps_telemetry[gps_field]
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise TypeError(f"gps_telemetry.{gps_field} must be numeric (Float).")
    if not (-90.0 <= float(gps_telemetry["lat"]) <= 90.0):
        raise ValueError("gps_telemetry.lat must be within [-90.0, 90.0].")
    if not (-180.0 <= float(gps_telemetry["lon"]) <= 180.0):
        raise ValueError("gps_telemetry.lon must be within [-180.0, 180.0].")
    if float(gps_telemetry["speed_kmh"]) < 0.0:
        raise ValueError("gps_telemetry.speed_kmh must be non-negative.")

    # --- injury_risk: Float, 4 Bytes, Real-time (0.0 - 1.0) ---
    injury_risk = payload["injury_risk"]
    if not isinstance(injury_risk, (int, float)) or isinstance(injury_risk, bool):
        raise TypeError("injury_risk must be a Float.")
    if not (_INJURY_RISK_MIN <= float(injury_risk) <= _INJURY_RISK_MAX):
        raise ValueError(
            f"injury_risk must be within [{_INJURY_RISK_MIN}, {_INJURY_RISK_MAX}]."
        )

    return payload  # type: ignore[return-value]
