"""
Zenodo Public Dataset Integration Adapter
==========================================

Dataset: "Synthetic Triathlete Dataset for Injury Prediction Research (2024)"
Source:  https://zenodo.org/records/15401061
DOI:     10.5281/zenodo.15401061
License: CC-BY 4.0 (Rossi, Leonardo — University of St.Gallen)

This adapter downloads ``athletes.csv`` directly from the Zenodo REST API
(no account or token required) and maps each athlete row to a
``BiometricPayload`` conforming to the official project schema defined in
``biometric_schema.py``.

Schema Mapping (Zenodo → BiometricPayload)
------------------------------------------
BiometricPayload field  | Zenodo column(s)          | Derivation
----------------------- | ------------------------- | ---------------------------------
heart_rate (int, BPM)   | resting_hr                | Floor to int, clamp 40–185 BPM
fatigue_index (float %) | hrv_baseline vs baseline  | 100 - normalized(hrv_baseline); higher HRV → lower fatigue
glucose_level (float)   | vo2max + resting_hr proxy | Estimated via exercise physiology formula
gps_telemetry (dict)    | N/A (no GPS in dataset)   | Synthetically jittered around a triathlon reference venue
injury_risk (float 0–1) | stress_factor             | Clamp to [0.0, 1.0] directly

Note on GPS: The Zenodo dataset captures physiological metrics only (no
GPS tracking). GPS coordinates are synthetically generated with realistic
jitter around the Kona Ironman World Championship reference point
(19.6400° N, 155.9969° W), clearly labelled as synthetic.
"""

from __future__ import annotations

import io
import random
from typing import Any, Dict, Generator, List, Optional, Tuple

import requests

# ---------------------------------------------------------------------------
# Dataset Constants
# ---------------------------------------------------------------------------

ZENODO_RECORD_ID: str = "15401061"
ZENODO_API_BASE: str = "https://zenodo.org/api/records"
ATHLETES_CSV_KEY: str = "athletes.csv"
DAILY_CSV_KEY: str = "daily_data.csv"
DATASET_DOI: str = "10.5281/zenodo.15401061"
DATASET_CITATION: str = (
    "Rossi, Leonardo. (2025). Synthetic Triathlete Dataset for Injury "
    "Prediction Research (2024). Zenodo. https://doi.org/10.5281/zenodo.15401061"
)

# Ironman Kona World Championship venue (Hawaii) — reference GPS anchor
_GPS_ANCHOR_LAT: float = 19.6400
_GPS_ANCHOR_LON: float = -155.9969
_GPS_JITTER_DEG: float = 0.05  # ±0.05° ≈ ±5.5 km spread around venue

# Physiological bounds matching biometric_schema.py constraints
_HR_MIN: int = 40
_HR_MAX: int = 185
_FATIGUE_MIN: float = 5.0
_FATIGUE_MAX: float = 95.0
_GLUCOSE_MIN: float = 70.0
_GLUCOSE_MAX: float = 180.0
_INJURY_RISK_MIN: float = 0.01
_INJURY_RISK_MAX: float = 0.99


# ---------------------------------------------------------------------------
# Helper: VO₂max → estimated blood glucose (mg/dL)
# ---------------------------------------------------------------------------


def _estimate_glucose_from_vo2max(vo2max: float, resting_hr: float) -> float:
    """
    Estimate resting blood glucose (mg/dL) from aerobic capacity proxies.

    Physiological basis:
    - Highly aerobic athletes (high VO₂max) tend toward euglycaemia (~85 mg/dL)
    - Lower aerobic fitness correlates with higher baseline glucose (~110–130)
    - Resting HR modulates: lower resting HR → better insulin sensitivity

    This is a heuristic for demonstration purposes only.
    """
    # Normalise VO₂max to [0,1] over a realistic elite range [35–85 ml/kg/min]
    vo2_norm = min(max((float(vo2max) - 35.0) / 50.0, 0.0), 1.0)
    # HR factor: lower resting HR → more insulin-sensitive → lower glucose
    hr_factor = min(max((float(resting_hr) - 35.0) / 60.0, 0.0), 1.0)
    # Base glucose inversely proportional to aerobic fitness
    glucose = 130.0 - (vo2_norm * 45.0) - (1.0 - hr_factor) * 5.0
    # Apply light noise ±5 mg/dL for realism
    glucose += random.uniform(-5.0, 5.0)
    return round(min(max(glucose, _GLUCOSE_MIN), _GLUCOSE_MAX), 1)


# ---------------------------------------------------------------------------
# Helper: HRV baseline → fatigue index (%)
# ---------------------------------------------------------------------------


def _estimate_fatigue_from_hrv(
    hrv_baseline: float, hrv_range: Optional[Tuple[float, float]]
) -> float:
    """
    Derive a fatigue index percentage from heart-rate variability (HRV).

    High HRV → good autonomic recovery → low fatigue.
    Low HRV  → accumulated training stress → high fatigue.

    Args:
        hrv_baseline: Mean HRV (ms) from the dataset.
        hrv_range:    (min_hrv, max_hrv) tuple for this athlete, used for normalisation.

    Returns:
        float: Fatigue index in [5.0, 95.0] percent.
    """
    hrv = float(hrv_baseline)
    if hrv_range and len(hrv_range) == 2:
        lo, hi = float(hrv_range[0]), float(hrv_range[1])
        span = hi - lo if hi > lo else 50.0
        # HRV at top of range → 5% fatigue; at bottom → 95% fatigue
        normalised = (hi - hrv) / span  # high hrv → 0, low hrv → 1
    else:
        # Fallback: use absolute HRV range [20ms–160ms] typical in wearable literature
        normalised = (120.0 - min(max(hrv, 20.0), 120.0)) / 100.0

    fatigue = _FATIGUE_MIN + normalised * (_FATIGUE_MAX - _FATIGUE_MIN)
    # Small random variation to simulate intra-day fluctuation
    fatigue += random.uniform(-3.0, 3.0)
    return round(min(max(fatigue, _FATIGUE_MIN), _FATIGUE_MAX), 2)


# ---------------------------------------------------------------------------
# Helper: GPS jitter around anchor
# ---------------------------------------------------------------------------


def _generate_gps_telemetry(speed_kmh_hint: Optional[float] = None) -> Dict[str, float]:
    """
    Synthesise a GPS telemetry reading around the Kona Ironman reference.

    Args:
        speed_kmh_hint: Optional target speed (km/h). If None, random 0–35 km/h.

    Returns:
        dict with keys: lat, lon, speed_kmh  (matching BiometricPayload GPS schema)
    """
    lat = round(_GPS_ANCHOR_LAT + random.uniform(-_GPS_JITTER_DEG, _GPS_JITTER_DEG), 6)
    lon = round(_GPS_ANCHOR_LON + random.uniform(-_GPS_JITTER_DEG, _GPS_JITTER_DEG), 6)
    speed = speed_kmh_hint if speed_kmh_hint is not None else round(random.uniform(0.0, 35.0), 2)
    speed = round(min(max(float(speed), 0.0), 50.0), 2)
    return {"lat": lat, "lon": lon, "speed_kmh": speed}


# ---------------------------------------------------------------------------
# Main Loader Class
# ---------------------------------------------------------------------------


class ZenodoDatasetLoader:
    """
    Fetches and adapts the Zenodo Synthetic Triathlete Dataset for use with
    the BiometricsAthleteData cryptographic pipeline.

    Usage
    -----
    >>> loader = ZenodoDatasetLoader()
    >>> loader.fetch()                          # downloads athletes.csv
    >>> for payload, meta in loader.stream_payloads(limit=50):
    ...     encrypted = gateway.encrypt_data(payload, player_id=meta['athlete_id'])

    Attributes
    ----------
    record_id : str
        Zenodo record identifier.
    athletes_df : list[dict]
        Parsed athlete rows after ``fetch()`` is called.
    doi : str
        Dataset DOI for citation.
    citation : str
        Full dataset citation string (APA style).
    """

    def __init__(self) -> None:
        self.record_id: str = ZENODO_RECORD_ID
        self.doi: str = DATASET_DOI
        self.citation: str = DATASET_CITATION
        self.athletes_df: List[Dict[str, Any]] = []
        self._fetched: bool = False

    # ------------------------------------------------------------------
    # Step 1: Discover the file download URL via Zenodo REST API
    # ------------------------------------------------------------------

    def _resolve_file_url(self, csv_key: str) -> str:
        """
        Query the Zenodo record API to find the download URL for a given CSV.

        Returns:
            str: The direct content URL for the requested file.

        Raises:
            RuntimeError: If the record or file cannot be found.
        """
        api_url = f"{ZENODO_API_BASE}/{self.record_id}"
        resp = requests.get(api_url, timeout=30)
        resp.raise_for_status()
        record = resp.json()
        for file_entry in record.get("files", []):
            if file_entry.get("key") == csv_key:
                return file_entry["links"]["self"]
        raise RuntimeError(
            f"File '{csv_key}' not found in Zenodo record {self.record_id}. "
            f"Available files: {[f['key'] for f in record.get('files', [])]}"
        )

    # ------------------------------------------------------------------
    # Step 2: Download and parse athletes.csv
    # ------------------------------------------------------------------

    def fetch(self, verbose: bool = True) -> "ZenodoDatasetLoader":
        """
        Download ``athletes.csv`` from Zenodo and parse it into memory.

        Args:
            verbose: If True, print download progress to stdout.

        Returns:
            self (fluent interface)

        Raises:
            RuntimeError: If the download or parsing fails.
        """
        if verbose:
            print(f"\n{'='*60}")
            print("  Zenodo Dataset Loader")
            print(f"  Record : {self.record_id}")
            print(f"  DOI    : {self.doi}")
            print(f"  File   : {ATHLETES_CSV_KEY}")
            print(f"{'='*60}")
            print("  [1/3] Resolving download URL via Zenodo REST API...")

        file_url = self._resolve_file_url(ATHLETES_CSV_KEY)
        if verbose:
            print(f"  [2/3] Downloading {ATHLETES_CSV_KEY} ...")

        resp = requests.get(file_url, timeout=60)
        resp.raise_for_status()
        raw_csv = resp.text

        if verbose:
            kb = len(resp.content) / 1024
            print(f"        Downloaded {kb:.1f} KB")
            print("  [3/3] Parsing CSV rows...")

        self.athletes_df = self._parse_csv(raw_csv)
        self._fetched = True

        if verbose:
            print(f"        Parsed {len(self.athletes_df)} athlete records.")
            print(f"  {'='*58}")
            print(f"  Citation: {self.citation}")
            print(f"  {'='*58}\n")

        return self

    # ------------------------------------------------------------------
    # Internal: parse CSV text to list of dicts
    # ------------------------------------------------------------------

    def _parse_csv(self, csv_text: str) -> List[Dict[str, Any]]:
        """
        Parse the athletes CSV text into a list of row dicts.

        Handles the quirky numpy repr values (e.g., 'np.float64(82.9)')
        present in the hrv_range column without requiring numpy.
        """
        import csv
        import re

        rows: List[Dict[str, Any]] = []
        reader = csv.DictReader(io.StringIO(csv_text))
        for row in reader:
            cleaned: Dict[str, Any] = {}
            for k, v in row.items():
                k = k.strip()
                v = v.strip() if isinstance(v, str) else v
                # Strip numpy repr wrappers: np.float64(82.9) → 82.9
                v_clean = re.sub(r"np\.\w+\(([^)]+)\)", r"\1", v) if isinstance(v, str) else v
                cleaned[k] = v_clean
            rows.append(cleaned)
        return rows

    # ------------------------------------------------------------------
    # Step 3: Map each row → BiometricPayload
    # ------------------------------------------------------------------

    def _row_to_payload(self, row: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, str]]:
        """
        Convert a single Zenodo athlete row to a ``BiometricPayload`` dict
        plus metadata (athlete_id, device_id).

        Returns:
            (payload_dict, meta_dict)
        """

        def safe_float(val: Any, default: float = 0.0) -> float:
            try:
                return float(str(val).replace(",", "."))
            except (ValueError, TypeError):
                return default

        def safe_int(val: Any, default: int = 70) -> int:
            try:
                return int(float(str(val)))
            except (ValueError, TypeError):
                return default

        athlete_id: str = row.get("athlete_id", f"ZEN-{random.randint(1000,9999)}")
        device_id: str = f"IOT-ZEN-{athlete_id[:8].upper()}"

        # --- heart_rate ---
        resting_hr_raw = safe_float(row.get("resting_hr", "70"), 70.0)
        heart_rate: int = int(min(max(resting_hr_raw, _HR_MIN), _HR_MAX))

        # --- fatigue_index ---
        hrv_baseline = safe_float(row.get("hrv_baseline", "80"), 80.0)
        # Try to parse hrv_range tuple string "(lo, hi)"
        hrv_range_str = row.get("hrv_range", "")
        hrv_range_parsed: Optional[Tuple[float, float]] = None
        if hrv_range_str:
            import re

            nums = re.findall(r"[-+]?\d*\.?\d+", hrv_range_str)
            if len(nums) >= 2:
                hrv_range_parsed = (float(nums[0]), float(nums[1]))
        fatigue_index: float = _estimate_fatigue_from_hrv(hrv_baseline, hrv_range_parsed)

        # --- glucose_level ---
        vo2max = safe_float(row.get("vo2max", "55"), 55.0)
        glucose_level: float = _estimate_glucose_from_vo2max(vo2max, resting_hr_raw)

        # --- gps_telemetry ---
        # Estimate running speed from VO₂max using Cooper's equation approximation:
        # v (km/h) ≈ VO₂max × 0.21  (elite triathlete running pace)
        speed_hint = min(max(vo2max * 0.21, 5.0), 35.0)
        gps_telemetry: Dict[str, float] = _generate_gps_telemetry(speed_kmh_hint=speed_hint)

        # --- injury_risk ---
        stress_factor = safe_float(row.get("stress_factor", "0.3"), 0.3)
        injury_risk: float = round(min(max(stress_factor, _INJURY_RISK_MIN), _INJURY_RISK_MAX), 2)

        payload: Dict[str, Any] = {
            "heart_rate": heart_rate,
            "fatigue_index": fatigue_index,
            "glucose_level": glucose_level,
            "gps_telemetry": gps_telemetry,
            "injury_risk": injury_risk,
        }

        meta: Dict[str, str] = {
            "athlete_id": athlete_id,
            "device_id": device_id,
            "zenodo_record": self.record_id,
        }

        return payload, meta

    # ------------------------------------------------------------------
    # Public API: stream payloads
    # ------------------------------------------------------------------

    def stream_payloads(
        self,
        limit: Optional[int] = None,
        shuffle: bool = True,
    ) -> Generator[Tuple[Dict[str, Any], Dict[str, str]], None, None]:
        """
        Yield (payload, meta) tuples from the loaded athlete dataset.

        Each ``payload`` is a valid ``BiometricPayload`` dict ready to be
        passed directly to ``SecureGateway.encrypt_data()``.

        Args:
            limit:   Maximum number of records to yield. None = all athletes.
            shuffle: If True, randomise the athlete order (default True).

        Yields:
            Tuple[dict, dict]:
                - payload: ``BiometricPayload`` schema-conforming dict.
                - meta:    ``{'athlete_id', 'device_id', 'zenodo_record'}``

        Raises:
            RuntimeError: If ``fetch()`` has not been called yet.
        """
        if not self._fetched:
            raise RuntimeError(
                "Call loader.fetch() before streaming payloads. "
                "Example: loader.fetch(); for p, m in loader.stream_payloads(): ..."
            )

        rows = list(self.athletes_df)
        if shuffle:
            random.shuffle(rows)
        if limit is not None:
            rows = rows[:limit]

        for row in rows:
            yield self._row_to_payload(row)

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def summary(self) -> str:
        """Return a human-readable summary of the loaded dataset."""
        if not self._fetched:
            return "Dataset not yet fetched. Call fetch() first."
        n = len(self.athletes_df)
        return (
            f"Zenodo Synthetic Triathlete Dataset\n"
            f"  Records   : {n} athletes\n"
            f"  DOI       : {self.doi}\n"
            f"  Schema    : heart_rate, fatigue_index, glucose_level, "
            f"gps_telemetry, injury_risk\n"
            f"  GPS source: synthetic (Kona Ironman reference venue)\n"
            f"  Citation  : {self.citation}"
        )

    def __len__(self) -> int:
        return len(self.athletes_df)

    def __repr__(self) -> str:
        status = f"{len(self.athletes_df)} athletes loaded" if self._fetched else "not fetched"
        return f"ZenodoDatasetLoader(record_id={self.record_id!r}, status={status!r})"
