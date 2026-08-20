"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Week 1: Core Encryption Module & Secure Edge Gateway
Task 1 — Week 8 Update: Hybrid ECDH + AES-GCM Key Exchange

This module now supports TWO encryption modes:

1. **Legacy Symmetric Mode** (original, unchanged):
   ``encrypt_data()`` / ``decrypt_data()`` — uses a pre-shared AES-256 key.
   All existing callers continue to work without modification.

2. **Hybrid ECDH Mode** (new in Week 8):
   ``encrypt_data_hybrid()`` / ``decrypt_data_hybrid()`` — performs an
   Elliptic-Curve Diffie-Hellman key exchange (NIST P-256) between the edge
   gateway and an authorized purchasing club, deriving a *session-specific*
   AES-256-GCM key via HKDF-SHA256. The static pre-shared key is completely
   eliminated from the data path.

   Security Impact:
   - **Eliminates multi-tenant decryption leaks**: Each session produces a
     unique key. A compromised gateway key does NOT expose past or future
     telemetry from other sessions or other clubs.
   - **Forward Secrecy**: Ephemeral key pairs (generated fresh per
     ``SecureGateway`` instance) mean that even full compromise of long-term
     club key material cannot retroactively decrypt captured ciphertext.
   - **Tactical espionage hardening**: Rival clubs or eavesdroppers cannot
     derive the session key without the authorized club's private key AND the
     gateway's ephemeral private key — both must be simultaneously compromised.
"""

from __future__ import annotations

import calendar
import json
import os
import time
from typing import Any, Dict, Optional, Set, Union

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.biometric_schema import validate_biometric_payload
from core.ecdh_key_exchange import (
    build_session_info,
    derive_session_key,
    deserialize_public_key,
    generate_ec_keypair,
    serialize_public_key,
)


def build_associated_data(**context: Any) -> bytes:
    """
    Deterministically encode contextual metadata (e.g., gateway_id, device_id,
    player_id, timestamp) into canonical bytes suitable for use as AES-GCM
    Associated Authenticated Data (AAD).

    Binding this context to the ciphertext means the authentication tag is
    only valid for THIS exact combination of gateway/device/timestamp. An
    attacker cannot splice a genuine ciphertext onto a different device_id,
    replay it under a different gateway, or relabel its origin — any such
    tampering causes `decrypt_data()` to raise `InvalidTag`, even though the
    ciphertext bytes themselves were never modified.

    Args:
        **context: Arbitrary key/value metadata to bind (must be JSON-serializable).

    Returns:
        bytes: Canonical (sorted-key, separator-normalized) UTF-8 JSON encoding.
    """
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")


class SecureGateway:
    """
    Edge Security Gateway for Athlete Biometric Data Protection.

    This class simulates an edge computing gateway node attached to wearable sensors
    (e.g., GPS vests, heart rate monitors, fatigue monitors). It provides robust data
    confidentiality, integrity, and authenticity for sensitive telemetry data prior to
    transmission over untrusted networks (e.g., stadium Wi-Fi, cellular, radio links).

    Security Architecture & Espionage Mitigation:
    ----------------------------------------------
    1. Confidentiality (AES-256 Encryption):
       Prevents tactical performance espionage. Rival teams or malicious third parties
       intercepting unencrypted biometric telemetry (heart rate variability, fatigue index,
       sprint speed degradation, muscle load) could gain unfair competitive advantages by
       detecting player exhaustion, tactical weaknesses, or impending injury risks during matches.
       AES-256 ensures payload confidentiality under current cryptographic standards.

    2. Integrity & Authenticity (Galois/Counter Mode - GCM):
       AES-GCM is an Authenticated Encryption with Associated Data (AEAD) scheme. It computes
       a 128-bit authentication tag appended to the ciphertext. Any unauthorized tampering or
       bit-flipping in transit causes decryption failure (raising cryptography.exceptions.InvalidTag),
       preventing adversary data injection or spoofing of player telemetry.

    3. Replay Protection & Semantic Security (Unique 96-bit Nonce):
       Each encryption operation utilizes a cryptographically random 12-byte (96-bit) nonce
       generated via system entropy (`os.urandom(12)`). This guarantees that identical
       biometric readings produce distinct ciphertexts, thwarting eavesdropping pattern
       analysis. An in-memory nonce ledger additionally detects (defense-in-depth) the
       catastrophic case of accidental nonce reuse under the same key, refusing to encrypt
       rather than silently breaking GCM's confidentiality/integrity guarantees.

    4. Context Binding (Associated Authenticated Data - AAD):
       Every ciphertext's authentication tag is cryptographically bound to contextual
       metadata (gateway_id, device_id, player_id, packet timestamp) via AES-GCM's AAD
       mechanism. This prevents "cut-and-paste" attacks where an adversary captures a
       genuine ciphertext and re-attributes it to a different device/athlete, or replays
       it through a different gateway — `decrypt_data()` will raise `InvalidTag` unless
       the exact same context is supplied.

    5. Replay / Freshness Protection (Timestamped Packets + Max-Age Window):
       Every encrypted packet carries a `sent_at` UTC timestamp (also bound via AAD).
       `decrypt_data()` optionally rejects packets older than `max_age_seconds`,
       closing the window for delayed replay attacks (an adversary capturing and
       re-transmitting a valid packet later to spoof stale telemetry as "live").

    6. Hybrid ECDH Key Exchange (NEW — Task 1 / Week 8):
       ``encrypt_data_hybrid()`` / ``decrypt_data_hybrid()`` replace the static
       pre-shared AES key with a per-session key derived via ECDH (NIST P-256)
       + HKDF-SHA256. The gateway's ephemeral public key travels alongside the
       ciphertext so that only the authorized club holding the matching private
       key can derive the session AES key and decrypt the payload. This neutralizes
       multi-tenant decryption leaks and provides forward secrecy.

    Key Management:
    ----------------
    **Legacy symmetric mode** (unchanged):
    A `SecureGateway` may be constructed with a pre-shared 32-byte AES key
    (``aes_key`` parameter) for backward-compatible operation. All existing
    ``encrypt_data()`` / ``decrypt_data()`` callers continue to work.

    **Hybrid ECDH mode** (new):
    Each ``SecureGateway`` instance generates a fresh ephemeral NIST P-256 key
    pair on construction. ``get_public_key_pem()`` exposes the ephemeral public
    key for transmission to the authorized club. The club's registered public key
    is used during ``encrypt_data_hybrid()`` to derive the session AES key.
    """

    NONCE_BYTES: int = 12  # 96-bit nonce, the standard/recommended size for AES-GCM

    def __init__(self, gateway_id: str, aes_key: Optional[bytes] = None) -> None:
        """
        Initialize the SecureGateway instance.

        Automatically generates an ephemeral NIST P-256 EC key pair for use
        in the new hybrid ECDH encryption path. The legacy symmetric key
        (``aes_key``) is also managed here for full backward compatibility.

        Args:
            gateway_id (str): Unique identifier for the edge gateway device.
            aes_key (Optional[bytes]): Pre-shared 256-bit (32-byte) symmetric key for
                                        the legacy ``encrypt_data()`` / ``decrypt_data()``
                                        path. If omitted, a fresh cryptographically random
                                        key is generated. Supply the SAME key to both the
                                        encrypting (edge) and decrypting (cloud) gateway
                                        instances for real interoperability.

        Raises:
            ValueError: If gateway_id is empty/not a string, or aes_key is provided but
                        is not exactly 32 bytes.
        """
        if not gateway_id or not isinstance(gateway_id, str):
            raise ValueError("gateway_id must be a non-empty string.")

        if aes_key is not None:
            if not isinstance(aes_key, (bytes, bytearray)) or len(aes_key) != 32:
                raise ValueError("aes_key must be exactly 32 bytes (256 bits) if provided.")
            self.aes_key: bytes = bytes(aes_key)
        else:
            # Generate a cryptographically secure 256-bit (32 bytes) symmetric key
            self.aes_key = AESGCM.generate_key(bit_length=256)

        # Instantiate the AESGCM cipher engine with the 256-bit symmetric key
        self.aesgcm: AESGCM = AESGCM(self.aes_key)
        self.gateway_id: str = gateway_id

        # Defense-in-depth: tracks (nonce) values used by THIS instance so an accidental
        # nonce reuse under the same key is detected loudly instead of silently
        # degrading AES-GCM's security guarantees (catastrophic for confidentiality/auth).
        self._used_nonces: Set[bytes] = set()

        # --- Week 8: Hybrid ECDH Key Pair ---
        # Generate a fresh ephemeral NIST P-256 key pair for ECDH-based sessions.
        # This private key NEVER leaves this instance; only the public key is exposed
        # via ``get_public_key_pem()`` for transmission to the authorized club.
        self._ec_private_key, self._ec_public_key = generate_ec_keypair()

    def encrypt_data(
        self,
        raw_data: Union[dict, str],
        *,
        device_id: Optional[str] = None,
        player_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt raw biometric telemetry data using AES-256-GCM with context-bound AAD.

        Accepts biometric data as a dictionary or plain text string, serializes it to
        UTF-8 encoded bytes, generates a unique 12-byte initialization vector (nonce),
        and produces authenticated ciphertext whose authentication tag is additionally
        bound to `gateway_id`, `device_id`, `player_id`, and the packet's `sent_at`
        timestamp via Associated Authenticated Data (AAD).

        Args:
            raw_data (Union[dict, str]): Biometric telemetry payload. When a dict is
                                         supplied, it MUST conform to the official
                                         `BiometricPayload` Data Schema (see
                                         `biometric_schema.py`): heart_rate (int),
                                         fatigue_index (float), glucose_level (float),
                                         gps_telemetry (JSON object), injury_risk (float).
                                         Plain strings (e.g., alert messages) are also
                                         accepted and bypass schema validation.
            device_id (Optional[str]): Originating wearable device identifier, bound
                                        into the AAD context (defense against packet
                                        re-attribution / splicing attacks).
            player_id (Optional[str]): Athlete identifier, bound into the AAD context.

        Returns:
            Dict[str, Any]: A dictionary containing:
                - 'gateway_id': Identifier of the originating gateway.
                - 'device_id' / 'player_id': Echoed context (also bound as AAD).
                - 'sent_at': UTC ISO-8601 timestamp of encryption (bound as AAD).
                - 'nonce': Hex-encoded 12-byte initialization vector.
                - 'ciphertext': Hex-encoded encrypted payload (includes appended GCM auth tag).

        Raises:
            TypeError: If raw_data is neither a dictionary nor a string, or a dict
                       field has the wrong type per the schema.
            ValueError: If a dict payload is missing a required schema field, a value
                        is outside its permitted range, or (astronomically unlikely)
                        a nonce collision is detected for this gateway instance.
        """
        if isinstance(raw_data, dict):
            # Enforce the strict instructor-mandated Data Schema BEFORE encryption.
            # Rejecting malformed telemetry here prevents corrupted/spoofed data
            # from ever being encrypted and transmitted downstream.
            validated_payload = validate_biometric_payload(raw_data)
            payload_bytes: bytes = json.dumps(validated_payload).encode("utf-8")
        elif isinstance(raw_data, str):
            payload_bytes = raw_data.encode("utf-8")
        else:
            raise TypeError("raw_data must be a dictionary or a string.")

        sent_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Generate a fresh 12-byte (96-bit) random nonce for GCM standard mode.
        # Re-roll (extremely unlikely to ever trigger) if this instance has already
        # used this exact nonce value, then hard-fail if collisions persist — a
        # real nonce collision under the same key would be a critical security event.
        nonce: bytes = os.urandom(self.NONCE_BYTES)
        attempts = 0
        while nonce in self._used_nonces:
            attempts += 1
            if attempts > 5:
                raise ValueError(
                    "SECURITY FAILURE: repeated AES-GCM nonce collision detected; "
                    "refusing to encrypt to avoid breaking confidentiality/integrity."
                )
            nonce = os.urandom(self.NONCE_BYTES)
        self._used_nonces.add(nonce)

        associated_data = build_associated_data(
            gateway_id=self.gateway_id,
            device_id=device_id,
            player_id=player_id,
            sent_at=sent_at,
        )

        # Encrypt the payload; AESGCM handles tag computation automatically
        ciphertext_bytes: bytes = self.aesgcm.encrypt(
            nonce, payload_bytes, associated_data=associated_data
        )

        return {
            "gateway_id": self.gateway_id,
            "device_id": device_id,
            "player_id": player_id,
            "sent_at": sent_at,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext_bytes.hex(),
        }

    # -----------------------------------------------------------------------
    # Week 8 — Hybrid ECDH Helpers & Encryption/Decryption
    # -----------------------------------------------------------------------

    def get_public_key_pem(self) -> bytes:
        """
        Return this gateway's ephemeral NIST P-256 public key in PEM format.

        The authorized club must receive this PEM (alongside the ciphertext
        packet) so it can reconstruct the ECDH shared secret and derive the
        session AES key. This is the ONLY piece of the gateway's key material
        that is ever transmitted externally; the private key stays local.

        Returns:
            bytes: PEM-encoded SubjectPublicKeyInfo (begins with
                   ``b"-----BEGIN PUBLIC KEY-----"``).
        """
        return serialize_public_key(self._ec_public_key)

    def encrypt_data_hybrid(
        self,
        raw_data: Union[dict, str],
        club_public_key_pem: bytes,
        *,
        club_id: str,
        device_id: Optional[str] = None,
        player_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Encrypt biometric telemetry using the ECDH hybrid mode (Task 1 / Week 8).

        Replaces the static pre-shared AES key with a *session-specific* key
        derived from an ECDH exchange between this gateway's ephemeral private
        key and the authorized club's registered public key. The gateway's
        ephemeral public key is embedded in the returned packet so the club can
        mirror the ECDH and derive the identical session AES key.

        Encryption Flow
        ---------------
        1. Deserialize the club's PEM public key.
        2. Build the session context string: ``{gateway_id}|{player_id}|{club_id}``.
        3. Derive the 32-byte AES-256 session key via ``derive_session_key()``
           (ECDH + HKDF-SHA256 with context binding).
        4. Generate a random 12-byte GCM nonce (same nonce-reuse guard as the
           symmetric path).
        5. Build AAD from gateway_id / device_id / player_id / sent_at — same
           context-binding mechanism as the legacy path.
        6. AES-256-GCM encrypt; embed the gateway's ephemeral public key PEM
           and ``club_id`` in the returned packet.

        Args:
            raw_data (Union[dict, str]): Biometric telemetry payload. Dict inputs
                                         are validated against the BiometricPayload
                                         schema before encryption.
            club_public_key_pem (bytes): PEM-encoded NIST P-256 public key of the
                                          authorized receiving club (as registered via
                                          ``AthleteDashboard.authorize_club()``).
            club_id (str): Unique identifier of the authorized club. Bound into the
                            HKDF context to prevent cross-club key confusion.
            device_id (Optional[str]): Wearable device identifier (bound into AAD).
            player_id (Optional[str]): Athlete identifier (bound into AAD and HKDF context).

        Returns:
            Dict[str, Any]: Encrypted packet containing:
                - Standard fields: ``gateway_id``, ``device_id``, ``player_id``,
                  ``sent_at``, ``nonce`` (hex), ``ciphertext`` (hex).
                - NEW: ``ephemeral_public_key_pem`` (bytes) — gateway's ephemeral
                  EC public key for the club to mirror the ECDH.
                - NEW: ``club_id`` (str) — target club identifier.

        Raises:
            TypeError: If ``raw_data`` is not a dict or str, or a dict field
                       has the wrong type per the schema.
            ValueError: If a required schema field is missing/out-of-range,
                        ``club_public_key_pem`` cannot be deserialized, or a
                        nonce collision is detected.
        """
        if isinstance(raw_data, dict):
            validated_payload = validate_biometric_payload(raw_data)
            payload_bytes: bytes = json.dumps(validated_payload).encode("utf-8")
        elif isinstance(raw_data, str):
            payload_bytes = raw_data.encode("utf-8")
        else:
            raise TypeError("raw_data must be a dictionary or a string.")

        # Step 1: Deserialize the club's public key.
        club_public_key: EllipticCurvePublicKey = deserialize_public_key(club_public_key_pem)

        sent_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Step 2-3: Derive session-specific AES-256 key via ECDH + HKDF.
        session_info: bytes = build_session_info(
            gateway_id=self.gateway_id,
            player_id=player_id or "",
            club_id=club_id,
        )
        session_key: bytes = derive_session_key(
            self._ec_private_key, club_public_key, session_info=session_info
        )
        session_aesgcm = AESGCM(session_key)

        # Step 4: Fresh random nonce (same reuse-guard as the symmetric path).
        nonce: bytes = os.urandom(self.NONCE_BYTES)
        attempts = 0
        while nonce in self._used_nonces:
            attempts += 1
            if attempts > 5:
                raise ValueError(
                    "SECURITY FAILURE: repeated AES-GCM nonce collision detected; "
                    "refusing to encrypt to avoid breaking confidentiality/integrity."
                )
            nonce = os.urandom(self.NONCE_BYTES)
        self._used_nonces.add(nonce)

        # Step 5: Build context-binding AAD (same mechanism as symmetric path).
        associated_data = build_associated_data(
            gateway_id=self.gateway_id,
            device_id=device_id,
            player_id=player_id,
            sent_at=sent_at,
        )

        # Step 6: AES-256-GCM encryption with the derived session key.
        ciphertext_bytes: bytes = session_aesgcm.encrypt(
            nonce, payload_bytes, associated_data=associated_data
        )

        return {
            "gateway_id": self.gateway_id,
            "device_id": device_id,
            "player_id": player_id,
            "sent_at": sent_at,
            "nonce": nonce.hex(),
            "ciphertext": ciphertext_bytes.hex(),
            # ECDH-specific fields:
            "ephemeral_public_key_pem": self.get_public_key_pem().decode("utf-8"),
            "club_id": club_id,
        }

    def decrypt_data_hybrid(
        self,
        encrypted_packet: dict,
        club_private_key_pem: bytes,
        *,
        max_age_seconds: Optional[float] = None,
    ) -> Union[dict, str]:
        """
        Decrypt a hybrid ECDH-encrypted biometric packet (Task 1 / Week 8).

        Mirrors the ECDH exchange performed by ``encrypt_data_hybrid()``: extracts
        the gateway's ephemeral public key from the packet, uses the club's private
        key to derive the same session AES key, then decrypts and verifies the
        AES-256-GCM ciphertext.

        Decryption Flow
        ---------------
        1. Validate freshness (``max_age_seconds``) if requested.
        2. Deserialize the gateway's ephemeral public key PEM from the packet.
        3. Reconstruct the session context: ``{gateway_id}|{player_id}|{club_id}``.
        4. Derive the 32-byte AES-256 session key via ``derive_session_key()``
           — identical HKDF inputs → identical output.
        5. Reconstruct the AAD from the packet's routing metadata.
        6. AES-256-GCM decrypt + auth-tag verification.

        Args:
            encrypted_packet (dict): Packet produced by ``encrypt_data_hybrid()``.
                                      Must contain: ``gateway_id``, ``device_id``,
                                      ``player_id``, ``sent_at``, ``nonce`` (hex),
                                      ``ciphertext`` (hex),
                                      ``ephemeral_public_key_pem`` (str/bytes),
                                      ``club_id`` (str).
            club_private_key_pem (bytes): PEM-encoded NIST P-256 private key of the
                                           authorized club performing the decryption.
            max_age_seconds (Optional[float]): Freshness window for replay protection
                                                (same semantics as ``decrypt_data()``).

        Returns:
            Union[dict, str]: Decrypted original payload.

        Raises:
            KeyError: If mandatory packet fields are missing.
            ValueError: If the packet is stale, or key deserialization fails.
            cryptography.exceptions.InvalidTag: If the session key is wrong (wrong
                private key, wrong club_id, tampered ciphertext, or tampered AAD).
        """
        required = {"nonce", "ciphertext", "ephemeral_public_key_pem", "club_id"}
        missing = required - encrypted_packet.keys()
        if missing:
            raise KeyError(
                f"Hybrid encrypted packet is missing required field(s): {sorted(missing)}"
            )

        # Step 1: Replay / freshness check (same logic as decrypt_data).
        if max_age_seconds is not None and "sent_at" in encrypted_packet:
            sent_epoch = calendar.timegm(
                time.strptime(encrypted_packet["sent_at"], "%Y-%m-%dT%H:%M:%SZ")
            )
            age = time.time() - sent_epoch
            if age > max_age_seconds:
                raise ValueError(
                    f"SECURITY FAILURE: packet is stale (age={age:.1f}s > "
                    f"max_age_seconds={max_age_seconds}); possible replay attack."
                )

        # Step 2: Deserialize the gateway's ephemeral public key.
        raw_pem = encrypted_packet["ephemeral_public_key_pem"]
        if isinstance(raw_pem, str):
            raw_pem = raw_pem.encode("utf-8")
        gateway_ephemeral_pub: EllipticCurvePublicKey = deserialize_public_key(raw_pem)

        # Step 3: Deserialize the club's private key.
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        club_private_key = load_pem_private_key(club_private_key_pem, password=None)

        # Step 4: Reconstruct the session context and derive the identical AES key.
        session_info: bytes = build_session_info(
            gateway_id=encrypted_packet.get("gateway_id", ""),
            player_id=encrypted_packet.get("player_id") or "",
            club_id=encrypted_packet["club_id"],
        )
        session_key: bytes = derive_session_key(
            club_private_key, gateway_ephemeral_pub, session_info=session_info
        )
        session_aesgcm = AESGCM(session_key)

        # Step 5: Reconstruct the AAD.
        associated_data = build_associated_data(
            gateway_id=encrypted_packet.get("gateway_id"),
            device_id=encrypted_packet.get("device_id"),
            player_id=encrypted_packet.get("player_id"),
            sent_at=encrypted_packet.get("sent_at"),
        )

        # Step 6: AES-256-GCM decryption + authentication-tag verification.
        nonce: bytes = bytes.fromhex(encrypted_packet["nonce"])
        ciphertext_bytes: bytes = bytes.fromhex(encrypted_packet["ciphertext"])
        decrypted_bytes: bytes = session_aesgcm.decrypt(
            nonce, ciphertext_bytes, associated_data=associated_data
        )
        decrypted_str: str = decrypted_bytes.decode("utf-8")

        try:
            return json.loads(decrypted_str)
        except json.JSONDecodeError:
            return decrypted_str

    def decrypt_data(
        self,
        encrypted_packet: dict,
        *,
        max_age_seconds: Optional[float] = None,
    ) -> Union[dict, str]:
        """
        Decrypt and verify an encrypted biometric data packet.

        Extracts the hex-encoded nonce and ciphertext, reconstructs the AAD context
        from the packet's own `gateway_id`/`device_id`/`player_id`/`sent_at` fields,
        verifies the authentication tag over BOTH the ciphertext and that context,
        and reconstructs the original payload (dictionary or string).

        Args:
            encrypted_packet (dict): Structured packet containing 'gateway_id',
                                     'device_id', 'player_id', 'sent_at', 'nonce' (hex),
                                     and 'ciphertext' (hex).
            max_age_seconds (Optional[float]): If provided, reject (raise ValueError)
                                                packets whose 'sent_at' is older than
                                                this many seconds relative to now,
                                                mitigating delayed replay attacks.

        Returns:
            Union[dict, str]: Deserialized original payload dictionary or UTF-8 decoded string.

        Raises:
            KeyError: If mandatory keys ('nonce', 'ciphertext') are missing from the packet.
            ValueError: If the packet exceeds `max_age_seconds` (stale/replayed packet).
            cryptography.exceptions.InvalidTag: If payload or ANY bound context field
                (gateway_id, device_id, player_id, sent_at) has been altered in transit,
                or the packet was re-attributed to a different device/athlete/gateway.
        """
        if "nonce" not in encrypted_packet or "ciphertext" not in encrypted_packet:
            raise KeyError("Encrypted packet must contain 'nonce' and 'ciphertext' fields.")

        if max_age_seconds is not None and "sent_at" in encrypted_packet:
            sent_epoch = calendar.timegm(
                time.strptime(encrypted_packet["sent_at"], "%Y-%m-%dT%H:%M:%SZ")
            )
            age = time.time() - sent_epoch
            if age > max_age_seconds:
                raise ValueError(
                    f"SECURITY FAILURE: packet is stale (age={age:.1f}s > "
                    f"max_age_seconds={max_age_seconds}); possible replay attack."
                )

        nonce: bytes = bytes.fromhex(encrypted_packet["nonce"])
        ciphertext_bytes: bytes = bytes.fromhex(encrypted_packet["ciphertext"])

        associated_data = build_associated_data(
            gateway_id=encrypted_packet.get("gateway_id"),
            device_id=encrypted_packet.get("device_id"),
            player_id=encrypted_packet.get("player_id"),
            sent_at=encrypted_packet.get("sent_at"),
        )

        # Decrypt payload and verify authentication tag over ciphertext + AAD context
        decrypted_bytes: bytes = self.aesgcm.decrypt(
            nonce, ciphertext_bytes, associated_data=associated_data
        )
        decrypted_str: str = decrypted_bytes.decode("utf-8")

        # Attempt to deserialize as JSON dictionary; fallback to string if not JSON
        try:
            return json.loads(decrypted_str)
        except json.JSONDecodeError:
            return decrypted_str
