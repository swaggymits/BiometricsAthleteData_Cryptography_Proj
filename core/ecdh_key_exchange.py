"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Task 1 — Week 8: ECDH Key Exchange Primitives

Standalone cryptographic module implementing Elliptic-Curve Diffie-Hellman
(ECDH) key exchange and session-key derivation for the hybrid
Asymmetric-Symmetric encryption architecture.

Architecture Overview
---------------------
The hybrid model works in two phases:

Phase 1 — Asymmetric Key Exchange (this module):
  Each party generates an ephemeral NIST P-256 (secp256r1) key pair per
  session. The ``derive_session_key()`` function performs the ECDH operation
  (point multiplication of one party's private key with the other party's
  public key) and feeds the resulting shared secret through **HKDF-SHA256**
  (RFC 5869) to produce a 32-byte (256-bit) symmetric key.

  Why HKDF over the raw ECDH output?
  - The raw ECDH result is an elliptic-curve group element (x-coordinate
    of a point), NOT a uniformly random byte string. Feeding it directly
    into AES would violate AES's security assumptions.
  - HKDF *extract* step converts the group element into a uniformly
    distributed pseudorandom key material; the *expand* step stretches it
    to the required output length.
  - The ``session_info`` parameter binds the derived key to the specific
    session context (gateway_id, player_id, club_id), preventing
    cross-session key confusion even if the same EC key pair is reused.

Phase 2 — Symmetric Encryption (secure_gateway.py):
  The 32-byte derived key is used as a standard AES-256-GCM key by
  ``SecureGateway.encrypt_data_hybrid()`` / ``decrypt_data_hybrid()``.

Why NIST P-256?
---------------
- Natively supported by ``cryptography>=42.0.0`` (already in requirements.txt)
  with a constant-time, hardware-accelerated backend (OpenSSL).
- The dominant curve in TLS 1.3, FIDO2/WebAuthn, and JOSE/JWK — the project
  can directly re-use its key serialization in real-world deployments.
- 128-bit security level (equivalent to AES-128), well above the minimum
  needed for protecting short-lived session telemetry.

Security Notes
--------------
- ALL key pairs generated here are EPHEMERAL (fresh per session / per
  function call). They are never persisted to disk by this module.
  Long-term public keys for club registration are managed separately by
  ``AthleteDashboard.authorize_club()`` and the ``ClubKeyRegistry`` in
  ``main_server.py``.
- PEM encoding is used for all public-key transport (industry standard,
  human-readable, already supported by the ``cryptography`` library).
- Private keys are never serialized by this module. Any caller that needs
  to transport a private key (e.g., in tests) must handle serialization
  themselves and accept the security responsibility.
"""

from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH,
    SECP256R1,
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    generate_private_key,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Elliptic curve used for all key operations in this module.
CURVE = SECP256R1()

#: Length (bytes) of the AES-256 session key produced by ``derive_session_key``.
SESSION_KEY_BYTES: int = 32

#: HKDF salt: a fixed, non-secret domain separator string.
#: Using a fixed application-specific salt follows the HKDF RFC 5869
#: recommendation when a random salt is not exchanged out-of-band.
_HKDF_SALT: bytes = b"AthleteDataECDH-v1-SessionKey"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_ec_keypair() -> Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
    """
    Generate a fresh ephemeral NIST P-256 EC key pair.

    Every call produces a cryptographically independent key pair using
    the OS CSPRNG. Callers MUST treat the private key as session-local
    secret material and MUST NOT persist it to disk.

    Returns:
        Tuple[EllipticCurvePrivateKey, EllipticCurvePublicKey]:
            ``(private_key, public_key)`` objects. The public key may be
            freely transmitted (see ``serialize_public_key``); the private
            key must remain confidential.

    Example::

        priv, pub = generate_ec_keypair()
        pem = serialize_public_key(pub)   # safe to send over the wire
    """
    private_key: EllipticCurvePrivateKey = generate_private_key(CURVE)
    return private_key, private_key.public_key()


def serialize_public_key(public_key: EllipticCurvePublicKey) -> bytes:
    """
    Serialize an EC public key to PEM-encoded SubjectPublicKeyInfo bytes.

    The PEM format is the standard interchange format for public keys:
    it is ASCII-safe, self-describing, and directly parseable by OpenSSL,
    the ``cryptography`` library, and most cloud/HSM providers.

    Args:
        public_key (EllipticCurvePublicKey): The key object to serialize.

    Returns:
        bytes: PEM-encoded public key (begins with
               ``b"-----BEGIN PUBLIC KEY-----"``).

    Raises:
        TypeError: If ``public_key`` is not an ``EllipticCurvePublicKey``.
    """
    if not isinstance(public_key, EllipticCurvePublicKey):
        raise TypeError(
            f"Expected an EllipticCurvePublicKey, got {type(public_key).__name__}."
        )
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes) -> EllipticCurvePublicKey:
    """
    Deserialize a PEM-encoded EC public key back into a key object.

    Validates that the deserialized key is actually an ``EllipticCurvePublicKey``
    (not an RSA or other key type) before returning it, preventing silent
    type confusion in downstream callers.

    Args:
        pem_bytes (bytes): PEM-encoded SubjectPublicKeyInfo bytes (e.g., as
                           returned by ``serialize_public_key()`` or received
                           from a remote party over the network).

    Returns:
        EllipticCurvePublicKey: The reconstructed public key object.

    Raises:
        TypeError: If the deserialized key is not an EC public key.
        ValueError: If ``pem_bytes`` is not valid PEM or cannot be parsed.
    """
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        key = load_pem_public_key(pem_bytes)
    except Exception as exc:
        raise ValueError(
            f"Failed to deserialize public key from PEM bytes: {exc}"
        ) from exc

    if not isinstance(key, EllipticCurvePublicKey):
        raise TypeError(
            f"PEM data decoded to {type(key).__name__}, not an EllipticCurvePublicKey."
        )
    return key


def derive_session_key(
    private_key: EllipticCurvePrivateKey,
    peer_public_key: EllipticCurvePublicKey,
    session_info: bytes = b"",
) -> bytes:
    """
    Derive a 32-byte AES-256 session key from an ECDH exchange.

    Performs the ECDH key agreement (scalar multiplication) between
    ``private_key`` and ``peer_public_key`` to obtain the raw shared
    secret (x-coordinate of the resulting point), then runs it through
    HKDF-SHA256 to produce a uniformly distributed 32-byte AES key.

    Security Properties
    -------------------
    * **Forward Secrecy**: If both parties use ephemeral key pairs (generated
      fresh per session via ``generate_ec_keypair()``), compromise of any
      long-term key material does NOT expose previously captured ciphertext.
    * **Context Binding**: The ``session_info`` parameter is passed as the
      HKDF ``info`` field, cryptographically tying the derived key to the
      specific session metadata. A session key derived with
      ``session_info=b"GW-01|PLAYER-77|FC-BUYING-CITY"`` is distinct from
      one derived with different context — preventing cross-session key reuse.
    * **Key Separation**: The fixed ``_HKDF_SALT`` domain-separates this
      derivation from any other HKDF usage in the codebase.

    Args:
        private_key (EllipticCurvePrivateKey): This party's private key.
        peer_public_key (EllipticCurvePublicKey): The remote party's public key.
        session_info (bytes): Arbitrary context bytes bound into HKDF derivation
                               (e.g., concatenation of gateway_id, player_id,
                               club_id). Defaults to ``b""`` (no context binding).

    Returns:
        bytes: 32 uniformly random bytes suitable for direct use as an
               AES-256-GCM key in ``AESGCM(derived_key)``.

    Raises:
        TypeError: If either key argument is not the expected EC key type.
        ValueError: If the ECDH operation fails (e.g., point at infinity,
                    key on a different curve).
    """
    if not isinstance(private_key, EllipticCurvePrivateKey):
        raise TypeError(
            f"private_key must be an EllipticCurvePrivateKey, "
            f"got {type(private_key).__name__}."
        )
    if not isinstance(peer_public_key, EllipticCurvePublicKey):
        raise TypeError(
            f"peer_public_key must be an EllipticCurvePublicKey, "
            f"got {type(peer_public_key).__name__}."
        )

    # ECDH — produces the raw shared secret (x-coordinate of P·Q on the curve).
    shared_secret: bytes = private_key.exchange(ECDH(), peer_public_key)

    # HKDF-SHA256: extract + expand the shared secret into a proper AES key.
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=SESSION_KEY_BYTES,
        salt=_HKDF_SALT,
        info=session_info,
    )
    return hkdf.derive(shared_secret)


def build_session_info(
    gateway_id: str,
    player_id: str,
    club_id: str,
) -> bytes:
    """
    Construct the canonical ``session_info`` bytes for HKDF context binding.

    Produces a deterministic, pipe-delimited UTF-8 encoding of the three
    session-context identifiers. Both the gateway (encryptor) and the club
    (decryptor) MUST call this function with the SAME arguments to derive
    the identical AES-256 session key.

    Args:
        gateway_id (str): Edge gateway identifier (e.g., ``"GW-STADIUM-01"``).
        player_id (str):  Athlete identifier (e.g., ``"PLAYER-77"``).
        club_id (str):    Authorized club identifier (e.g., ``"FC-BUYING-CITY"``).

    Returns:
        bytes: Canonical ``|``-delimited UTF-8 context string.

    Example::

        info = build_session_info("GW-01", "PLAYER-77", "FC-CITY")
        # → b"GW-01|PLAYER-77|FC-CITY"
    """
    return f"{gateway_id}|{player_id}|{club_id}".encode("utf-8")
