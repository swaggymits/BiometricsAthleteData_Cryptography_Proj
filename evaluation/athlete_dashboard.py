"""
Data Privacy in Elite Performance: Protecting Athlete Biometrics
Month 2 — Week 5: Access Control & GDPR Consent Toggle
Task 1 — Week 8 Update: Club Authorization Control Plane (ECDH Key Management)

This module implements the ``AthleteDashboard`` class, which represents the
logical client-side controls available to an individual athlete. It is a
**pure-Python, non-GUI, logic-only** component (no Streamlit, no Tkinter,
no frontend framework), as mandated by the instructor's specifications.

Role in the Week 5 Architecture:
---------------------------------
``AthleteDashboard`` acts as the athlete-facing control plane that:

1.  **GDPR Consent Management (Art. 7 & Art. 17 "Right to be Forgotten")**
    Exposes a single ``privacy_toggle_consent`` boolean.  When the athlete
    sets it to ``False``, any server-side component that performs the GDPR
    consent check (``POST /api/v1/athlete/consent`` → stored in
    ``ConsentRegistry``) MUST refuse to decrypt or share that athlete's
    biometrics with ANY requesting party — regardless of their role.  This
    directly implements the GDPR right to withdraw consent at any time
    (Art. 7(3)) and the principle of purpose limitation (Art. 5(1)(b)).

2.  **Authentication (AAA — the first "A")**
    ``authenticate()`` performs a credential check.  In production this
    would validate against an identity provider (OAuth2 / OpenID Connect);
    here it models the interface contract so that the server-side RBAC
    layer can trust ``login_status``.

3.  **Consent Packet Signing**
    ``update_consent()`` returns a structured, HMAC-SHA256-signed consent
    packet.  The signature binds the consent decision to the athlete's
    ``player_id`` and a UTC timestamp, making it tamper-evident: the cloud
    server (or an audit log) can verify that the status update was
    legitimately issued by this athlete, not spoofed by a third party.

4.  **Club Authorization Control Plane (NEW — Task 1 / Week 8)**
    ``authorize_club()`` / ``revoke_club()`` allow the athlete to decide
    WHICH purchasing clubs are permitted to receive an ECDH session key and
    decrypt their biometric telemetry.  ``get_authorized_club_key()`` is
    the gated accessor: it returns the stored PEM only when:
      (a) the club has been explicitly authorized, AND
      (b) GDPR consent is currently granted.
    This gives the athlete sovereign control over their biometric data
    sharing — far beyond a single global consent toggle.

Security & Compliance Notes:
-----------------------------
-   Signing key is intentionally generated fresh per ``AthleteDashboard``
    instance (simulating a device-local secret or a key derived from an HSM
    in a real deployment).  For reproducible verification the key is
    accessible via ``self.signing_key_hex`` — a real system would use a
    proper key-exchange or PKI mechanism.
-   No biometric data is ever stored or processed by this class; it only
    manages consent state and identity.
-   All timestamps use UTC (``time.gmtime()``) and ISO-8601 format for
    interoperability.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Dict

# ---------------------------------------------------------------------------
# Allowed credential keys for the authenticate() method.  Keeping validation
# explicit prevents accidental acceptance of unexpected credential shapes.
# ---------------------------------------------------------------------------
_REQUIRED_CREDENTIAL_KEYS: frozenset[str] = frozenset({"username", "password"})

# ---------------------------------------------------------------------------
# Simulated valid credentials store (stands in for an identity provider).
# In production this MUST be replaced with a real IdP / password-hash check.
# ---------------------------------------------------------------------------
_MOCK_CREDENTIALS: Dict[str, str] = {
    "athlete_admin": "securePass123!",
}


class AthleteDashboard:
    """
    Non-GUI logic class representing an individual athlete's client-side controls.

    Implements GDPR consent management (privacy toggle) and AAA
    authentication / authorization primitives.  Designed to interoperate
    with the cloud server's ``ConsentRegistry`` and Role-Based Access
    Control (RBAC) checks added in Week 5.

    Attributes:
        player_id (str): Unique athlete identifier (e.g., "PLAYER-77").
        privacy_toggle_consent (bool): GDPR consent flag.  ``True`` (default)
            means the athlete consents to their biometric data being accessed
            by authorized personnel.  ``False`` revokes that consent under
            GDPR Art. 7(3) — the cloud server MUST then block all decryption
            requests for this athlete.
        login_status (bool): Authentication state.  ``False`` (default) until
            ``authenticate()`` is called with valid credentials.
        signing_key_hex (str): Hex-encoded 32-byte HMAC-SHA256 signing key
            bound to this dashboard instance, used to produce tamper-evident
            consent packets in ``update_consent()``.
    """

    def __init__(self, player_id: str) -> None:
        """
        Initialise the AthleteDashboard for the specified athlete.

        Args:
            player_id (str): Unique athlete identifier.  Must be a non-empty
                             string (validated on construction).

        Raises:
            ValueError: If ``player_id`` is empty or not a string.
        """
        if not player_id or not isinstance(player_id, str):
            raise ValueError("player_id must be a non-empty string.")

        self.player_id: str = player_id

        # GDPR consent: True = athlete consents to authorized biometric access.
        # Defaults to True so that a freshly enrolled athlete is "opted in"
        # until they explicitly revoke (GDPR Art. 7 — consent must be freely
        # given AND freely withdrawable).
        self.privacy_toggle_consent: bool = True

        # Authentication / session state — starts unauthenticated.
        self.login_status: bool = False

        # Tamper-evident consent signing key (fresh per instance / per session).
        # In a real deployment this would come from a secure credential store,
        # HSM, or be derived from an authenticated session token.
        self._signing_key: bytes = os.urandom(32)
        self.signing_key_hex: str = self._signing_key.hex()

        # --- Week 8: Club Authorization Registry ---
        # Maps club_id → PEM-encoded public key bytes for authorized clubs.
        # Only clubs in this dict may receive an ECDH session key from the
        # athlete's gateway. Empty by default — the athlete must explicitly
        # call authorize_club() to grant access to each purchasing club.
        self._authorized_clubs: Dict[str, bytes] = {}

    # ------------------------------------------------------------------
    # Week 8 — Club Authorization Control Plane
    # ------------------------------------------------------------------

    def authorize_club(
        self,
        club_id: str,
        club_public_key_pem: bytes,
    ) -> None:
        """
        Register a purchasing club's NIST P-256 public key as authorized.

        Once registered, the club's PEM key is stored in
        ``self._authorized_clubs`` and can be retrieved via
        ``get_authorized_club_key()`` for use in the ECDH handshake.

        This is the athlete's explicit, per-club consent: they choose
        exactly which clubs may initiate an ECDH session to receive
        their encrypted biometric telemetry.

        Args:
            club_id (str): Unique club identifier (e.g., ``"FC-BUYING-CITY"``).
            club_public_key_pem (bytes): PEM-encoded NIST P-256 public key
                                          of the club. Must begin with
                                          ``b"-----BEGIN PUBLIC KEY-----"``.

        Raises:
            ValueError: If ``club_id`` is empty or not a string.
            TypeError: If ``club_public_key_pem`` is not bytes or bytearray.
        """
        if not club_id or not isinstance(club_id, str):
            raise ValueError("club_id must be a non-empty string.")
        if not isinstance(club_public_key_pem, (bytes, bytearray)):
            raise TypeError(
                f"club_public_key_pem must be bytes, got {type(club_public_key_pem).__name__}."
            )
        self._authorized_clubs[club_id] = bytes(club_public_key_pem)

    def revoke_club(
        self,
        club_id: str,
    ) -> bool:
        """
        Revoke a previously authorized club's access.

        Removes the club's public key from the authorized registry.
        Subsequent calls to ``get_authorized_club_key(club_id)`` will
        raise ``PermissionError`` until ``authorize_club()`` is called again.

        This complements GDPR Art. 7(3) (right to withdraw consent) at the
        per-club level: the athlete can fine-grain revoke a specific club's
        access without affecting other authorized parties.

        Args:
            club_id (str): Unique club identifier to revoke.

        Returns:
            bool: ``True`` if the club was authorized and has been removed;
                  ``False`` if the club was not in the authorized list
                  (idempotent — does not raise on double-revoke).
        """
        if club_id in self._authorized_clubs:
            del self._authorized_clubs[club_id]
            return True
        return False

    def get_authorized_club_key(
        self,
        club_id: str,
    ) -> bytes:
        """
        Return the PEM-encoded public key for an authorized club.

        This is the gated accessor used by the edge gateway before calling
        ``SecureGateway.encrypt_data_hybrid()``. Two independent conditions
        must BOTH be true before the key is released:

        1. **Club Authorization**: ``club_id`` must have been registered via
           ``authorize_club()`` (explicit per-club athlete consent).
        2. **Global GDPR Consent**: ``privacy_toggle_consent`` must be
           ``True`` (global biometric access consent). If the athlete has
           revoked global consent, no club key is returned regardless of
           individual club authorization status.

        Args:
            club_id (str): Unique club identifier whose key is requested.

        Returns:
            bytes: PEM-encoded NIST P-256 public key of the authorized club.

        Raises:
            PermissionError: If global GDPR consent is revoked
                             (``privacy_toggle_consent == False``), or if
                             ``club_id`` has not been authorized via
                             ``authorize_club()``.
        """
        # Gate 1: Global GDPR consent check.
        if not self.privacy_toggle_consent:
            raise PermissionError(
                f"Access Denied: Athlete {self.player_id!r} has revoked global "
                f"GDPR consent. No club key may be released."
            )
        # Gate 2: Per-club authorization check.
        if club_id not in self._authorized_clubs:
            raise PermissionError(
                f"Access Denied: Club {club_id!r} is not authorized by "
                f"athlete {self.player_id!r}. Call authorize_club() first."
            )
        return self._authorized_clubs[club_id]

    def get_authorization_status(self) -> Dict[str, Any]:
        """
        Return a snapshot of the current club authorization state.

        Provides a read-only view of which clubs have been authorized,
        suitable for audit logging, the athlete's dashboard display, or
        server-side registration checks.

        Returns:
            Dict[str, Any]: A dictionary containing:
                - ``player_id``              (str)  Athlete identifier.
                - ``privacy_toggle_consent`` (bool) Global GDPR consent flag.
                - ``authorized_clubs``       (list) List of currently authorized
                  club IDs (public key bytes are NOT included for brevity).
                - ``authorized_club_count``  (int)  Number of authorized clubs.
        """
        return {
            "player_id": self.player_id,
            "privacy_toggle_consent": self.privacy_toggle_consent,
            "authorized_clubs": sorted(self._authorized_clubs.keys()),
            "authorized_club_count": len(self._authorized_clubs),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_consent(self, consent_status: bool) -> Dict[str, Any]:
        """
        Update the athlete's GDPR consent flag and return a signed consent packet.

        The returned packet is suitable for transmission to the cloud server's
        ``POST /api/v1/athlete/consent`` endpoint.  The HMAC-SHA256 signature
        makes the packet tamper-evident: any modification to ``player_id``,
        ``privacy_toggle_consent``, or ``issued_at`` will invalidate the MAC,
        so the server (or an independent audit log) can detect spoofed updates.

        Args:
            consent_status (bool): New GDPR consent state.
                ``True``  → athlete grants consent (biometric access permitted
                            to authorized roles such as TEAM_DOCTOR).
                ``False`` → athlete revokes consent (all decryption requests
                            for this player MUST be blocked by the server,
                            regardless of the requester's role, per GDPR Art. 7(3)).

        Returns:
            Dict[str, Any]: Signed consent-status update packet containing:
                - ``player_id``              (str)   Athlete identifier.
                - ``privacy_toggle_consent`` (bool)  New consent state.
                - ``issued_at``              (str)   UTC ISO-8601 timestamp.
                - ``gdpr_basis``             (str)   Legal basis identifier.
                - ``signature_hmac_sha256``  (str)   Hex HMAC-SHA256 over the
                                                     canonical payload bytes.

        Raises:
            TypeError: If ``consent_status`` is not a boolean.
        """
        if not isinstance(consent_status, bool):
            raise TypeError(
                f"consent_status must be a bool, got {type(consent_status).__name__}."
            )

        # Persist the new state on this instance immediately.
        self.privacy_toggle_consent = consent_status

        issued_at: str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Canonical payload (sorted keys, tight separators) for deterministic signing.
        import json

        canonical_payload: str = json.dumps(
            {
                "gdpr_basis": "GDPR_Art7_ConsentWithdrawal"
                if not consent_status
                else "GDPR_Art7_ConsentGranted",
                "issued_at": issued_at,
                "player_id": self.player_id,
                "privacy_toggle_consent": consent_status,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

        signature: str = hmac.new(
            self._signing_key,
            canonical_payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return {
            "player_id": self.player_id,
            "privacy_toggle_consent": consent_status,
            "issued_at": issued_at,
            "gdpr_basis": "GDPR_Art7_ConsentWithdrawal"
            if not consent_status
            else "GDPR_Art7_ConsentGranted",
            "signature_hmac_sha256": signature,
        }

    def authenticate(self, credentials: dict) -> bool:
        """
        Attempt to authenticate the athlete with the provided credentials.

        Models the Authentication leg of the AAA (Authentication, Authorisation,
        Accounting) framework.  In a production system this would validate
        against a password-hash store or delegate to an OAuth2 identity provider
        (e.g., Google, Okta).  Here it validates against a local mock credential
        dictionary, giving the integration tests a deterministic fixture.

        Side-effect: sets ``self.login_status = True`` on success.

        Args:
            credentials (dict): Mapping containing at least ``"username"``
                                 (str) and ``"password"`` (str).

        Returns:
            bool: ``True`` if authentication succeeded; ``False`` otherwise.
                  Never raises on bad credentials — callers must inspect the
                  return value.

        Raises:
            TypeError:  If ``credentials`` is not a dict.
            ValueError: If ``credentials`` is missing a required key
                        (``"username"`` or ``"password"``).
        """
        if not isinstance(credentials, dict):
            raise TypeError(
                f"credentials must be a dict, got {type(credentials).__name__}."
            )

        missing = _REQUIRED_CREDENTIAL_KEYS - credentials.keys()
        if missing:
            raise ValueError(
                f"credentials dict is missing required key(s): {sorted(missing)}."
            )

        username: str = credentials["username"]
        password: str = credentials["password"]

        # Use a constant-time comparison to avoid timing-based side-channels
        # that could leak whether a username exists before the password check.
        stored_password: str = _MOCK_CREDENTIALS.get(username, "")
        authenticated: bool = hmac.compare_digest(
            stored_password.encode("utf-8"),
            password.encode("utf-8"),
        )

        if authenticated:
            self.login_status = True

        return authenticated

    def get_athlete_state(self) -> Dict[str, Any]:
        """
        Return a snapshot of the current athlete dashboard state.

        Useful for the server to inspect consent/auth status without coupling
        to internal attribute names, and for audit logging.

        Returns:
            Dict[str, Any]: State snapshot containing:
                - ``player_id``              (str)  Athlete identifier.
                - ``privacy_toggle_consent`` (bool) Current GDPR consent flag.
                - ``login_status``           (bool) Current authentication state.
        """
        return {
            "player_id": self.player_id,
            "privacy_toggle_consent": self.privacy_toggle_consent,
            "login_status": self.login_status,
        }

    # ------------------------------------------------------------------
    # Dunder helpers
    # ------------------------------------------------------------------

    def __repr__(self) -> str:  # pragma: no cover
        return (
            f"AthleteDashboard("
            f"player_id={self.player_id!r}, "
            f"consent={self.privacy_toggle_consent}, "
            f"authenticated={self.login_status})"
        )
