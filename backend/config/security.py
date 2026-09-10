"""
SENTINEL-X Security Boundary

This project is designed for passive observation of
unidirectional IP traffic.

The following capabilities are intentionally disabled:

- Active probing
- Active scanning
- Automated blocking
- Firewall modification
- Payload decryption
- Return-path communication

SENTINEL-X produces cybersecurity intelligence and alerts only.
"""

READ_ONLY_MODE = True

ALLOW_ACTIVE_PROBING = False
ALLOW_ACTIVE_SCANNING = False
ALLOW_AUTOMATED_BLOCKING = False
ALLOW_PAYLOAD_DECRYPTION = False
ALLOW_RETURN_PATH = False


def security_policy() -> dict:
    """
    Return the immutable security policy used by SENTINEL-X.
    """

    return {
        "read_only_mode": READ_ONLY_MODE,
        "active_probing": ALLOW_ACTIVE_PROBING,
        "active_scanning": ALLOW_ACTIVE_SCANNING,
        "automated_blocking": ALLOW_AUTOMATED_BLOCKING,
        "payload_decryption": ALLOW_PAYLOAD_DECRYPTION,
        "return_path": ALLOW_RETURN_PATH,
    }