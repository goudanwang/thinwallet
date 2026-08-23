from __future__ import annotations

import secrets

from common import hash_to_field


DOMAIN = "phase2c-setup-check-v1"


def new_client_nonce() -> str:
    return secrets.token_hex(32)


def alpha_i(manifest_digest: str, client_nonce: str, check_round: int, index: int) -> int:
    return hash_to_field(DOMAIN, manifest_digest, client_nonce, check_round, index)

