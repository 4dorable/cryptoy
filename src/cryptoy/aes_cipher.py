from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)


def encrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    cypher_text = aesgcm.encrypt(nonce, msg, None)
    return cypher_text

def decrypt(msg: bytes, key: bytes, nonce: bytes) -> bytes:
    # A implémenter en utilisant la class AESGCM
    aesgcm = AESGCM(key)
    plain_text = aesgcm.decrypt(nonce, msg, None)
    return plain_text

