from math import (
    gcd,
)

from cryptoy.utils import (
    draw_random_prime,
    int_to_str,
    modular_inverse,
    pow_mod,
    str_to_int,
)


def keygen() -> dict:
    e = 65537
    # Implementez la génération de clef de RSA avec e = 65537
    # 1. Tire aléatoirement un nombre premier p avec la fonction draw_random_prime
    # 2. Tire aléatoirement un nombre premier q avec la fonction draw_random_prime
    # 3. Calcul de d, l'inverse de e modulo (p - 1) * (q - 1), avec la fonction modular_inverse
    # 4. Renvoit un dictionnaire { "public_key": (e, p * q), "private_key": d}
    p = draw_random_prime()
    q = draw_random_prime()
    n = p * q
    d = modular_inverse(e, (p - 1) * (q - 1))
    return {"public_key": (e, n), "private_key": d}


def encrypt(msg: str, public_key: tuple) -> int:
    # Implementez le chiffrement rsa d'un message avec une clef publique de la forme (e, N)
    # 1. Convertir le message en nombre entier avec la fonction str_to_int
    # 2. Verifiez que ce nombre est < public_key[1], sinon lancer une exception
    # 3. Chiffrez le nombre entier avec pow_mod et les paramètre de la clef publique (e, N)
    msg_int = str_to_int(msg)
    if msg_int >= public_key[1]:
        raise ValueError("Message too large")
    encrypted_msg = pow_mod(msg_int, public_key[0], public_key[1])
    return encrypted_msg


def decrypt(msg: int, key: dict) -> str:
    # Implementez le dechiffrement rsa d'un message avec une clef de la forme { "public_key": (e, p * q), "private_key": d}
    # 1. Utilisez pow_mod avec les paramètres de la clef
    # 2. Convertir l'entier calculé en str avec la fonction int_to_str
    decrypted_msg_int = pow_mod(msg, key["private_key"], key["public_key"][1])
    decrypted_msg = int_to_str(decrypted_msg_int)
    return decrypted_msg
