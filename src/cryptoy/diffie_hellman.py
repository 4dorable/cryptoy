import random
import sys

from cryptoy.utils import (
    pow_mod,
)

sys.setrecursionlimit(5000)  # Required for pow_mod for large exponents


def keygen(prime_number: int, generator: int) -> dict[str, int]:
    # Implementez la generation de clef de diffie hellman
    # 1. Tire aléatoirement un nombre secret private_key entre 2 et prime_number - 1 inclus avec random.randint(min, max)
    # 2. Calcule la clef publique public_key = generator ** private_key % prime_number; utiliser la fonction pow_mod
    # 3. Renvoit le dictionnaitre {"public_key": A, "private_key": a}
    private_key = random.randint(2, prime_number - 1)
    public_key = pow_mod(generator, private_key, prime_number)
    return {"public_key": public_key, "private_key": private_key}


def compute_shared_secret_key(public: int, private: int, prime_number: int) -> int:
    # Implementer le calcul de la clef secrete partagée à partir de la clef publique de l'autre participant et de ma clef privée
    # Utiliser pow_mod
    shared_secret_key = pow_mod(public, private, prime_number)
    return shared_secret_key
