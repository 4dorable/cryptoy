from math import (
    gcd,
)

from cryptoy.utils import (
    str_to_unicodes,
    unicodes_to_str,
)

# TP: Chiffrement affine


def compute_permutation(a: int, b: int, n: int) -> list[int]:
    result = []
    for i in range(n):
        result.append((a * i + b) % n)
    return result


def compute_inverse_permutation(a: int, b: int, n: int) -> list[int]:
    # A implémenter, pour cela on appelle perm = compute_permutation(a, b, n) et on calcule la permutation inverse
    # result qui est telle que: perm[i] == j implique result[j] == i
    perm = compute_permutation(a, b, n)
    result = [-1] * n
    for i, j in enumerate(perm):
        result[j] = i
    return result


def encrypt(msg: str, a: int, b: int) -> str:
    # A implémenter, en utilisant compute_permutation, str_to_unicodes et unicodes_to_str
    unicodes = str_to_unicodes(msg)
    perm = compute_permutation(a, b, 26)
    encrypted_unicodes = [perm[code -ord("A") + ord("A") if "A" <= chr(code)<= "Z" else code] for unicode in unicodes]
    encrypted_msg = unicodes_to_str(encrypted_unicodes)


    return encrypted_msg



def encrypt_optimized(msg: str, a: int, b: int) -> str:
    # A implémenter, sans utiliser compute_permutation
    result = ""
    for char in msg:
        if char.isalpha():
            char_code = ord(char)
            if char.islower():
                decrypted_code = (a * (char_code - ord("a")) + b) % 26 + ord("a")
            else:
                decrypted_code = (a * (char_code - ord("A")) + b) % 26 + ord("A")

            result += chr(decrypted_code)
        else:
            result += char
    return result



def decrypt_optimized(msg: str, a_inverse: int, b: int) -> str:
    # A implémenter, sans utiliser compute_inverse_permutation
    # On suppose que a_inverse a été précalculé en utilisant compute_affine_key_inverse, et passé
    # a la fonction
    decrypted_msg = ""
    for char in msg:
        if char.isalpha():
            char_code = ord(char)
            if char.islower():
                decrypted_code = (a_inverse * (char_code - ord("a") - b)) % 26 + ord("a")
            else:
                decrypted_code = (a_inverse * (char_code - ord("A") - b)) % 26 + ord("A")

            decrypted_msg += chr(decrypted_code)
        else:
            decrypted_msg += char
    return decrypted_msg


def compute_affine_keys(n: int) -> list[int]:
    # A implémenter, doit calculer l'ensemble des nombre a entre 1 et n tel que gcd(a, n) == 1
    # c'est à dire les nombres premiers avec n
    clefs = []
    for i in range(1, n):
        if gcd(i, n) == 1:
            clefs.append(i)
    return clefs


def compute_affine_key_inverse(a: int, affine_keys: list, n: int) -> int:
    # Trouver a_1 dans affine_keys tel que a * a_1 % N == 1 et le renvoyer
    # Placer le code ici (une boucle)
    for a_1 in affine_keys:
        if a * a_1 % n == 1:
            return a_1
    # Si a_1 n'existe pas, alors a n'a pas d'inverse, on lance une erreur:
    raise RuntimeError(f"{a} has no inverse")


def attack() -> tuple[str, tuple[int, int]]:
    s = "࠾ੵΚઐ௯ஹઐૡΚૡೢఊஞ௯\u0c5bૡీੵΚ៚Κஞїᣍફ௯ஞૡΚր\u05ecՊՊΚஞૡΚՊեԯՊ؇ԯրՊրր"
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg et b == 58

    # Placer le code ici
    aff_keys = compute_affine_keys(26)
    for a in aff_keys:
        a_inverse = compute_affine_key_inverse(a, aff_keys, 26)
        decrypted_msg = decrypt_optimized(s, a_inverse, 58)
        if "bombe" in decrypted_msg:
            return decrypted_msg, (a, b)

    raise RuntimeError("Failed to attack")


def attack_optimized() -> tuple[str, tuple[int, int]]:
    s = (
        "જഏ൮ൈ\u0c51ܲ೩\u0c51൛൛అ౷\u0c51ܲഢൈᘝఫᘝా\u0c51\u0cfc൮ܲఅܲᘝ൮ᘝܲాᘝఫಊಝ"
        "\u0c64\u0c64ൈᘝࠖܲೖఅܲఘഏ೩ఘ\u0c51ܲ\u0c51൛൮ܲఅ\u0cfc\u0cfcඁೖᘝ\u0c51"
    )
    # trouver msg, a et b tel que affine_cipher_encrypt(msg, a, b) == s
    # avec comme info: "bombe" in msg

    # Placer le code ici
    aff_keys = compute_affine_keys(26)
    for a in aff_keys:
        a_inverse = compute_affine_key_inverse(a, aff_keys, 26)
        decrypted_msg = decrypt_optimized(s, a_inverse, 58)

        if "bombe" in decrypted_msg:
            return decrypted_msg, (a, 58)

    raise RuntimeError("Failed to attack")

