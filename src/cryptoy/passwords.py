import hashlib
import os
from random import (
    Random,
)

import names


def hash_password(password: str) -> str:
    return hashlib.sha3_256(password.encode()).hexdigest()


def random_salt() -> str:
    return bytes.hex(os.urandom(32))


def generate_users_and_password_hashes(
    passwords: list[str], count: int = 32
) -> dict[str, str]:
    rng = Random()  # noqa: S311

    users_and_password_hashes = {
        names.get_full_name(): hash_password(rng.choice(passwords))
        for _i in range(count)
    }
    return users_and_password_hashes


def attack(passwords: list[str], passwords_database: dict[str, str]) -> dict[str, str]:
    users_and_passwords = {}

    # A implémenter
    # Doit calculer le mots de passe de chaque utilisateur grace à une attaque par dictionnaire

    hashed_passwords = {}

    for password in passwords:
        hashed_passwords[hash_password(password)] = password

    for user, password_hash in passwords_database.items():
        users_and_passwords[user] = hashed_passwords[password_hash]

    return users_and_passwords


def fix(
    passwords: list[str], passwords_database: dict[str, str]
) -> dict[str, dict[str, str]]:
    users_and_passwords = attack(passwords, passwords_database)

    users_and_salt = {}
    new_database = {}

    users_and_salt = {}
    new_database = {}

    for user, password in users_and_passwords.items():
        salt = random_salt()
        hashed_password = hash_password(salt + password)
        users_and_salt[user] = salt
        new_database[user] = {"password_hash": hashed_password, "password_salt": salt}

    return new_database


def authenticate(
    user: str, password: str, new_database: dict[str, dict[str, str]]
) -> bool:
    # Doit renvoyer True si l'utilisateur a envoyé le bon password, False sinon
    if user in new_database:
        user_data = new_database[user]
        hashed_password = hash_password(user_data["password_salt"] + password)
        return hashed_password == user_data["password_hash"]

    return False

