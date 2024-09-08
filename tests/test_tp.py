# -*- coding: utf-8 -*-
import hashlib
import json
import secrets
from base64 import (
    urlsafe_b64encode,
)
from pathlib import (
    Path,
)
from secrets import (
    token_bytes,
)

from cryptography.fernet import (
    Fernet,
)
from cryptography.hazmat.primitives.ciphers.aead import (
    AESGCM,
)

from cryptoy import (
    aes_cipher,
    affine_cipher,
    caesar_cipher,
    diffie_hellman,
    passwords,
    rsa_cipher,
)
from cryptoy.utils import (
    binary_strings_to_bytes,
    int_to_binary,
    split_binary_strings,
)


def test_caesar_cipher() -> None:
    assert caesar_cipher.encrypt("Hello", 1234) == "ԚԷԾԾՁ"
    assert caesar_cipher.decrypt("ԚԷԾԾՁ", 1234) == "Hello"

    msg = "C@€s4r Ciph€r"
    assert caesar_cipher.decrypt(caesar_cipher.encrypt(msg, 4321), 4321) == msg


def test_attack_caesar_cipher() -> None:
    msg, shift = caesar_cipher.attack()
    assert (
        hashlib.sha512(msg.encode()).hexdigest()
        == "f6ce4890442ffa3f10f058bf1b3a49e6af216ea7eb90d77ca2953166bbaca64d25778741ca8d8a85313b574efbcce408ffdccfb70a31f1fe3fc6cde12f2c3ff1"
    )
    assert (
        hashlib.sha512(str(shift).encode()).hexdigest()
        == "a608f13bdb51d8cf6cb3898a02209e46f378968bf1b493b91f1373e58d9d1064456b35b48d003e1782471856b9e194b96741139cb0c0355300e4c43702a8a44a"
    )


def test_affine_cypher_permutation() -> None:
    assert affine_cipher.compute_permutation(2, 2, 5) == [2, 4, 1, 3, 0]
    assert affine_cipher.compute_inverse_permutation(2, 2, 5) == [4, 2, 0, 3, 1]


def test_affine_cipher() -> None:
    key = 13
    assert affine_cipher.encrypt("Hello", key, 1234) == "ࡺ৳\u0a4e\u0a4eੵ"
    assert affine_cipher.decrypt("ࡺ৳\u0a4e\u0a4eੵ", key, 1234) == "Hello"

    msg = "C@€s4r Ciph€r"
    assert (
        affine_cipher.decrypt(affine_cipher.encrypt(msg, key, 4321), key, 4321) == msg
    )

    tp_key = 1114111
    assert (
        hashlib.sha256(
            affine_cipher.decrypt_optimized(
                "ґѦѦҲљѣѝѠҲѰѱџѭҲѱѠѭҲѰѭѦѣѤѫҲўѣҲѝџ", tp_key, 1234
            ).encode()
        ).hexdigest()
        == "c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d"
    )


def test_affine_cipher_optimized() -> None:
    key = 13
    assert affine_cipher.encrypt_optimized("Hello", key, 1234) == "ࡺ৳\u0a4e\u0a4eੵ"
    affine_keys = affine_cipher.compute_affine_keys(0x110000)
    key_inverse = affine_cipher.compute_affine_key_inverse(key, affine_keys, 0x110000)
    assert (
        affine_cipher.decrypt_optimized(
            "ࡺ৳\u0a4e\u0a4eੵ",
            key_inverse,
            1234,
        )
        == "Hello"
    )
    msg = "C@€s4r Ciph€r"
    assert (
        affine_cipher.decrypt_optimized(
            affine_cipher.encrypt_optimized(msg, 13, 4321), key_inverse, 4321
        )
        == msg
    )

    tp_key = 1114111
    tp_key_inverse = affine_cipher.compute_affine_key_inverse(
        tp_key, affine_keys, 0x110000
    )
    assert (
        hashlib.sha256(
            affine_cipher.decrypt_optimized(
                "ґѦѦҲљѣѝѠҲѰѱџѭҲѱѠѭҲѰѭѦѣѤѫҲўѣҲѝџ", tp_key_inverse, 1234
            ).encode()
        ).hexdigest()
        == "c46ec1b18ce8a878725a37e780dfb7351f68ed2e194c79fbc6aebee1a667975d"
    )


def test_attack_affine_cipher() -> None:
    msg, key = affine_cipher.attack()
    assert (
        hashlib.sha512(msg.encode()).hexdigest()
        == "bfc9718f1ac2bbe716d8b0c63e00cf953bead753ac70289f40107d5245a229f00bf11811a03c6bb3df2b74d23f766079b5b01c37e88498921c23e90b9f0d4dac"
    )
    assert (
        hashlib.sha512(str(key).encode()).hexdigest()
        == "88954726b584f187e961271994e90fdef8cda28466d51c69b2c43b0a114114ef07837af1a75a9e02ea80697cb0d2397268016c72335b3140b8f47b635a368173"
    )


def test_attack_affine_cipher_optimized() -> None:
    msg, key = affine_cipher.attack_optimized()
    assert (
        hashlib.sha512(msg.encode()).hexdigest()
        == "3b9923eeed436f0a269bc80289e6ddc4d5db70d0f2ccbf15d1827298d2cb914b84bdbeac9c0042b809ba67b63a74bb7c6a86895f6ab5fb541d50506bdce44dd7"
    )
    assert (
        hashlib.sha512(str(key).encode()).hexdigest()
        == "67f0ae7eff1e8c6f9a6c5495719936b5a50b4136460b9b95132ba16d21705ccea2ac686344e5c3860450453316d7728b02bf40c547496fe0e5bab481072505ec"
    )


def load_passwords_data() -> tuple[list[str], dict[str, str]]:
    passwords_list = (
        (Path(__file__).parent / "data" / "2151220-passwords.txt")
        .read_text()
        .splitlines()
    )
    passwords_database = json.loads(
        (Path(__file__).parent / "data" / "passwords-database.json").read_text()
    )
    return passwords_list, passwords_database


def test_passwords_attack() -> None:
    passwords_list, passwords_database = load_passwords_data()

    users_and_passwords = passwords.attack(passwords_list, passwords_database)
    for user in passwords_database:
        assert user in users_and_passwords
    for user, password in users_and_passwords.items():
        assert passwords.hash_password(password) == passwords_database[user]


def test_passwords_fix() -> None:
    passwords_list, passwords_database = load_passwords_data()

    new_database = passwords.fix(passwords_list, passwords_database)
    for user in passwords_database:
        assert user in new_database
    for user, password_hash_and_salt in new_database.items():
        assert "password_hash" in password_hash_and_salt
        assert "password_salt" in password_hash_and_salt
        assert user in passwords_database

    assert passwords.authenticate("James Barrows", "94220254", new_database) is True
    assert passwords.authenticate("Blanca Kimmel", "crazydave6", new_database) is True
    assert passwords.authenticate("Cindy Zink", "loveyou77", new_database) is False


def test_aes() -> None:
    msg = b'\xd0\x8d)%\x18QnD\xf9\x9c\xc7(\x1a\x85\xc3t\xf3\xc4\x92"\x1ahB\xf9\xfb\xa1\xc1]\xee\xf0\xda\xbcd\x9d: ?\xb8\xe1\xb4{\x87\n2'
    nonce = b"\xfa}_\xe1\x9cN\x0cz/\xebNt"
    key = b"allyourbasearebelongtous"
    decrypted_msg = aes_cipher.decrypt(msg, key, nonce)
    print(decrypted_msg)
    assert (
        "75519e379b872fd71a6073ee1891dfeb70e2ce24030567ad1b86a92bbac9a4f98d994544561c1970c9459aa5cdf6ff9e1182e8e7a729709696726061f047e52f"
        == hashlib.sha512(decrypted_msg).hexdigest()
    )

    nonce = token_bytes(16)
    assert (
        aes_cipher.decrypt(aes_cipher.encrypt(b"Hello World", key, nonce), key, nonce)
        == b"Hello World"
    )


def test_diffie_hellman() -> None:
    prime_number = 32317006071311007300153513477825163362488057133489075174588434139269806834136210002792056362640164685458556357935330816928829023080573472625273554742461245741026202527916572972862706300325263428213145766931414223654220941111348629991657478268034230553086349050635557712219187890332729569696129743856241741236237225197346402691855797767976823014625397933058015226858730761197532436467475855460715043896844940366130497697812854295958659597567051283852132784468522925504568272879113720098931873959143374175837826000278034973198552060607533234122603254684088120031105907484281003994966956119696956248629032338072839127039
    generator = 2

    # Alice génère ses clefs publique et privée
    alice_keys = diffie_hellman.keygen(prime_number, generator)
    print("Alice", alice_keys)

    # Bob génère ses clefs publique et privée
    bob_keys = diffie_hellman.keygen(prime_number, generator)
    print("Bob", bob_keys)

    # Alice transfère sa clef publique à Bob, qui calcule la clef secrète partagée en combinant les deux
    bob_side_shared_key = diffie_hellman.compute_shared_secret_key(
        alice_keys["public_key"], bob_keys["private_key"], prime_number
    )

    # Bob transfère sa clef publique à Alice, qui calcule la clef secrète partagée en combinant les deux
    alice_side_shared_key = diffie_hellman.compute_shared_secret_key(
        bob_keys["public_key"], alice_keys["private_key"], prime_number
    )

    print("Bob compute shared key: ", bob_side_shared_key)
    print("Alice compute shared key: ", alice_side_shared_key)

    # La clef secrète doit être la même des deux coté
    assert bob_side_shared_key == alice_side_shared_key

    # Exemple d'échange de messages chiffrés en utilisant la clef:

    # On commence par convertir la clef (un nombre entier) en bytes
    diffie_hellman_key = bytes(
        binary_strings_to_bytes(
            split_binary_strings(int_to_binary(alice_side_shared_key))
        )
    )

    # Premier exemple: en utilisant un chiffrage de type Fernet

    fernet_key = urlsafe_b64encode(diffie_hellman_key)[:43] + b"="
    print("Fernet key: ", fernet_key)

    f = Fernet(fernet_key)
    encrypted_msg_from_alice = f.encrypt(b"Hello Bob !")
    print(f"Bob received: {encrypted_msg_from_alice.decode()}")
    decrypted_from_bob = f.decrypt(encrypted_msg_from_alice)
    print(f"Bob decrypted: {decrypted_from_bob.decode()}")

    # Deuxième exemple: en utilisant un chiffrage de type AES

    # About AES with cryptography module: https://stackoverflow.com/questions/36117046/cryptography-module-is-fernet-safe-and-can-i-do-aes-encryption-with-that-module
    # AES-GCM: https://www.aes-gcm.com/

    aes_key = diffie_hellman_key[:32]  # AES256 needs 32 bytes
    aes = AESGCM(aes_key)

    nonce = secrets.token_bytes(12)  # GCM mode needs 12 fresh bytes every time
    ciphertext = nonce + aes.encrypt(nonce, b"Hello Bob !", b"")
    print(ciphertext)

    # Decrypt (raises InvalidTag if using wrong key or corrupted ciphertext)
    msg = aes.decrypt(ciphertext[:12], ciphertext[12:], b"")
    print(msg)


def test_rsa() -> None:
    key = rsa_cipher.keygen()
    assert (
        rsa_cipher.decrypt(rsa_cipher.encrypt("Hello World", key["public_key"]), key)
        == "Hello World"
    )


def test_rsa_decrypt() -> None:
    the_key = {
        "public_key": (
            65537,
            5160258950707004527433623694972158618124318233517473047143553795491940821509623478999918620803781490217484710013203990920469036477279549580526508159601864388073082079512341058264577952562685541104181983806385199170060477093723804132167472821471700912412626406630441429793392837273636598268817240946497506820181915787509671527530995465765189468225857652273536564402340541728949333875068519127712897006118486068587904480131024032316438716419790315599017159081820735583525204106378011177934323267819214343749323750085324401804369000005522035908418807110114718039261271305886368333912351391303836457593948335395855507583,
        ),
        "private_key": 627936358574368083773794176837556875956199366957624663182169484704033264439007694051060484930804848932426576778847091377248585774544217890728884486211222187388541275678027983271434596818399029407904715212107999502284698793390715747654540118577853956947841609974179019524883773704277764792313006340667372886909680395607160112990863561229594521434907523415894476610812782204805233492229679822906086298065600687219804109153860239235505216857720372348199986727139109826857982310524023571110322296236136269506896654238646838784117269757980736109840900745065339439594650937314449703712101022601412396454202821492505234473,
    }

    cipher_text = 602615695538398865986103808888324609946059458992453782893761508370364126434765480745925456008311110097781088480248720248090596169378272945034170486888633924019689244629365827705143735859884159481048823046306550922413690593957216042187301328427358353776920173019807815522432899231960604161765261470093563432833290945028180426672801670399260070325291950555331382320004409327959232953037211763370983500859883074329273915004363416303271902383762493068939220935480452285519833077108260421677790570729682150610949840577977481271582539442140105973442786832608699078905470007784090128822980202327104900727766440040286840010

    text = rsa_cipher.decrypt(cipher_text, the_key)
    assert (
        hashlib.sha512(text.encode()).hexdigest()
        == "15dd2240ad8384ade2e745efba3f7849a520920e6a10b4cdf6c2568f592a9ce11f40edfe177be75b6616754449ae0d2ecda57f0dda9e98cf35e6fda6985c1469"
    )
