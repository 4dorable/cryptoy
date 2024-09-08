import random
from math import (
    ceil,
)


def str_to_unicodes(s: str) -> list[int]:
    return [ord(char) for char in s]


def unicodes_to_str(codes: list[int]) -> str:
    return "".join([chr(code) for code in codes])


def bytes_to_binary_strings(bytes_: bytes) -> list[str]:
    return [f"{b:08b}" for b in bytes_]


def str_to_binary_strings(s: str) -> list[str]:
    return bytes_to_binary_strings(s.encode())


def concat_binary_strings(byte_strings: list[str]) -> str:
    return "".join(byte_strings)


def str_to_binary(s: str) -> str:
    return concat_binary_strings(str_to_binary_strings(s))


def str_to_int(s: str) -> int:
    return int(str_to_binary(s), 2)


def split_binary_strings(s: str) -> list[str]:
    return [s[i : i + 8] for i in range(0, len(s), 8)]


def binary_strings_to_bytes(bytes_: list[str]) -> bytes:
    return bytes([int(c, 2) for c in bytes_])


def bytes_to_str(bytes_: bytes) -> str:
    return bytes(bytes_).decode()


def int_to_binary(value: int) -> str:
    s = f"{value:b}"
    size = ceil(len(s) / 8) * 8
    return f"{s:0>{size}}"


def int_to_str(value: int) -> str:
    return bytes_to_str(
        binary_strings_to_bytes(split_binary_strings(int_to_binary(value)))
    )


# Fast modular exponent: (b ** e) % m
def pow_mod(b: int, e: int, m: int) -> int:
    if e == 0:
        return 1
    elif e == 1:
        return b % m
    else:
        root = pow_mod(b, e // 2, m)
        if e % 2 == 0:
            return (root * root) % m
        else:
            return (root * root * b) % m


def miller_rabin(n: int, k: int) -> bool:
    # Implementation uses the Miller-Rabin Primality Test
    # The optimal number of rounds for this test is 40
    # See http://stackoverflow.com/questions/6325576/how-many-iterations-of-rabin-miller-should-i-use-for-cryptographic-safe-primes
    # for justification
    # If number is even, it's a composite number

    if n == 2 or n == 3:
        return True

    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def draw_random_prime(
    min: int = 2**1023, max: int = 2**1024
) -> (
    int
):  # source for RSA prime lengths: https://crypto.stackexchange.com/questions/22971/what-prime-lengths-are-used-for-rsa
    while True:
        p = (2 * random.randint(min, max) + 1) % max
        fermat_test = pow_mod(2, p - 1, p)
        if fermat_test != 1:
            continue
        if miller_rabin(p, 40):
            return p


def modular_inverse(a: int, n: int) -> int:
    t = 0
    newt = 1
    r = n
    newr = a

    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr

    if r > 1:
        raise RuntimeError("a not invertible")
    if t < 0:
        t = t + n

    return t
