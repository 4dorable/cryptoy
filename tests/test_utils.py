from cryptoy.utils import (
    int_to_str,
    str_to_binary,
    str_to_binary_strings,
    str_to_int,
    str_to_unicodes,
    unicodes_to_str,
)


def test_str_to_unicodes() -> None:
    assert str_to_unicodes("Hello World") == [
        72,
        101,
        108,
        108,
        111,
        32,
        87,
        111,
        114,
        108,
        100,
    ]


def test_unicodes_to_str() -> None:
    assert (
        unicodes_to_str(
            [
                72,
                101,
                108,
                108,
                111,
                32,
                87,
                111,
                114,
                108,
                100,
            ]
        )
        == "Hello World"
    )


def test_str_to_binary_strings() -> None:
    assert str_to_binary_strings("Hello World") == [
        "01001000",
        "01100101",
        "01101100",
        "01101100",
        "01101111",
        "00100000",
        "01010111",
        "01101111",
        "01110010",
        "01101100",
        "01100100",
    ]


def test_str_to_binary() -> None:
    assert (
        str_to_binary("Hello World")
        == "0100100001100101011011000110110001101111001000000101011101101111011100100110110001100100"
    )


def test_str_to_int() -> None:
    assert str_to_int("Hello World") == 87521618088882533792115812


def test_int_to_str() -> None:
    assert int_to_str(87521618088882533792115812) == "Hello World"
