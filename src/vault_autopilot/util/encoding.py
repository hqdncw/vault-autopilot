from base64 import encodebytes
from typing import Literal

Encoding = Literal["base64", "utf8"]


def encode(value: bytes, encoding: Encoding) -> str:
    match encoding:
        case "base64":
            return encodebytes(value).decode("utf-8")
        case "utf8":
            return value.decode("utf-8")
