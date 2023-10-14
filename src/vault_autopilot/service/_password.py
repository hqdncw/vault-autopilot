import base64
import secrets
import string
from dataclasses import dataclass

from .. import dto
from .._pkg import asyva
from . import _abstract

CHAR_SET = (
    string.ascii_lowercase + string.ascii_uppercase + string.digits + string.punctuation
)
CHAR_SET_NO_SPECIALS = string.ascii_lowercase + string.ascii_uppercase + string.digits


def rand(len_: int, use_specials: bool) -> str:
    """
    Generates a random password of given length.

    Args:
        use_specials (bool): Whether to include special characters in the password.

    Returns:
        str: A randomly generated password
    """
    return "".join(
        secrets.choice(CHAR_SET if use_specials else CHAR_SET_NO_SPECIALS)
        for _ in range(len_)
    )


def b64encode(input: str) -> str:
    """Encodes given string to base64."""
    return base64.b64encode(input.encode()).decode()


def encode(value: str, encoding: str) -> str:
    match encoding:
        case "base64":
            return b64encode(value)
        case "utf8":
            return value
        case _:
            raise NotImplementedError()


@dataclass(frozen=True, slots=True)
class PasswordService(_abstract.Service):
    client: asyva.Client

    async def push(self, payload: dto.BaseDTO) -> None:
        assert isinstance(payload, dto.PasswordDTO), (
            "Expected PasswordDTO, got %r" % payload
        )
        await self.client.create_or_update_secret(
            path=payload.spec.path,
            data={
                payload.spec.secret_keys.secret_key: encode(
                    # TODO: generate value using Vault Password Policy API
                    #  https://developer.hashicorp.com/vault/docs/concepts/password-policies
                    value=rand(
                        len_=payload.spec.length, use_specials=payload.spec.use_specials
                    ),
                    encoding=payload.spec.encoding,
                )
            },
            cas=payload.spec.cas,
            mount_path=payload.spec.mount,
        )
