from typing import Annotated, Literal, NotRequired

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
)
from pydantic import Field
from typing_extensions import TypedDict

from .abstract import AbstractDTO, VersionedSecretApplyDTO

EllipticCurve = Literal[
    "prime192v1",
    "prime256v1",
    # "secp192r1",
    # "secp224r1",
    "secp256r1",
    "secp384r1",
    "secp521r1",
    # "secp256k1",
    # "sect163k1",
    # "sect233k1",
    # "sect283k1",
    # "sect409k1",
    # "sect571k1",
    # "sect163r2",
    # "sect233r1",
    # "sect283r1",
    # "sect409r1",
    # "sect571r1",
    # "brainpoolP256r1",
    # "brainpoolP384r1",
    # "brainpoolP512r1",
]


class AbstractKey(TypedDict):
    secret_key: NotRequired[str]
    encoding: NotRequired[Encoding]


class PublicKey(AbstractKey):
    format: NotRequired[PublicFormat]


class PrivateKey(AbstractKey):
    format: NotRequired[PrivateFormat]
    # encryption: NotRequired[Encryption]


class RSAOptions(TypedDict):
    type: Literal["rsa"]
    bits: NotRequired[int]


class ECOptions(TypedDict):
    type: Literal["ec"]
    # https://safecurves.cr.yp.to/
    curve: EllipticCurve


class ED25519Options(TypedDict):
    type: Literal["ed25519"]


class SSHKeyApplyDTO(VersionedSecretApplyDTO):
    model_config = {**AbstractDTO.model_config, "arbitrary_types_allowed": True}

    class Spec(VersionedSecretApplyDTO.Spec):
        key_options: Annotated[
            RSAOptions | ECOptions | ED25519Options, Field(discriminator="type")
        ]
        public_key: NotRequired[PublicKey]
        private_key: NotRequired[PrivateKey]

    kind: Literal["SSHKey"] = "SSHKey"
    spec: Spec

    def absolute_path(self) -> str:
        return "/".join((self.spec["secrets_engine"], self.spec["path"]))
