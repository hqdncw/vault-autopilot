from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from typing_extensions import override

from vault_autopilot.util.model import model_dump_json

from .. import dto
from .._pkg import asyva
from ..util.encoding import encode
from . import abstract


@dataclass(slots=True)
class SSHKeyService(abstract.VersionedSecretApplyMixin[dto.SSHKeyApplyDTO]):
    client: asyva.Client

    @override
    async def check_and_set(self, payload: dto.SSHKeyApplyDTO) -> None:
        """
        Performs `Check-and-Set` operation on a secret at path
        ``payload["spec"]["path"]``.

        Raises:
            CASParameterMismatchError: If the provided version does not match the
                current version of the secret or is not incremented by one.
        """
        spec = payload.spec

        match spec["key_options"]["type"]:
            case "rsa":
                key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=spec["key_options"].get("bits", 4096),
                )
            case "ec":
                key = ec.generate_private_key(
                    curve=ec._CURVE_TYPES[spec["key_options"]["curve"]]
                )
            case "ed25519":
                key = ed25519.Ed25519PrivateKey.generate()
            case _ as key:
                raise NotImplementedError(key)

        private_key, public_key = (
            spec.get("private_key", {}),
            spec.get("public_key", {}),
        )

        # may raise a CASParameterMismatchError
        _ = await self.client.update_or_create_kvv2_secret(
            path=spec["path"],
            data={
                private_key.get("private_key", "private_key"): encode(
                    key.private_bytes(
                        private_key.get("encoding", serialization.Encoding.PEM),
                        private_key.get("format", serialization.PrivateFormat.PKCS8),
                        serialization.NoEncryption(),
                    ),
                    encoding=spec["encoding"],
                ),
                public_key.get("public_key", "public_key"): encode(
                    key.public_key().public_bytes(
                        public_key.get("encoding", serialization.Encoding.OpenSSH),
                        public_key.get("format", serialization.PublicFormat.OpenSSH),
                    ),
                    encoding=spec["encoding"],
                ),
            },
            cas=spec["version"] - 1,
            mount_path=spec["secrets_engine_path"],
        )
        _ = await self.client.update_or_create_metadata(
            mount_path=spec["secrets_engine_path"],
            path=spec["path"],
            custom_metadata={self.SNAPSHOT_LABEL: model_dump_json(payload)},
        )
