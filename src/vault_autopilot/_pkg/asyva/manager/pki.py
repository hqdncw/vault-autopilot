from http import HTTPStatus
from typing import Any, NoReturn, NotRequired

import aiohttp
import pydantic
from typing_extensions import TypedDict, Unpack, override

from vault_autopilot._pkg.asyva.dto.pki_role import PKIRoleFields
from vault_autopilot._pkg.asyva.exc import IssuerNameTakenError, VaultAPIError

from ....util.model import model_dump_json
from .. import constants, dto
from ..dto import issuer
from .base import AbstractResult, BaseManager

__all__ = (
    "AbstractCertData",
    "GenerateIntmdCSRResult",
    "GenerateRootResult",
    "SignIntmdResult",
    "SetSignedIntmdResult",
    "IssuerUpdateResult",
    "IssuerReadResult",
)


GENERATE_QUERY_PARAMS = {"type", "mount_path"}


class AbstractCertData(TypedDict):
    expiration: int
    certificate: str
    issuing_ca: str
    serial_number: str


class GenerateIntmdCSRResult(AbstractResult):
    class Data(TypedDict):
        csr: str
        key_id: str
        private_key: NotRequired[pydantic.SecretStr]
        private_key_type: NotRequired[issuer.KeyType]

    data: Data


class GenerateRootResult(AbstractResult):
    class Data(TypedDict):
        issuer_id: str
        issuer_name: str
        key_id: str
        key_name: str

    data: Data


class SignIntmdResult(AbstractResult):
    class Data(AbstractCertData):
        ca_chain: list[str]

    data: Data


class SetSignedIntmdResult(AbstractResult):
    class Data(TypedDict):
        imported_issuers: NotRequired[list[str]]
        imported_keys: NotRequired[list[str]]
        mapping: NotRequired[dict[str, str]]
        existing_issuers: NotRequired[list[str]]
        existing_keys: NotRequired[list[str]]

    data: Data


class IssuerUpdateResult(AbstractResult):
    class Data(TypedDict):
        ca_chain: list[str]
        certificate: str
        issuer_id: str
        issuer_name: str
        key_id: str
        leaf_not_after_behavior: issuer.LeafNotAfterBehaviorType
        manual_chain: Any
        usage: issuer.UsageType
        revocation_signature_algorithm: NotRequired[issuer.SignatureAlgorithmType]
        issuing_certificates: NotRequired[list[str]]
        crl_distribution_points: NotRequired[list[str]]
        ocsp_servers: NotRequired[list[str]]

    data: Data

    @override
    @classmethod
    def from_response(cls, data: dict[Any, Any]) -> "IssuerUpdateResult":
        data["data"]["usage"] = data["data"]["usage"].split(",")
        return cls.model_construct(**data)


class IssuerReadResult(AbstractResult):
    class Data(IssuerUpdateResult.Data):
        revoked: bool

    data: Data


class RoleReadResult(AbstractResult):
    data: PKIRoleFields


async def raise_issuer_name_taken_exc(
    response: aiohttp.ClientResponse, name_collision: str, secrets_engine: str
) -> NoReturn:
    raise IssuerNameTakenError(
        "Issuer name {ctx[path_collision]!r} (secrets_engine: {ctx[mount_path]!r}) "
        "is already in use. Please choose a different name",
        ctx=IssuerNameTakenError.Context(
            **await VaultAPIError.compose_context(response),
            path_collision=name_collision,
            mount_path=secrets_engine,
        ),
    )


class PKIManager(BaseManager):
    async def generate_root(
        self, **payload: Unpack[dto.IssuerGenerateRootDTO]
    ) -> GenerateRootResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{mount_path}/issuers/generate/{issuer_type}/{cert_type}".format(
                    mount_path=payload["mount_path"],
                    issuer_type="root",
                    cert_type=payload["type"],
                ),
                data=model_dump_json(payload, exclude=GENERATE_QUERY_PARAMS),
            )

        result = await resp.json() or {}

        if resp.status == HTTPStatus.OK:
            return GenerateRootResult.from_response(result)

        for msg in result.get("errors", {}):
            if constants.ISSUER_NAME_TAKEN in msg:
                await raise_issuer_name_taken_exc(
                    resp,
                    name_collision=payload["issuer_name"],  # pyright: ignore[reportTypedDictNotRequiredAccess]
                    secrets_engine=payload["mount_path"],
                )

        raise await VaultAPIError.from_response("Failed to create root issuer", resp)

    async def generate_intmd_csr(
        self, **payload: Unpack[dto.IssuerGenerateIntmdCSRDTO]
    ) -> GenerateIntmdCSRResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{mount_path}/issuers/generate/{issuer_type}/{cert_type}".format(
                    mount_path=payload["mount_path"],
                    issuer_type="intermediate",
                    cert_type=payload["type"],
                ),
                data=model_dump_json(payload, exclude=GENERATE_QUERY_PARAMS),
            )

        result = await resp.json() or {}

        if resp.status == HTTPStatus.OK:
            return GenerateIntmdCSRResult.from_response(result)

        raise await VaultAPIError.from_response(
            "Failed to generate intermediate CSR", resp
        )

    async def sign_intmd(
        self, **payload: Unpack[dto.IssuerSignIntmdDTO]
    ) -> SignIntmdResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/issuer/%s/sign-intermediate"
                % (payload["mount_path"], payload["issuer_ref"]),
                data=model_dump_json(payload, exclude={"mount_path", "issuer_ref"}),
            )

        if resp.status == HTTPStatus.OK:
            return SignIntmdResult.from_response(await resp.json() or {})

        raise await VaultAPIError.from_response(
            "Failed to sign intermediate certificate", resp
        )

    async def set_signed_intmd(
        self, **payload: Unpack[dto.IssuerSetSignedIntmdDTO]
    ) -> SetSignedIntmdResult:
        """
        Set a signed intermediate certificate in Vault.
        """
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/intermediate/set-signed" % payload["mount_path"],
                json={"certificate": payload["certificate"]},
            )

        if resp.status == HTTPStatus.OK:
            return SetSignedIntmdResult.from_response(await resp.json() or {})

        raise await VaultAPIError.from_response(
            "Failed to set signed intermediate certificate", resp
        )

    async def update_key(self, **payload: Unpack[dto.KeyUpdateDTO]) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/key/%s" % (payload["mount_path"], payload["key_ref"]),
                json={"key_name": payload["key_name"]},
            )

        if resp.status == HTTPStatus.OK:
            return

        raise await VaultAPIError.from_response("Failed to update key", resp)

    async def update_issuer(
        self, **payload: Unpack[dto.IssuerUpdateDTO]
    ) -> IssuerUpdateResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/issuer/%s" % (payload["mount_path"], payload["issuer_ref"]),
                data=model_dump_json(payload, exclude={"mount_path", "issuer_ref"}),
            )

        result = await resp.json() or {}

        if resp.status == HTTPStatus.OK:
            return IssuerUpdateResult.from_response(result)

        for msg in result.get("errors", {}):
            if constants.ISSUER_NAME_TAKEN in msg:
                await raise_issuer_name_taken_exc(
                    resp,
                    name_collision=payload["issuer_name"],  # pyright: ignore[reportTypedDictNotRequiredAccess]
                    secrets_engine=payload["mount_path"],
                )

        raise await VaultAPIError.from_response("Failed to update Issuer", resp)

    async def update_or_create_role(
        self, **payload: Unpack[dto.PKIRoleCreateDTO]
    ) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/roles/%s" % (payload["mount_path"], payload["name"]),
                data=model_dump_json(payload, exclude={"mount_path", "name"}),
            )

        if resp.status == HTTPStatus.OK:
            return

        raise await VaultAPIError.from_response(
            "Failed to create/update pki role", resp
        )

    async def read_issuer(
        self, mount_path: str, issuer_ref: str
    ) -> IssuerReadResult | None:
        async with self.new_session() as sess:
            resp = await sess.get("/v1/%s/issuer/%s" % (mount_path, issuer_ref))

        result = await resp.json()

        if resp.status == HTTPStatus.OK:
            return IssuerReadResult.from_response(result)

        for msg in result.get("errors", {}):
            if constants.ISSUER_NOT_FOUND in msg:
                if not resp.status == HTTPStatus.INTERNAL_SERVER_ERROR:
                    continue

                return None

        raise await VaultAPIError.from_response("Failed to read issuer", resp)

    async def read_role(
        self, **payload: Unpack[dto.PKIRoleReadDTO]
    ) -> RoleReadResult | None:
        async with self.new_session() as sess:
            resp = await sess.get(
                "/v1/%s/roles/%s" % (payload["mount_path"], payload["name"]),
            )

        if resp.status == HTTPStatus.OK:
            return RoleReadResult.from_response(await resp.json() or {})

        if resp.status == HTTPStatus.NOT_FOUND:
            return

        raise await VaultAPIError.from_response("Failed to read pki role", resp)
