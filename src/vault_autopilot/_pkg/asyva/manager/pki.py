import http
import logging
from typing import Any, NoReturn, NotRequired, Optional

import pydantic
from typing_extensions import TypedDict

from .... import util
from .. import constants, dto, exc
from ..dto import issuer
from . import base

__all__ = (
    "AbstractCertData",
    "GenerateIntmdCSRResult",
    "GenerateRootResult",
    "SignIntmdResult",
    "SetSignedIntmdResult",
    "UpdateResult",
    "GetResult",
)


logger = logging.getLogger(__name__)


GENERATE_QUERY_PARAMS = {"type_", "mount_path"}


class AbstractCertData(TypedDict):
    expiration: int
    certificate: str
    issuing_ca: str
    serial_number: str


class GenerateIntmdCSRResult(base.AbstractResult):
    class Data(TypedDict):
        csr: str
        key_id: str
        private_key: NotRequired[pydantic.SecretStr]
        private_key_type: NotRequired[issuer.KeyType]

    data: Data


class GenerateRootResult(base.AbstractResult):
    class Data(TypedDict):
        issuer_id: str
        issuer_name: str
        key_id: str
        key_name: str

    data: Data


class SignIntmdResult(base.AbstractResult):
    class Data(AbstractCertData):
        ca_chain: list[str]

    data: Data


class SetSignedIntmdResult(base.AbstractResult):
    class Data(TypedDict):
        imported_issuers: NotRequired[list[str]]
        imported_keys: NotRequired[list[str]]
        mapping: NotRequired[dict[str, str]]
        existing_issuers: NotRequired[list[str]]
        existing_keys: NotRequired[list[str]]

    data: Data


class UpdateResult(base.AbstractResult):
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

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "UpdateResult":
        data["data"]["usage"] = data["data"]["usage"].split(",")
        return cls.model_construct(**data)


class GetResult(base.AbstractResult):
    class Data(UpdateResult.Data):
        revoked: bool

    data: Data


def raise_issuer_name_taken_exc(issuer_name: str, mount_path: str) -> NoReturn:
    raise exc.IssuerNameTakenError(
        "Issuer name {issuer_name!r} (secret_engine: {secret_engine!r}) is "
        "already in use. Please choose a different name",
        ctx=exc.IssuerNameTakenError.Context(
            issuer_name=issuer_name,
            secret_engine=mount_path,
        ),
    )


class PKIManager(base.BaseManager):
    async def generate_root(
        self,
        payload: dto.IssuerGenerateRootDTO,
    ) -> GenerateRootResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{mount_path}/issuers/generate/{issuer_type}/{cert_type}".format(
                    mount_path=payload["mount_path"],
                    issuer_type="root",
                    cert_type=payload["type_"],
                ),
                data=util.model.model_dump_json(payload, exclude=GENERATE_QUERY_PARAMS),
            )

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return GenerateRootResult.from_response(result)

        if constants.ISSUER_NAME_TAKEN in result["errors"]:
            raise_issuer_name_taken_exc(
                issuer_name=payload[
                    "issuer_name"
                ],  # pyright: ignore[reportTypedDictNotRequiredAccess]
                mount_path=payload["mount_path"],
            )

        logger.debug(result)

        raise await exc.VaultAPIError.from_response(
            "Failed to create root issuer", resp
        )

    async def generate_intmd_csr(
        self, payload: dto.IssuerGenerateIntmdCSRDTO
    ) -> GenerateIntmdCSRResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{mount_path}/issuers/generate/{issuer_type}/{cert_type}".format(
                    mount_path=payload["mount_path"],
                    issuer_type="intermediate",
                    cert_type=payload["type_"],
                ),
                data=util.model.model_dump_json(payload, exclude=GENERATE_QUERY_PARAMS),
            )

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return GenerateIntmdCSRResult.from_response(result)

        logger.debug(await resp.json())

        raise await exc.VaultAPIError.from_response(
            "Failed to generate intermediate CSR", resp
        )

    async def sign_intmd(self, payload: dto.IssuerSignIntmdDTO) -> SignIntmdResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/issuer/%s/sign-intermediate"
                % (payload["mount_path"], payload["issuer_ref"]),
                data=util.model.model_dump_json(
                    payload, exclude={"mount_path", "issuer_ref"}
                ),
            )

        if resp.status == http.HTTPStatus.OK:
            return SignIntmdResult.from_response(await resp.json())

        logger.debug(await resp.json())

        raise await exc.VaultAPIError.from_response(
            "Failed to sign intermediate certificate", resp
        )

    async def set_signed_intmd(
        self, payload: dto.IssuerSetSignedIntmdDTO
    ) -> SetSignedIntmdResult:
        """
        Set a signed intermediate certificate in Vault.
        """
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/intermediate/set-signed" % payload["mount_path"],
                json={"certificate": payload["certificate"]},
            )

        if resp.status == http.HTTPStatus.OK:
            return SetSignedIntmdResult.from_response(await resp.json())

        logger.debug(await resp.json())

        raise await exc.VaultAPIError.from_response(
            "Failed to set signed intermediate certificate", resp
        )

    async def update_key(self, payload: dto.KeyUpdateDTO) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/key/%s" % (payload["mount_path"], payload["key_ref"]),
                json={"key_name": payload["key_name"]},
            )

        if resp.status == http.HTTPStatus.OK:
            return

        logger.debug(await resp.json())

        raise await exc.VaultAPIError.from_response("Failed to update key", resp)

    async def update_issuer(self, payload: dto.IssuerUpdateDTO) -> UpdateResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/issuer/%s" % (payload["mount_path"], payload["issuer_ref"]),
                data=util.model.model_dump_json(
                    payload, exclude={"mount_path", "issuer_ref"}
                ),
            )

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return UpdateResult.from_response(result)

        if constants.ISSUER_NAME_TAKEN in result["errors"]:
            raise_issuer_name_taken_exc(
                issuer_name=payload[
                    "issuer_name"
                ],  # pyright: ignore[reportTypedDictNotRequiredAccess]
                mount_path=payload["mount_path"],
            )

        logger.debug(result)

        raise await exc.VaultAPIError.from_response("Failed to update Issuer", resp)

    async def update_or_create_role(self, payload: dto.PKIRoleCreateDTO) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/roles/%s" % (payload["mount_path"], payload["issuer_ref"]),
                data=util.model.model_dump_json(
                    payload, exclude={"mount_path", "issuer_ref"}
                ),
            )

        if resp.status == http.HTTPStatus.OK:
            return

        logger.debug(await resp.json())

        raise await exc.VaultAPIError.from_response(
            "Failed to create/update pki role", await resp.json()
        )

    async def get_issuer(self, payload: dto.IssuerGetDTO) -> Optional[GetResult]:
        async with self.new_session() as sess:
            resp = await sess.get(
                "/v1/%s/issuer/%s" % (payload["mount_path"], payload["issuer_ref"])
            )

        result = await resp.json()

        if resp.status == http.HTTPStatus.OK:
            return GetResult.from_response(result)
        elif (
            resp.status == http.HTTPStatus.INTERNAL_SERVER_ERROR
            and constants.ISSUER_NOT_FOUND in result["errors"][0]
        ):
            return None

        logger.debug(await resp.json())

        raise await exc.VaultAPIError.from_response("Failed to get issuer", resp)
