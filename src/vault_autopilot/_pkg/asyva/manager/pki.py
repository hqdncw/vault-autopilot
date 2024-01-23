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
    "AbstractResult",
    "AbstractCertData",
    "GenerateIntmdCSRResult",
    "GenerateRootResult",
    "SignIntmdResult",
    "SetSignedIntmdResult",
    "UpdateResult",
)


logger = logging.getLogger(__name__)


GENERATE_QUERY_PARAMS = {"type_", "mount_path"}


class AbstractResult(pydantic.BaseModel):
    request_id: str
    lease_id: str
    renewable: bool
    lease_duration: int
    auth: Any
    wrap_info: Any
    warnings: Optional[list[str]] = None


class AbstractCertData(TypedDict):
    expiration: int
    certificate: str
    issuing_ca: str
    serial_number: str


class GenerateIntmdCSRResult(AbstractResult):
    data: "Data"

    class Data(TypedDict):
        csr: str
        key_id: str
        private_key: NotRequired[pydantic.SecretStr]
        private_key_type: NotRequired[issuer.KeyType]

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "GenerateIntmdCSRResult":
        return cls.model_construct(**data)


class GenerateRootResult(AbstractResult):
    data: "Data"

    class Data(TypedDict):
        issuer_id: str
        issuer_name: str
        key_id: str
        key_name: str

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "GenerateRootResult":
        return cls.model_construct(**data)


class SignIntmdResult(AbstractResult):
    data: "Data"

    class Data(AbstractCertData):
        ca_chain: list[str]

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "SignIntmdResult":
        return cls.model_construct(**data)


class SetSignedIntmdResult(AbstractResult):
    data: "Data"

    class Data(TypedDict):
        imported_issuers: NotRequired[list[str]]
        imported_keys: NotRequired[list[str]]
        mapping: NotRequired[dict[str, str]]
        existing_issuers: NotRequired[list[str]]
        existing_keys: NotRequired[list[str]]

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "SetSignedIntmdResult":
        return cls.model_construct(**data)


class UpdateResult(AbstractResult):
    data: "Data"

    class Data(TypedDict):
        ca_chain: list[str]
        certificate: str
        issuer_id: str
        issuer_name: str
        key_id: str
        leaf_not_after_behavior: issuer.LeafNotAfterBehaviorType
        manual_chain: Any
        usage: issuer.UsageType
        revocation_signature_algorithm: issuer.SignatureAlgorithmType
        issuing_certificates: NotRequired[list[str]]
        crl_distribution_points: NotRequired[list[str]]
        ocsp_servers: NotRequired[list[str]]

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> "UpdateResult":
        data["data"]["usage"] = data["data"]["usage"].split(",")
        return cls.model_construct(**data)


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

        result: dict[str, Any] = await resp.json()
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
        raise await exc.VaultAPIError.from_response("Root CA generation failed", resp)

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

        result: dict[str, Any] = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return GenerateIntmdCSRResult.from_response(result)

        logger.debug(result)
        raise await exc.VaultAPIError.from_response(
            "Intermediate CSR generation failed", resp
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

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return SignIntmdResult.from_response(result)

        logger.debug(result)
        raise await exc.VaultAPIError.from_response("Issuer generation failed", resp)

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

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return SetSignedIntmdResult.from_response(result)

        logger.debug(result)
        raise await exc.VaultAPIError.from_response(
            "Failed to set signed intermediate certificate", resp
        )

    async def update_key(self, payload: dto.KeyUpdateDTO) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/key/%s" % (payload["mount_path"], payload["key_ref"]),
                json={"key_name": payload["key_name"]},
            )

        result = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return

        logger.debug(result)
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

    async def create_or_update_role(self, payload: dto.PKIRoleCreateDTO) -> None:
        async with self.new_session() as sess:
            await (
                resp := await sess.post(
                    "/v1/%s/roles/%s" % (payload["mount_path"], payload["issuer_ref"]),
                    data=util.model.model_dump_json(
                        payload, exclude={"mount_path", "issuer_ref"}
                    ),
                )
            ).json()

        if resp.status == http.HTTPStatus.OK:
            return

        raise await exc.VaultAPIError.from_response(
            "Failed to create/update PKI Role", resp
        )
