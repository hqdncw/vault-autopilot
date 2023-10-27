import http
import logging
from dataclasses import dataclass
from typing import Any, Literal, NoReturn, Optional, TypedDict

import pydantic
from typing_extensions import Unpack

from .... import util
from .. import constants, dto, exc
from ..dto import issuer
from . import base

logger = logging.getLogger(__name__)

IssuerType = Literal["root", "intermediate"]

GEN_EXCL = {"type_", "mount_path"}
SIGN_INTMD_EXCL = {"mount_path", "issuer_ref"}
UPDATE_EXCL = SIGN_INTMD_EXCL


@dataclass(slots=True)
class AbstractResult:
    request_id: str
    lease_id: str
    renewable: bool
    lease_duration: int
    warnings: Optional[list[str]] = None
    auth: Any = None
    wrap_info: Any = None


class BaseCertData(TypedDict):
    expiration: int
    certificate: str
    issuing_ca: str
    serial_number: str


@dataclass(slots=True, kw_only=True)
class GenerateIntmdCSRResult(AbstractResult):
    data: "Data"

    class Data(TypedDict):
        csr: str
        private_key: Optional[pydantic.SecretStr]
        private_key_type: Optional[issuer.KeyType]
        key_id: str


@dataclass(slots=True, kw_only=True)
class GenerateRootResult(AbstractResult):
    data: "Data"

    class Data(BaseCertData):
        issuer_id: str
        issuer_name: str
        key_id: str
        key_name: str


@dataclass(slots=True, kw_only=True)
class SignIntmdResult(AbstractResult):
    data: "Data"

    class Data(BaseCertData):
        ca_chain: str


@dataclass(slots=True, kw_only=True)
class SetSignedIntmdResult(AbstractResult):
    data: "Data"

    class Data(TypedDict):
        imported_issuers: Optional[list[str]]
        imported_keys: Optional[list[str]]
        mapping: Optional[dict[str, str]]
        existing_issuers: Optional[list[str]]
        existing_keys: Optional[list[str]]


@dataclass(slots=True, kw_only=True)
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
        issuing_certificates: Optional[list[str]]
        crl_distribution_points: Optional[list[str]]
        ocsp_servers: Optional[list[str]]


def raise_issuer_name_taken_exc(issuer_name: str, mount_path: str) -> NoReturn:
    raise exc.IssuerNameTakenError(
        "Issuer name {issuer_name!r} (secret_engine: {pki_mount_path!r}) is "
        "already in use. Please choose a different name",
        issuer_name=issuer_name,
        pki_mount_path=mount_path,
    )


@dataclass
class PKIManager(base.BaseManager):
    async def generate_root(
        self,
        **payload: Unpack[dto.IssuerGenerateRootDTO],
    ) -> GenerateRootResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{mount_path}/issuers/generate/{issuer_type}/{cert_type}".format(
                    mount_path=payload["mount_path"],
                    issuer_type="root",
                    cert_type=payload["type_"],
                ),
                data=util.pydantic.model_dump_json(
                    payload, exclude=GEN_EXCL, exclude_unset=True
                ),
            )

        resp_body: dict[str, Any] = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return GenerateRootResult(**resp_body)
        elif constants.ISSUER_NAME_TAKEN in resp_body["errors"]:
            raise_issuer_name_taken_exc(
                issuer_name=payload[
                    "issuer_name"
                ],  # pyright: ignore[reportTypedDictNotRequiredAccess]
                mount_path=payload["mount_path"],
            )

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response("Root CA generation failed", resp)

    async def generate_intmd_csr(
        self,
        **payload: Unpack[dto.IssuerGenerateIntmdCSRDTO],
    ) -> GenerateIntmdCSRResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/{mount_path}/issuers/generate/{issuer_type}/{cert_type}".format(
                    mount_path=payload["mount_path"],
                    issuer_type="intermediate",
                    cert_type=payload["type_"],
                ),
                data=util.pydantic.model_dump_json(
                    payload, exclude=GEN_EXCL, exclude_unset=True
                ),
            )

        resp_body: dict[str, Any] = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return GenerateIntmdCSRResult(**resp_body)

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response(
            "Intermediate CSR generation failed", resp
        )

    async def sign_intmd(
        self, **payload: Unpack[dto.IssuerSignIntmdDTO]
    ) -> SignIntmdResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/issuer/%s/sign-intermediate"
                % (payload["mount_path"], payload["issuer_ref"]),
                data=util.pydantic.model_dump_json(
                    payload, exclude=SIGN_INTMD_EXCL, exclude_unset=True
                ),
            )

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return SignIntmdResult(**resp_body)

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response("Issuer generation failed", resp)

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

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return SetSignedIntmdResult(**resp_body)

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response(
            "Failed to set signed intermediate certificate", resp
        )

    async def update_key(self, **payload: Unpack[dto.KeyUpdateDTO]) -> None:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/key/%s" % (payload["mount_path"], payload["key_ref"]),
                json={"key_name": payload["key_name"]},
            )

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response("Failed to update key", resp)

    async def update_issuer(
        self, **payload: Unpack[dto.IssuerUpdateDTO]
    ) -> UpdateResult:
        async with self.new_session() as sess:
            resp = await sess.post(
                "/v1/%s/issuer/%s" % (payload["mount_path"], payload["issuer_ref"]),
                data=util.pydantic.model_dump_json(
                    payload, exclude=UPDATE_EXCL, exclude_unset=True
                ),
            )

        resp_body = await resp.json()
        if resp.status == http.HTTPStatus.OK:
            return UpdateResult(**resp_body)
        elif constants.ISSUER_NAME_TAKEN in resp_body["errors"]:
            raise_issuer_name_taken_exc(
                issuer_name=payload[
                    "issuer_name"
                ],  # pyright: ignore[reportTypedDictNotRequiredAccess]
                mount_path=payload["mount_path"],
            )

        logger.debug(resp_body)
        raise await exc.VaultAPIError.from_response("Failed to update issuer", resp)
