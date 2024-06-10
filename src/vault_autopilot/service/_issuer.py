import logging
from dataclasses import dataclass

from .. import dto
from .._pkg import asyva
from .._pkg.asyva.manager.pki import GetResult
from ..util.model import model_dump
from . import abstract

logger = logging.getLogger(__name__)


# MUTABLE_FIELDS = (
#     "leaf_not_after_behavior",
#     "manual_chain",
#     "usage",
#     "revocation_signature_algorithm",
#     "issuing_certificates",
#     "crl_distribution_points",
#     "ocsp_servers",
#     "enable_aia_url_templating",
# )


@dataclass(slots=True)
class IssuerService:
    client: asyva.Client

    async def _create_intmd_issuer(self, payload: dto.IssuerApplyDTO) -> None:
        mount_path, certificate, chaining = (
            payload.spec["secrets_engine"],
            payload.spec["certificate"],
            payload.spec.get("chaining"),
        )

        assert chaining is not None, "The 'chaining' field is required"

        upstream_ref = chaining["upstream_issuer_ref"].split("/", maxsplit=1)
        result = await self.client.set_signed_intermediate(
            certificate=(
                await self.client.sign_intermediate(
                    mount_path=upstream_ref[0],  # PKI engine mount path
                    issuer_ref=upstream_ref[1],  # Issuer name
                    csr=(
                        await self.client.generate_intermediate_csr(
                            mount_path=mount_path, **certificate
                        )
                    ).data["csr"],
                    use_csr_values=True,
                    **model_dump(chaining, exclude={"issuer_ref"}),
                )
            ).data["certificate"],
            mount_path=mount_path,
        )

        imported_issuers = result.data.get("imported_issuers", [])
        assert len(imported_issuers) == 1, (
            "Expected one issuer only to be imported, got: %r" % imported_issuers
        )

        # Set issuer name
        _ = await self.client.update_issuer(
            issuer_ref=imported_issuers[0],
            issuer_name=payload.spec["name"],
            mount_path=payload.spec["secrets_engine"],
        )

    async def _create_root_issuer(self, payload: dto.IssuerApplyDTO) -> None:
        spec = payload.spec

        _ = await self.client.generate_root(
            issuer_name=spec["name"],
            mount_path=spec["secrets_engine"],
            **model_dump(
                spec["certificate"],
                exclude={"add_basic_constraints"},
            ),
        )

    async def create(self, payload: dto.IssuerApplyDTO) -> None:
        if payload.spec.get("chaining"):
            await self._create_intmd_issuer(payload)
        else:
            await self._create_root_issuer(payload)

        logger.debug("created issuer at path: %r", payload.absolute_path())

    async def get(self, payload: dto.IssuerGetDTO) -> GetResult | None:
        return await self.client.get_issuer(**payload)

    async def apply(self, payload: dto.IssuerApplyDTO) -> abstract.ApplyResult:
        try:
            result = await self.get(
                dto.IssuerGetDTO(
                    issuer_ref=payload.spec["name"],
                    mount_path=payload.spec["secrets_engine"],
                )
            )
        except Exception as ex:
            return abstract.ApplyResult(status="verify_error", errors=(ex,))

        if result is None:
            try:
                await self.create(payload)
            except Exception as ex:
                return abstract.ApplyResult(status="create_error", errors=(ex,))
            else:
                return abstract.ApplyResult(status="create_success")
        else:
            return abstract.ApplyResult(status="verify_success")
