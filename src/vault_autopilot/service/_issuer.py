import logging
from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class IssuerService:
    client: asyva.Client

    async def _create_intmd_issuer(self, payload: dto.IssuerCreateDTO) -> None:
        mount_path, csr_params, iss_params = (
            payload.spec["secret_engine"],
            payload.spec["csr_params"],
            payload.spec.get("issuance_params"),
        )

        assert iss_params is not None, "Issuance params must not be null"

        root_ref = iss_params["issuer_ref"].split("/", maxsplit=1)
        result = await self.client.set_signed_intermediate(
            certificate=(
                await self.client.sign_intermediate(
                    mount_path=root_ref[0],  # PKI engine mount path
                    issuer_ref=root_ref[1],  # Issuer name
                    csr=(
                        await self.client.generate_intermediate_csr(
                            mount_path=mount_path, **csr_params
                        )
                    ).data["csr"],
                    use_csr_values=True,
                    **util.model.model_dump(iss_params, exclude={"issuer_ref"}),
                )
            ).data["certificate"],
            mount_path=mount_path,
        )

        imported_issuers = result.data.get("imported_issuers", [])
        assert len(imported_issuers) == 1, (
            "Expected one issuer only to be imported, got: %r" % imported_issuers
        )

        # Set issuer name
        await self.client.update_issuer(
            issuer_ref=imported_issuers[0],
            issuer_name=payload.spec["name"],
            mount_path=payload.spec["secret_engine"],
        )

    async def _create_root_issuer(self, payload: dto.IssuerCreateDTO) -> None:
        spec = payload.spec

        await self.client.generate_root(
            issuer_name=spec["name"],
            mount_path=spec["secret_engine"],
            **util.model.model_dump(
                spec["csr_params"],
                exclude={"add_basic_constraints"},
            ),
        )

    async def create(self, payload: dto.IssuerCreateDTO) -> None:
        if payload.spec.get("issuance_params"):
            await self._create_intmd_issuer(payload)
        else:
            await self._create_root_issuer(payload)

        logger.debug("created issuer at path: %r", payload.absolute_path())
