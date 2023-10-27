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
            payload.spec.get("secret_engine"),
            payload.spec.get("csr_params"),
            payload.spec.get("issuance_params"),
        )
        assert (
            iss_params and csr_params and mount_path
        ), "Issuance params must not be null"

        res = await self.client.set_signed_intermediate(
            certificate=(
                await self.client.sign_intermediate(
                    mount_path=iss_params["issuer_ref"]["secret_engine"],
                    issuer_ref=iss_params["issuer_ref"]["issuer_name"],
                    csr=(
                        await self.client.generate_intermediate_csr(
                            mount_path=mount_path,
                            **util.pydantic.model_dump(
                                csr_params,
                                exclude_unset=True,
                            ),
                        )
                    ).data["csr"],
                    use_csr_values=True,
                    **util.pydantic.model_dump(
                        iss_params, exclude={"issuer_ref"}, exclude_unset=True
                    ),
                )
            ).data["certificate"],
            mount_path=mount_path,
        )

        if not (
            (imported_issuers := res.data.get("imported_issuers"))
            and len(imported_issuers) == 1
        ):
            raise RuntimeError(
                "Expected one issuer only to be imported, got %r" % imported_issuers
            )

        await self.client.update_issuer(
            issuer_ref=imported_issuers[0],
            issuer_name=csr_params["issuer_name"],
            mount_path=payload.spec["secret_engine"],
        )

    async def _create_root_issuer(self, payload: dto.IssuerCreateDTO) -> None:
        spec, csr_params = payload.spec, payload.spec["csr_params"]
        await self.client.generate_root(
            mount_path=spec["secret_engine"],
            **util.pydantic.model_dump(csr_params, exclude_unset=True),
        )

    async def create(self, payload: dto.IssuerCreateDTO) -> None:
        if payload.spec.get("issuance_params"):
            await self._create_intmd_issuer(payload)
        else:
            await self._create_root_issuer(payload)
        logger.debug("issuer %r created" % payload.get_full_path())
