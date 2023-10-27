from dataclasses import dataclass

from .. import dto, util
from .._pkg import asyva
from . import _abstract


@dataclass(slots=True)
class IssuerService(_abstract.Service):
    client: asyva.Client

    async def _push_intmd_issuer(self, payload: dto.IssuerDTO) -> None:
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
            (imported_issuers := res.data.get("imported_keys"))
            and len(imported_issuers) == 1
        ):
            raise RuntimeError("Expected one issuer only, got %r" % imported_issuers)

        await self.client.update_issuer(
            issuer_ref=imported_issuers[0],
            issuer_name=csr_params["issuer_name"],
            mount_path=payload.spec["secret_engine"],
        )

    async def _push_root_issuer(self, payload: dto.IssuerDTO) -> None:
        spec, csr_params = payload.spec, payload.spec["csr_params"]
        await self.client.generate_root(
            mount_path=spec["secret_engine"],
            **util.pydantic.model_dump(csr_params, exclude_unset=True),
        )

    async def push(self, payload: dto.BaseDTO) -> None:
        assert isinstance(payload, dto.IssuerDTO), "Expected %r, got %r" % (
            dto.IssuerDTO,
            payload,
        )
        if payload.spec.get("issuance_params"):
            await self._push_intmd_issuer(payload)
        else:
            await self._push_root_issuer(payload)
