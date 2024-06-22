from contextlib import suppress
from dataclasses import dataclass
from typing import Any, Callable, ClassVar, Coroutine

from cryptography.utils import cached_property
from deepdiff import DeepDiff
from typing_extensions import Unpack

from vault_autopilot._pkg.asyva.exc import IssuerNotFoundError
from vault_autopilot.exc import ResourceIntegrityError
from vault_autopilot.repo.snapshot import SnapshotRepo

from .. import dto
from .._pkg import asyva
from .._pkg.asyva.manager.pki import IssuerReadResult
from ..util.model import model_dump, recursive_dict_filter
from .abstract import ResourceApplyMixin

MUTABLE_FIELDS = (
    "leaf_not_after_behavior",
    "manual_chain",
    "usage",
    "revocation_signature_algorithm",
    "issuing_certificates",
    "crl_distribution_points",
    "ocsp_servers",
    "enable_aia_url_templating",
)


IssuerSnapshot = dto.IssuerApplyDTO


@dataclass
class IssuerService(ResourceApplyMixin[dto.IssuerApplyDTO, IssuerSnapshot]):
    client: asyva.Client
    repo: SnapshotRepo[IssuerSnapshot]
    immutable_field_pats: ClassVar[tuple[str, ...]] = (
        "root.spec[[]'certificate'[]]**",
    )

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
                            mount_path=mount_path,
                            add_basic_constraints=payload.spec.get("chaining", {}).get(
                                "add_basic_constraints", False
                            ),
                            **certificate,
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

        # Set issuer name and other options if provided
        _ = await self.client.update_issuer(
            issuer_ref=imported_issuers[0],
            issuer_name=payload.spec["name"],
            mount_path=payload.spec["secrets_engine"],
            **payload.spec.get("options", {}),
        )

    async def _create_root_issuer(self, payload: dto.IssuerApplyDTO) -> None:
        spec = payload.spec

        _ = await self.client.generate_root(
            issuer_name=spec["name"],
            mount_path=spec["secrets_engine"],
            **spec["certificate"],
        )

        if options := spec.get("options"):
            _ = await self.client.update_issuer(
                mount_path=spec["secrets_engine"],
                issuer_ref=spec["name"],
                **options,
            )

    async def create(self, payload: dto.IssuerApplyDTO) -> None:
        if payload.spec.get("chaining"):
            await self._create_intmd_issuer(payload)
        else:
            await self._create_root_issuer(payload)

        await self.repo.put(
            payload.absolute_path(),
            payload,
        )

    async def update(self, payload: dto.IssuerApplyDTO) -> None:
        await self.client.update_issuer(
            mount_path=payload.spec["secrets_engine"],
            issuer_ref=payload.spec["name"],
            **payload.spec.get("options", {}),
        )

    async def get(self, **payload: Unpack[dto.IssuerGetDTO]) -> IssuerReadResult | None:
        return await self.client.read_issuer(**payload)

    @cached_property
    def update_or_create_executor(
        self,
    ) -> Callable[[dto.IssuerApplyDTO], Coroutine[Any, Any, Any]]:
        async def wrapper(payload: dto.IssuerApplyDTO):
            is_exists: bool = False

            with suppress(IssuerNotFoundError):
                is_exists = bool(
                    await self.get(
                        issuer_ref=payload.spec["name"],
                        mount_path=payload.spec["secrets_engine"],
                    )
                )

            return (
                await self.update(payload) if is_exists else await self.create(payload)
            )

        return lambda payload: wrapper(payload)

    async def build_snapshot(
        self, payload: dto.IssuerApplyDTO
    ) -> IssuerSnapshot | None:
        snapshot, issuer = (
            await self.repo.get(payload.absolute_path()),
            await self.get(
                issuer_ref=payload.spec["name"],
                mount_path=payload.spec["secrets_engine"],
            ),
        )
        snapshot_is_missing = snapshot is None
        issuer_is_missing = issuer is None

        if snapshot_is_missing and issuer_is_missing:
            return None

        if snapshot_is_missing:
            raise ResourceIntegrityError(
                "Snapshot not found, resource integrity compromised",
                ResourceIntegrityError.Context(resource=payload),
            )

        if issuer_is_missing:
            raise ResourceIntegrityError(
                "Failed to retrieve a snapshot, the required resource is missing",
                ResourceIntegrityError.Context(resource=payload),
            )

        if options := recursive_dict_filter(
            model_dump(
                issuer.data,
                include=MUTABLE_FIELDS,
            ),
            payload.spec.get("options", {}),
        ):
            snapshot.spec.update(options=options)  # type: ignore[reportArgumentType]

        return snapshot

    def diff(
        self, payload: dto.IssuerApplyDTO, snapshot: IssuerSnapshot
    ) -> dict[str, Any]:
        return DeepDiff(
            snapshot,
            payload,
            ignore_order=True,
            verbose_level=2,
        )
