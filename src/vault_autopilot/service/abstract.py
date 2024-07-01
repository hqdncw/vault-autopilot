import json
from abc import abstractmethod
from dataclasses import dataclass
from fnmatch import fnmatch
from logging import getLogger
from typing import (
    Any,
    Callable,
    ClassVar,
    Coroutine,
    Generic,
    Literal,
    NotRequired,
    TypedDict,
    TypeVar,
)

from cryptography.utils import cached_property
from deepdiff import DeepDiff
from humps import camelize

from vault_autopilot._pkg.asyva import Client as AsyvaClient
from vault_autopilot._pkg.asyva.exc import CASParameterMismatchError
from vault_autopilot._pkg.asyva.manager.kvv2 import ReadMetadataResult
from vault_autopilot.exc import (
    ResourceImmutFieldError,
    ResourceIntegrityError,
    SecretVersionMismatchError,
    SnapshotMismatchError,
)

from ..dto.abstract import AbstractDTO, VersionedSecretApplyDTO

__all__ = ("VersionedSecretApplyMixin", "ResourceApplyMixin")

T = TypeVar("T", bound=VersionedSecretApplyDTO)
P = TypeVar("P", bound=AbstractDTO)
S = TypeVar("S")
ApplyResultStatus = Literal[
    "verify_success",
    "create_success",
    "update_success",
    "verify_error",
    "create_error",
    "update_error",
]

logger = getLogger(__name__)


class ApplyResult(TypedDict):
    status: ApplyResultStatus
    error: NotRequired[Exception]


@dataclass(kw_only=True)
class ResourceApplyMixin(Generic[P, S]):
    client: AsyvaClient
    immutable_fields: ClassVar[tuple[str, ...]] = tuple()

    @abstractmethod
    async def build_snapshot(self, payload: P) -> S | None: ...

    @abstractmethod
    def diff(self, payload: P, snapshot: S) -> dict[str, Any]: ...

    @cached_property
    @abstractmethod
    def update_or_create_executor(self) -> Callable[[P], Coroutine[Any, Any, Any]]: ...

    @staticmethod
    def _create_immut_field_error(
        diff: dict[Any, Any], payload: P, field_name: str
    ) -> ResourceImmutFieldError:
        return ResourceImmutFieldError(
            "Cannot modify immutable field {ctx[field_name]!r}\n\n{ctx[diff]!r}",
            ResourceImmutFieldError.Context(
                resource=payload, field_name=field_name, diff=diff
            ),
        )

    async def apply(self, payload: P) -> ApplyResult:
        snapshot = await self.build_snapshot(payload)
        is_create = snapshot is None

        if not is_create and (diff := self.diff(payload, snapshot)):
            logger.debug("[%s] diff: %r", self.__class__.__name__, diff)
            is_update = True

            if errors := tuple(
                self._create_immut_field_error(diff, payload, immut_field)
                for immut_field in filter(
                    lambda loc: next(
                        (True for pat in self.immutable_fields if fnmatch(loc, pat)),
                        False,
                    ),
                    (v for inner in diff.values() for v in inner.keys()),
                )
            ):
                return ApplyResult(
                    status="update_error",
                    error=ExceptionGroup("Failed to update issuer", errors),
                )
        else:
            is_update = False

        if not (is_create or is_update):
            return ApplyResult(status="verify_success")

        try:
            await self.update_or_create_executor(payload)
        except Exception as exc:
            return ApplyResult(
                status="create_error" if is_create else "update_error", error=exc
            )

        if is_create:
            return ApplyResult(status="create_success")
        else:
            return ApplyResult(status="update_success")


@dataclass(slots=True)
class VersionedSecretApplyMixin(Generic[T]):
    client: AsyvaClient

    SNAPSHOT_LABEL = "hqdncw.github.io/vault-autopilot/snapshot"

    async def diff(self, payload: T, kv_metadata: ReadMetadataResult) -> dict[str, Any]:
        if not (
            snapshot := (
                (kv_metadata.data["custom_metadata"] or {}).get(self.SNAPSHOT_LABEL, "")
            )
        ):
            raise ResourceIntegrityError(
                "Snapshot not found, resource integrity compromised.",
                ctx=ResourceIntegrityError.Context(resource=payload),
            )

        return DeepDiff(
            json.loads(snapshot) or {},
            camelize(payload.__dict__),
            ignore_order=True,
            verbose_level=2,
        )

    async def apply(self, payload: T) -> ApplyResult:
        """
        Updates, creates, or verifies a secret using the given payload and version.

        If the provided version matches the current version of the secret, verify its
        integrity. Otherwise, Check-and-Set the secret with the given payload.
        """

        try:
            await self.check_and_set(payload)
        except CASParameterMismatchError as ex:
            if (required_cas := ex.ctx.get("required_cas")) is None:
                raise RuntimeError("'required_cas' field must not be null")

            provided_version = payload.spec["version"]

            if provided_version != required_cas:
                ctx = SecretVersionMismatchError.Context(resource=payload)

                if required_cas == 0:
                    exc = SecretVersionMismatchError(
                        "Version mismatch. Expected version: %d (to generate the "
                        "secret data), got: %d. Please enter the correct version "
                        "and try again." % (required_cas + 1, provided_version),
                        ctx,
                    )
                else:
                    exc = SecretVersionMismatchError(
                        "Version mismatch. Expected either version %d (to keep the "
                        "secret data untouched) or version %d (to regenerate the "
                        "secret data). Instead, version %r was provided. Please enter "
                        "the correct correct version and try again."
                        % (
                            required_cas,
                            required_cas + 1,
                            provided_version,
                        ),
                        ctx,
                    )

                return ApplyResult(status="verify_error", error=exc)

            if diff := await self.diff(
                payload,
                await self.client.read_kv_metadata(
                    mount_path=payload.spec["secrets_engine_ref"],
                    path=payload.spec["path"],
                ),
            ):
                raise SnapshotMismatchError(
                    "Snapshot mismatch. Resource state differs. Bump version or roll "
                    "back changes to sync.\n\n{ctx[diff]!r}",
                    ctx=SnapshotMismatchError.Context(resource=payload, diff=diff),
                )

            return ApplyResult(status="verify_success")

        except Exception as ex:
            return ApplyResult(status="create_error", error=ex)

        return (
            ApplyResult(status="create_success")
            if payload.spec["version"] == 1
            else ApplyResult(status="update_success")
        )

    @abstractmethod
    async def check_and_set(self, payload: T) -> None: ...
