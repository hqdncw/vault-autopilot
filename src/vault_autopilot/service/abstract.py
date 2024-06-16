import json
from abc import abstractmethod
from dataclasses import dataclass
from logging import getLogger
from typing import Any, Generic, Literal, NotRequired, TypedDict, TypeVar

from cryptography.utils import cached_property
from deepdiff import DeepDiff

from vault_autopilot._pkg.asyva import Client as AsyvaClient
from vault_autopilot._pkg.asyva.exc import CASParameterMismatchError
from vault_autopilot._pkg.asyva.manager.kvv2 import ReadMetadataResult
from vault_autopilot.exc import (
    SecretIntegrityError,
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
    errors: NotRequired[tuple[Exception, ...]]


@dataclass(slots=True)
class ResourceApplyMixin(Generic[P, S]):
    client: AsyvaClient

    @abstractmethod
    async def build_snapshot(self, payload: P) -> S | None: ...

    @abstractmethod
    def diff(self, payload: P, snapshot: S) -> dict[str, Any]: ...

    @cached_property
    @abstractmethod
    def update_or_create_executor(self): ...

    async def apply(self, payload: P) -> ApplyResult:
        snapshot = await self.build_snapshot(payload)

        is_create = snapshot is None

        if not is_create and (diff := self.diff(payload, snapshot)):
            logger.debug("[%s] diff: %r", self.__class__.__name__, diff)
            is_update = bool(diff)
        else:
            is_update = False

        if not (is_create or is_update):
            return ApplyResult(status="verify_success")

        try:
            await self.update_or_create_executor(payload)
        except Exception as exc:
            return ApplyResult(
                status="create_error" if is_create else "update_error", errors=(exc,)
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
            raise SecretIntegrityError(
                "Manifest object not found in secret metadata, secret integrity "
                "compromised.",
                ctx=SecretIntegrityError.Context(resource=payload),
            )

        return DeepDiff(
            type(payload)(**(json.loads(snapshot) or {})),
            payload,
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

                return ApplyResult(status="verify_error", errors=(exc,))

            if diff := await self.diff(
                payload,
                await self.client.read_kv_metadata(
                    mount_path=payload.spec["secrets_engine"],
                    path=payload.spec["path"],
                ),
            ):
                raise SnapshotMismatchError(
                    "The secret data has been modified unexpectedly. Please review and "
                    "update the secret accordingly.\n\n{ctx[diff]!r}",
                    ctx=SnapshotMismatchError.Context(resource=payload, diff=diff),
                )

            return ApplyResult(status="verify_success")

        except Exception as ex:
            return ApplyResult(status="create_error", errors=(ex,))

        return (
            ApplyResult(status="create_success")
            if payload.spec["version"] == 1
            else ApplyResult(status="update_success")
        )

    @abstractmethod
    async def check_and_set(self, payload: T) -> None: ...
