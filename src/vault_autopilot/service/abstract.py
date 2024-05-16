from abc import abstractmethod
from typing import Literal, NotRequired, TypedDict

from vault_autopilot._pkg.asyva.exc import CASParameterMismatchError
from vault_autopilot.exc import SecretVersionMismatchError

from ..dto import VersionedSecretApplyDTO

__all__ = ("VersionedSecretApplyMixin",)


ApplyResultStatus = Literal[
    "verify_success",
    "create_success",
    "update_success",
    "verify_error",
    "create_error",
    "update_error",
]


class ApplyResult(TypedDict):
    status: ApplyResultStatus
    errors: NotRequired[tuple[Exception, ...]]


class VersionedSecretApplyMixin:
    async def apply(self, payload: VersionedSecretApplyDTO) -> ApplyResult:
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
                        "Resource %r version mismatch: Expected version: %d (to "
                        "generate the secret data), got: %d. Please enter the correct "
                        "version and try again."
                        % (payload.absolute_path(), required_cas + 1, provided_version),
                        ctx,
                    )
                else:
                    exc = SecretVersionMismatchError(
                        "Resource %r version mismatch. Expected either version "
                        "%d (to keep the secret data untouched) or version %d (to "
                        "regenerate the secret data). Instead, version %r was provided. "
                        "Please enter the correct version and try again."
                        % (
                            payload.absolute_path(),
                            required_cas,
                            required_cas + 1,
                            provided_version,
                        ),
                        ctx,
                    )

                return ApplyResult(status="verify_error", errors=(exc,))

            return ApplyResult(status="verify_success")

        except Exception as ex:
            return ApplyResult(status="create_error", errors=(ex,))

        return (
            ApplyResult(status="create_success")
            if payload.spec["version"] == 1
            else ApplyResult(status="update_success")
        )

    @abstractmethod
    async def check_and_set(self, payload: VersionedSecretApplyDTO) -> None: ...
