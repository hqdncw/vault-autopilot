import asyncio
from collections.abc import Coroutine, Sequence
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar

from .. import dto
from ..exc import UnresolvedDependencyError
from ..util.coro import BoundlessSemaphore, create_task_limited

T = TypeVar("T")

FilterType = Sequence[type[T]]
CallbackType = Callable[[Any], Coroutine[Any, Any, Any]]


@dataclass(slots=True)
class HandlerObject(Generic[T]):
    filter: FilterType[T]
    callback: CallbackType


@dataclass(slots=True)
class EventObserver(Generic[T]):
    _handlers: list[HandlerObject[T]] = field(init=False, default_factory=list)

    def register(self, filter_: FilterType[T], callback: CallbackType) -> None:
        """
        Registers a handler function to be called when an event of the specified type is
        emitted.

        Args:
            filter_: A sequence of types that the event must match in order for the
                handler to be called.
            callback: The function to call when an event matches the filter.
        """
        self._handlers.append(HandlerObject(filter_, callback))

    async def trigger(self, event: T) -> None:
        async with asyncio.TaskGroup() as tg:
            for handler in filter(lambda h: type(event) in h.filter, self._handlers):
                await create_task_limited(
                    tg, BoundlessSemaphore(), handler.callback(event)
                )


@dataclass(slots=True)
class PasswordApplicationRequested:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordApplicationInitiated:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordCreateError:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordUpdateError:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordCreateSuccess:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordUpdateSuccess:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordVerifySuccess:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordVerifyError:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class IssuerApplicationRequested:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerApplicationInitiated:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerCreateError:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerUpdateError:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerCreateSuccess:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerUpdateSuccess:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerVerifySuccess:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerVerifyError:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class PasswordPolicyApplicationRequested:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyApplicationInitiated:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyCreateError:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyUpdateError:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyVerifyError:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyCreateSuccess:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyUpdateSuccess:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyVerifySuccess:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PKIRoleApplicationRequested:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleApplicationInitiated:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleCreateError:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleUpdateError:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleVerifyError:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleCreateSuccess:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleUpdateSuccess:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleVerifySuccess:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class SecretsEngineApplicationRequested:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineApplicationInitiated:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineCreateError:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineUpdateError:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineVerifyError:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineCreateSuccess:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineUpdateSuccess:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SecretsEngineVerifySuccess:
    resource: dto.SecretsEngineApplyDTO


@dataclass(slots=True)
class SSHKeyApplicationRequested:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyApplicationInitiated:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyCreateError:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyUpdateError:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyVerifyError:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyCreateSuccess:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyUpdateSuccess:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class SSHKeyVerifySuccess:
    resource: dto.SSHKeyApplyDTO


@dataclass(slots=True)
class ShutdownRequested:
    """
    Once all manifests have been applied, the dispatcher triggers this event to allow
    the processors to shut down gracefully.
    """


@dataclass(slots=True)
class UnresolvedDepsDetected:
    """
    This event is raised when the system encounters one or more resources that reference
    dependencies that are not defined in any of the provided manifests.

    Attributes:
        unresolved_deps: A tuple of ``UnresolvedDependencyError`` objects, each
            representing a resource with an unresolved dependency.

    Notes:
        This event is typically used to notify the system or users about the presence of
        unresolved dependencies, which can prevent resources from being properly
        deployed or configured.
    """

    unresolved_deps: tuple[UnresolvedDependencyError, ...]


ResourceApplicationRequested = (
    PasswordApplicationRequested
    | IssuerApplicationRequested
    | PasswordPolicyApplicationRequested
    | PKIRoleApplicationRequested
    | SecretsEngineApplicationRequested
    | SSHKeyApplicationRequested
)
ResourceApplicationInitiated = (
    PasswordApplicationInitiated
    | IssuerApplicationInitiated
    | PasswordPolicyApplicationInitiated
    | PKIRoleApplicationInitiated
    | SecretsEngineApplicationInitiated
    | SSHKeyApplicationInitiated
)
ResourceCreateError = (
    PasswordCreateError
    | IssuerCreateError
    | PKIRoleCreateError
    | PasswordPolicyCreateError
    | SecretsEngineCreateError
    | SSHKeyCreateError
)
ResourceUpdateError = (
    PasswordUpdateError
    | IssuerUpdateError
    | PKIRoleUpdateError
    | PasswordPolicyUpdateError
    | SecretsEngineUpdateError
    | SSHKeyUpdateError
)
ResourceCreateSuccess = (
    PasswordCreateSuccess
    | IssuerCreateSuccess
    | PasswordPolicyCreateSuccess
    | PKIRoleCreateSuccess
    | SecretsEngineCreateSuccess
    | SSHKeyCreateSuccess
)
ResourceUpdateSuccess = (
    PasswordUpdateSuccess
    | IssuerUpdateSuccess
    | PasswordPolicyUpdateSuccess
    | PKIRoleUpdateSuccess
    | SecretsEngineUpdateSuccess
    | SSHKeyUpdateSuccess
)
ResourceVerifySuccess = (
    PasswordVerifySuccess
    | IssuerVerifySuccess
    | PasswordPolicyVerifySuccess
    | PKIRoleVerifySuccess
    | SecretsEngineVerifySuccess
    | SSHKeyVerifySuccess
)
ResourceVerifyError = (
    PasswordVerifyError
    | IssuerVerifyError
    | PasswordPolicyVerifyError
    | PKIRoleVerifyError
    | SecretsEngineVerifyError
    | SSHKeyVerifyError
)

IssuerApplySuccess = IssuerCreateSuccess | IssuerUpdateSuccess | IssuerVerifySuccess
PasswordApplySuccess = (
    PasswordCreateSuccess | PasswordUpdateSuccess | PasswordVerifySuccess
)
PasswordPolicyApplySuccess = (
    PasswordPolicyCreateSuccess
    | PasswordPolicyUpdateSuccess
    | PasswordPolicyVerifySuccess
)
PKIRoleApplySuccess = PKIRoleCreateSuccess | PKIRoleUpdateSuccess | PKIRoleVerifySuccess
SecretsEngineApplySuccess = (
    SecretsEngineCreateSuccess | SecretsEngineUpdateSuccess | SecretsEngineVerifySuccess
)
SSHKeyApplySuccess = SSHKeyCreateSuccess | SSHKeyUpdateSuccess | SSHKeyVerifySuccess

ResourceApplySuccess = (
    PasswordApplySuccess
    | IssuerApplySuccess
    | PasswordPolicyApplySuccess
    | PKIRoleApplySuccess
    | SecretsEngineApplySuccess
    | SSHKeyApplySuccess
)

IssuerApplyError = IssuerCreateError | IssuerUpdateError | IssuerVerifyError
PasswordApplyError = PasswordCreateError | PasswordUpdateError | PasswordVerifyError
PasswordPolicyApplyError = (
    PasswordPolicyCreateError | PasswordPolicyUpdateError | PasswordPolicyVerifyError
)
PKIRoleApplyError = PKIRoleCreateError | PKIRoleUpdateError | PKIRoleVerifyError
SecretsEngineApplyError = (
    SecretsEngineCreateError | SecretsEngineUpdateError | SecretsEngineVerifyError
)
SSHKeyApplyError = SSHKeyCreateError | SSHKeyUpdateError | SSHKeyVerifyError

ResourceApplyError = (
    PasswordApplyError
    | IssuerApplyError
    | PasswordPolicyApplyError
    | PKIRoleApplyError
    | SecretsEngineApplyError
    | SSHKeyApplyError
)

EventType = (
    PasswordApplicationRequested
    | PasswordApplicationInitiated
    | PasswordCreateError
    | PasswordUpdateError
    | PasswordVerifyError
    | PasswordCreateSuccess
    | PasswordUpdateSuccess
    | PasswordVerifySuccess
    | PasswordVerifyError
    | IssuerApplicationRequested
    | IssuerApplicationInitiated
    | IssuerCreateError
    | IssuerUpdateError
    | IssuerVerifyError
    | IssuerCreateSuccess
    | IssuerUpdateSuccess
    | IssuerVerifySuccess
    | PasswordPolicyApplicationRequested
    | PasswordPolicyApplicationInitiated
    | PasswordPolicyCreateError
    | PasswordPolicyUpdateError
    | PasswordPolicyVerifyError
    | PasswordPolicyCreateSuccess
    | PasswordPolicyUpdateSuccess
    | PasswordPolicyVerifySuccess
    | PKIRoleApplicationRequested
    | PKIRoleApplicationInitiated
    | PKIRoleCreateError
    | PKIRoleUpdateError
    | PKIRoleVerifyError
    | PKIRoleCreateSuccess
    | PKIRoleUpdateSuccess
    | PKIRoleVerifySuccess
    | SecretsEngineApplicationRequested
    | SecretsEngineApplicationInitiated
    | SecretsEngineCreateError
    | SecretsEngineUpdateError
    | SecretsEngineVerifyError
    | SecretsEngineCreateSuccess
    | SecretsEngineUpdateSuccess
    | SecretsEngineVerifySuccess
    | SSHKeyApplicationRequested
    | SSHKeyApplicationInitiated
    | SSHKeyCreateError
    | SSHKeyUpdateError
    | SSHKeyVerifyError
    | SSHKeyCreateSuccess
    | SSHKeyUpdateSuccess
    | SSHKeyVerifySuccess
    | ShutdownRequested
    | UnresolvedDepsDetected
)
