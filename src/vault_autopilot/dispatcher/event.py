import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Generic, TypeVar
from collections.abc import Sequence, Coroutine

from ..util.coro import create_task_limited

from .. import dto, util

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
                    tg, util.coro.BoundlessSemaphore(), handler.callback(event)
                )


@dataclass(slots=True)
class PasswordApplyRequested:
    resource: dto.PasswordApplyDTO


@dataclass(slots=True)
class PasswordApplyStarted:
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
class IssuerApplyRequested:
    resource: dto.IssuerApplyDTO


@dataclass(slots=True)
class IssuerApplyStarted:
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
class PasswordPolicyApplyRequested:
    resource: dto.PasswordPolicyApplyDTO


@dataclass(slots=True)
class PasswordPolicyApplyStarted:
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
class PKIRoleApplyRequested:
    resource: dto.PKIRoleApplyDTO


@dataclass(slots=True)
class PKIRoleApplyStarted:
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
class PostProcessRequested:
    """
    Once all manifests have been applied, this event is triggered by the dispatcher,
    allowing you to inspect resources that still have unfulfilled dependencies. This
    might include situations where passwords are waiting for password policy applying
    or intermediate issuers are waiting for upstream issuers to complete their applying.
    """


ResourceApplyRequested = (
    PasswordApplyRequested
    | IssuerApplyRequested
    | PasswordPolicyApplyRequested
    | PKIRoleApplyRequested
)
ResourceApplyStarted = (
    PasswordApplyStarted
    | IssuerApplyStarted
    | PasswordPolicyApplyStarted
    | PKIRoleApplyStarted
)
ResourceCreateError = (
    PasswordCreateError
    | IssuerCreateError
    | PKIRoleCreateError
    | PasswordPolicyCreateError
)
ResourceUpdateError = (
    PasswordUpdateError
    | IssuerUpdateError
    | PKIRoleUpdateError
    | PasswordPolicyUpdateError
)
ResourceCreateSuccess = (
    PasswordCreateSuccess
    | IssuerCreateSuccess
    | PasswordPolicyCreateSuccess
    | PKIRoleCreateSuccess
)
ResourceUpdateSuccess = (
    PasswordUpdateSuccess
    | IssuerUpdateSuccess
    | PasswordPolicyUpdateSuccess
    | PKIRoleUpdateSuccess
)
ResourceVerifySuccess = (
    PasswordVerifySuccess
    | IssuerVerifySuccess
    | PasswordPolicyVerifySuccess
    | PKIRoleVerifySuccess
)
ResourceVerifyError = (
    PasswordVerifyError
    | IssuerVerifyError
    | PasswordPolicyVerifyError
    | PKIRoleVerifyError
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
ResourceApplySuccess = (
    PasswordApplySuccess
    | IssuerApplySuccess
    | PasswordPolicyApplySuccess
    | PKIRoleApplySuccess
)

IssuerApplyError = IssuerCreateError | IssuerUpdateError | IssuerVerifyError
PasswordApplyError = PasswordCreateError | PasswordUpdateError | PasswordVerifyError
PasswordPolicyApplyError = (
    PasswordPolicyCreateError | PasswordPolicyUpdateError | PasswordPolicyVerifyError
)
PKIRoleApplyError = PKIRoleCreateError | PKIRoleUpdateError | PKIRoleVerifyError
ResourceApplyError = (
    PasswordApplyError | IssuerApplyError | PasswordPolicyApplyError | PKIRoleApplyError
)


EventType = (
    PasswordApplyRequested
    | PasswordApplyStarted
    | PasswordCreateError
    | PasswordUpdateError
    | PasswordVerifyError
    | PasswordCreateSuccess
    | PasswordUpdateSuccess
    | PasswordVerifySuccess
    | PasswordVerifyError
    | IssuerApplyRequested
    | IssuerApplyStarted
    | IssuerCreateError
    | IssuerUpdateError
    | IssuerVerifyError
    | IssuerCreateSuccess
    | IssuerUpdateSuccess
    | IssuerVerifySuccess
    | PasswordPolicyApplyRequested
    | PasswordPolicyApplyStarted
    | PasswordPolicyCreateError
    | PasswordPolicyUpdateError
    | PasswordPolicyVerifyError
    | PasswordPolicyCreateSuccess
    | PasswordPolicyUpdateSuccess
    | PasswordPolicyVerifySuccess
    | PKIRoleApplyRequested
    | PKIRoleApplyStarted
    | PKIRoleCreateError
    | PKIRoleUpdateError
    | PKIRoleVerifyError
    | PKIRoleCreateSuccess
    | PKIRoleUpdateSuccess
    | PKIRoleVerifySuccess
    | PostProcessRequested
)
