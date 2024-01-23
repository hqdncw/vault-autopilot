import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Coroutine, Generic, Sequence, Type, TypeVar, Union

from .. import dto, util

T = TypeVar("T")

FilterType = Sequence[Type[T]]
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
                await util.coro.create_task_limited(
                    tg, util.coro.BoundlessSemaphore(), handler.callback(event)
                )


@dataclass(slots=True)
class PasswordDiscovered:
    payload: dto.PasswordCheckOrSetDTO


@dataclass(slots=True)
class PasswordCreated:
    payload: dto.PasswordCheckOrSetDTO


@dataclass(slots=True)
class PasswordUpdated:
    payload: dto.PasswordCheckOrSetDTO


@dataclass(slots=True)
class PasswordUnchanged:
    payload: dto.PasswordCheckOrSetDTO


@dataclass(slots=True)
class IssuerDiscovered:
    payload: dto.IssuerCheckOrSetDTO


@dataclass(slots=True)
class IssuerCreated:
    payload: dto.IssuerCheckOrSetDTO


@dataclass(slots=True)
class IssuerUpdated:
    payload: dto.IssuerCheckOrSetDTO


@dataclass(slots=True)
class IssuerUnchanged:
    payload: dto.IssuerCheckOrSetDTO


@dataclass(slots=True)
class PasswordPolicyDiscovered:
    payload: dto.PasswordPolicyCheckOrSetDTO


@dataclass(slots=True)
class PasswordPolicyCreated:
    payload: dto.PasswordPolicyCheckOrSetDTO


@dataclass(slots=True)
class PasswordPolicyUpdated:
    payload: dto.PasswordPolicyCheckOrSetDTO


@dataclass(slots=True)
class PasswordPolicyUnchanged:
    payload: dto.PasswordPolicyCheckOrSetDTO


@dataclass(slots=True)
class PKIRoleDiscovered:
    payload: dto.PKIRoleCheckOrSetDTO


@dataclass(slots=True)
class PKIRoleCreated:
    payload: dto.PKIRoleCheckOrSetDTO


@dataclass(slots=True)
class PKIRoleUpdated:
    payload: dto.PKIRoleCheckOrSetDTO


@dataclass(slots=True)
class PKIRoleUnchanged:
    payload: dto.PKIRoleCheckOrSetDTO


@dataclass(slots=True)
class PostProcessRequested:
    """
    Once all manifests have been processed, this event is triggered by the dispatcher,
    allowing you to inspect resources that still have unfulfilled dependencies. This
    might include situations where passwords are waiting for password policy processing
    or intermediate issuers are waiting for upstream issuers to complete their
    processing.

    See also:
        * :class:`PasswordProcessed`
        * :class:`IssuerProcessed`
        * :class:`PasswordPolicyProcessed`
    """


ResourceDiscovered = Union[
    PasswordDiscovered, IssuerDiscovered, PasswordPolicyDiscovered, PKIRoleDiscovered
]
PasswordProcessed = Union[PasswordCreated, PasswordUpdated, PasswordUnchanged]
IssuerProcessed = Union[IssuerCreated, IssuerUpdated, IssuerUnchanged]
PasswordPolicyProcessed = Union[
    PasswordPolicyCreated, PasswordPolicyUpdated, PasswordPolicyUnchanged
]
PKIRoleProcessed = Union[PKIRoleCreated, PKIRoleUpdated, PKIRoleUnchanged]


EventType = Union[
    PasswordDiscovered,
    PasswordCreated,
    PasswordUpdated,
    PasswordUnchanged,
    IssuerDiscovered,
    IssuerCreated,
    IssuerUpdated,
    IssuerUnchanged,
    PasswordPolicyDiscovered,
    PasswordPolicyCreated,
    PasswordPolicyUpdated,
    PasswordPolicyUnchanged,
    PKIRoleDiscovered,
    PKIRoleCreated,
    PKIRoleUpdated,
    PKIRoleUnchanged,
    PostProcessRequested,
]
