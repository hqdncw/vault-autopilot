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
        self._handlers.append(HandlerObject(filter_, callback))

    async def trigger(self, event: T) -> None:
        async with asyncio.TaskGroup() as tg:
            for handler in filter(lambda h: type(event) in h.filter, self._handlers):
                await util.coro.create_task_limited(
                    tg, util.coro.BoundlessSemaphore(), handler.callback(event)
                )


@dataclass(slots=True)
class PasswordDiscovered:
    payload: dto.PasswordInitializeDTO


@dataclass(slots=True)
class PasswordCreated:
    payload: dto.PasswordInitializeDTO


@dataclass(slots=True)
class PasswordUpdated:
    payload: dto.PasswordInitializeDTO


@dataclass(slots=True)
class PasswordUnchanged:
    payload: dto.PasswordInitializeDTO


@dataclass(slots=True)
class IssuerDiscovered:
    payload: dto.IssuerInitializeDTO


@dataclass(slots=True)
class IssuerCreated:
    payload: dto.IssuerInitializeDTO


@dataclass(slots=True)
class IssuerUpdated:
    payload: dto.IssuerInitializeDTO


@dataclass(slots=True)
class IssuerUnchanged:
    payload: dto.IssuerInitializeDTO


@dataclass(slots=True)
class PasswordPolicyDiscovered:
    payload: dto.PasswordPolicyInitializeDTO


@dataclass(slots=True)
class PasswordPolicyCreated:
    payload: dto.PasswordPolicyInitializeDTO


@dataclass(slots=True)
class PasswordPolicyUpdated:
    payload: dto.PasswordPolicyInitializeDTO


@dataclass(slots=True)
class PasswordPolicyUnchanged:
    payload: dto.PasswordPolicyInitializeDTO


@dataclass(slots=True)
class PostProcessRequested:
    """
    After all manifests have been processed, this event is triggered by the dispatcher,
    providing an opportunity to examine resources with unsatisfied dependencies. This
    can include situations such as passwords awaiting initialization of password
    policies or intermediate issuers waiting for initialization of upstream issuers.

    See also:
        * :class:`PasswordInitialized`
        * :class:`IssuerInitialized`
        * :class:`PasswordPolicyInitialized`
    """


ResourceDiscovered = Union[
    PasswordDiscovered, IssuerDiscovered, PasswordPolicyDiscovered
]
PasswordInitialized = Union[PasswordCreated, PasswordUpdated, PasswordUnchanged]
IssuerInitialized = Union[IssuerCreated, IssuerUpdated, IssuerUnchanged]
PasswordPolicyInitialized = Union[
    PasswordPolicyCreated, PasswordPolicyUpdated, PasswordPolicyUnchanged
]


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
    PostProcessRequested,
]
