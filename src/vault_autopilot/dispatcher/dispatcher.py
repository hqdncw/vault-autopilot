import asyncio
import logging
from dataclasses import InitVar, dataclass, field
from typing import Annotated, TYPE_CHECKING
from collections.abc import AsyncIterator

import annotated_types
from ironfence import Mutex

from vault_autopilot.util.dependency_chain import DependencyChain

from ..util.coro import (
    BoundlessSemaphore,
    create_task_limited,
)

from .. import dto
from ..service import (
    PasswordPolicyService,
    IssuerService,
    PasswordService,
    PKIRoleService,
)
from ..processor import (
    AbstractProcessor,
    PKIRoleApplyProcessor,
    IssuerApplyProcessor,
    PasswordPolicyApplyProcessor,
    PasswordApplyProcessor,
)
from .._pkg import asyva
from . import event

if TYPE_CHECKING:
    from ..parser import QueueType

logger = logging.getLogger(__name__)

MaxDispatchType = Annotated[int, annotated_types.Ge(0)]


@dataclass
class Dispatcher:
    """
    Dispatches DTOs to the relevant processors.

    Attributes:
        queue: The queue containing DTOs to be dispatched.
        max_dispatch: The maximum number of DTOs that can be dispatched and processed
            concurrently. Defaults to ``0``, which means no limit is set.
    """

    queue: "QueueType"
    client: InitVar[asyva.client.Client]
    max_dispatch: InitVar[MaxDispatchType] = 0

    _sem: asyncio.Semaphore = field(init=False)
    _observer: event.EventObserver[event.EventType] = field(
        init=False, default_factory=event.EventObserver
    )
    _is_concurrency_enabled: bool = field(init=False)
    _payload_proc_map: dict[  # pyright: ignore[reportRedeclaration]
        str, AbstractProcessor
    ] = field(init=False)

    def __post_init__(
        self, client: asyva.Client, max_dispatch: MaxDispatchType
    ) -> None:
        self._sem = (
            asyncio.BoundedSemaphore(max_dispatch)
            if max_dispatch > 0
            else BoundlessSemaphore()
        )
        self._is_concurrency_enabled = max_dispatch != 1

        # TODO: Allow processors to share the same dependency chain to reduce memory
        #  consumption.

        # Initialize processors
        self._payload_proc_map: dict[str, AbstractProcessor] = {
            "Password": PasswordApplyProcessor(
                sem=self._sem,
                client=client,
                observer=self._observer,
                dep_chain=Mutex(DependencyChain()),
                pwd_svc=PasswordService(client),
            ),
            "Issuer": IssuerApplyProcessor(
                sem=self._sem,
                client=client,
                observer=self._observer,
                dep_chain=Mutex(DependencyChain()),
                iss_svc=IssuerService(client),
            ),
            "PasswordPolicy": PasswordPolicyApplyProcessor(
                sem=self._sem,
                client=client,
                observer=self._observer,
                pwd_policy_svc=PasswordPolicyService(client),
            ),
            "PKIRole": PKIRoleApplyProcessor(
                sem=self._sem,
                client=client,
                observer=self._observer,
                dep_chain=Mutex(DependencyChain()),
                pki_role_svc=PKIRoleService(client),
            ),
        }

        # Enable the processors to handle events triggered by the Dispatcher
        for proc in self._payload_proc_map.values():
            proc.initialize()

    async def dispatch(self) -> None:
        async with asyncio.TaskGroup() as tg:
            async for payload in self._queue_iter():
                # dispatch the payload to the relevant processor that can handle it
                coro = self._observer.trigger(self._build_event_from_request(payload))

                # If concurrency is enabled, create a new task limited by the semaphore
                # otherwise, just wait for the coroutine to finish
                if self._is_concurrency_enabled:
                    await create_task_limited(tg, self._sem, coro)
                else:
                    await coro

        await self._observer.trigger(event.PostProcessRequested())

    def register_handler(
        self, filter_: event.FilterType[event.EventType], callback: event.CallbackType
    ) -> None:
        self._observer.register(filter_, callback)

    async def _queue_iter(self) -> AsyncIterator[dto.DTO]:
        while True:
            item = await self.queue.get()
            if item is None:
                break
            yield item

    def _build_event_from_request(
        self, payload: dto.DTO
    ) -> event.ResourceApplyRequested:
        if payload.kind == "Password":
            return event.PasswordApplyRequested(payload)
        if payload.kind == "Issuer":
            return event.IssuerApplyRequested(payload)
        if payload.kind == "PasswordPolicy":
            return event.PasswordPolicyApplyRequested(payload)
        if payload.kind == "PKIRole":
            return event.PKIRoleApplyRequested(payload)

        raise TypeError("Unexpected payload type: %r" % payload)
