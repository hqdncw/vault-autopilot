import asyncio
import logging
from dataclasses import InitVar, dataclass, field
from typing import Annotated, AsyncIterator

import annotated_types

from .. import dto, parser, processor, state, util
from .._pkg import asyva
from . import event

logger = logging.getLogger(__name__)

MaxDispatchType = Annotated[int, annotated_types.Ge(0)]


@dataclass
class Dispatcher:
    """
    Dispatches DTOs to the relevant processors.

    Args:
        queue: The queue containing DTOs to be processed.
        max_dispatch: The maximum number of DTOs that can be dispatched and processed
            concurrently. Defaults to ``0``, which means no limit is set.
    """

    queue: "parser.QueueType"
    client: InitVar[asyva.client.Client]
    max_dispatch: InitVar[MaxDispatchType] = 0

    _sem: asyncio.Semaphore = field(init=False)
    _observer: event.EventObserver[event.EventType] = field(
        init=False, default_factory=event.EventObserver
    )

    def __post_init__(
        self, client: asyva.Client, max_dispatch: MaxDispatchType
    ) -> None:
        self._sem = (
            asyncio.BoundedSemaphore(max_dispatch)
            if max_dispatch > 0
            else util.coro.BoundlessSemaphore()
        )
        self._is_concurrency_enabled = max_dispatch != 1

        # Initialize processors
        self._payload_proc_map = {
            "Password": processor.PasswordInitializeProcessor(
                state.PasswordState(client, self._sem, self._observer)
            ),
            "Issuer": processor.IssuerInitializeProcessor(
                state.IssuerState(client, self._sem, self._observer)
            ),
            "PasswordPolicy": processor.PasswordPolicyInitializeProcessor(
                state.PasswordPolicyState(client, self._sem, self._observer)
            ),
        }

        # register the handlers so the processors can handle events the Dispatcher
        # triggers
        for proc in self._payload_proc_map.values():
            proc.register_handlers()

    async def _queue_iter(self) -> AsyncIterator[dto.DTO]:
        while True:
            item = await self.queue.get()
            if isinstance(item, parser.EndByte):
                break
            yield item

    def _build_discovery_event(self, payload: dto.DTO) -> event.ResourceDiscovered:
        if payload.kind == "Password":
            return event.PasswordDiscovered(payload)
        if payload.kind == "Issuer":
            return event.IssuerDiscovered(payload)
        if payload.kind == "PasswordPolicy":
            return event.PasswordPolicyDiscovered(payload)

        raise TypeError("Unexpected payload type: %r" % payload)

    async def dispatch(self) -> None:
        async with asyncio.TaskGroup() as tg:
            async for payload in self._queue_iter():
                # dispatch the payload to the relevant processor that can handle it
                coro = self._observer.trigger(self._build_discovery_event(payload))

                # If concurrency is enabled, create a new task limited by the semaphore
                # otherwise, just wait for the coroutine to finish
                if self._is_concurrency_enabled:
                    await util.coro.create_task_limited(tg, self._sem, coro)
                else:
                    await coro

        await self._observer.trigger(event.PostProcessRequested())
