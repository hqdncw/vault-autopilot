import asyncio
import logging
from collections.abc import AsyncIterator
from dataclasses import InitVar, dataclass, field
from typing import Annotated, Callable, Generic, TypeVar

import annotated_types

from .._pkg import asyva
from ..processor import (
    AbstractProcessor,
)
from ..util.coro import (
    BoundlessSemaphore,
    create_task_limited,
)
from . import event

T = TypeVar("T")
P = TypeVar("P")
MaxDispatchType = Annotated[int, annotated_types.Ge(0)]

logger = logging.getLogger(__name__)


@dataclass
class Dispatcher(Generic[T, P]):
    """
    Dispatches DTOs to the relevant processors.

    Attributes:
        queue: The queue containing DTOs to be dispatched.
        max_dispatch: The maximum number of DTOs that can be dispatched and processed
            concurrently. Defaults to ``0``, which means no limit is set.
    """

    queue: asyncio.Queue[T | None]
    client: InitVar[asyva.client.Client]
    processing_registry: InitVar[dict[str, AbstractProcessor[P]]]
    observer: event.EventObserver[P]
    event_builder: Callable[[T | None], P]
    max_dispatch: InitVar[MaxDispatchType] = 0

    _sem: asyncio.Semaphore = field(init=False)
    _is_concurrency_enabled: bool = field(init=False)

    def __post_init__(
        self,
        client: asyva.Client,
        processing_registry: dict[str, AbstractProcessor[P]],
        max_dispatch: MaxDispatchType,
    ) -> None:
        self._sem = (
            asyncio.BoundedSemaphore(max_dispatch)
            if max_dispatch > 0
            else BoundlessSemaphore()
        )
        self._is_concurrency_enabled = max_dispatch != 1
        self._processing_registry = processing_registry

        # Enable the processors to handle events triggered by the Dispatcher
        for proc in self._processing_registry.values():
            proc.initialize()

    async def dispatch(self) -> int:
        """
        Dispatches payloads from the queue to their corresponding processors.

        Returns:
            The number of payloads dispatched.
        """
        counter = 0

        async with asyncio.TaskGroup() as tg:
            async for payload in self._queue_iter():
                # dispatch the payload to the relevant processor that can handle it
                coro = self.observer.trigger(self.event_builder(payload))

                # If concurrency is enabled, create a new task limited by the semaphore
                # otherwise, just wait for the coroutine to finish
                if self._is_concurrency_enabled:
                    await create_task_limited(tg, self._sem, coro)
                else:
                    await coro

                counter += 1

        # shutdown event
        await self.observer.trigger(self.event_builder(None))

        return counter

    def register_handler(
        self, filter_: event.FilterType[P], callback: event.CallbackType
    ) -> None:
        self.observer.register(filter_, callback)

    async def _queue_iter(self) -> AsyncIterator[T]:
        while True:
            item = await self.queue.get()
            if item is None:
                break
            yield item
