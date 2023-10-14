import asyncio
import logging
import typing
from dataclasses import InitVar, dataclass, field
from typing import AsyncIterator, Coroutine

import asyncstdlib

from . import dto

logger = logging.getLogger(__name__)


if typing.TYPE_CHECKING:
    from . import service


PrioritizedItem = tuple[int, dto.BaseDTO]


@dataclass(slots=True)
class Dispatcher:
    """
    Dispatches items stored in a queue until the queue is empty or an error occurs.

    Handles various DTO types, such as passwords, SSH keys, or PKI roles, and acts as a
    middleman between push requests and relevant services that can handle them.

    :param passwd_svc: Service for handling password-related operations
    :param event_loop: Asyncio event loop
    :param queue: Priority queue containing items to be processed
    :param max_dispatch:
        Represents the maximum number of items that can be dispatched concurrently,
        defaults to 64
    """

    passwd_svc: "service.PasswordService"
    queue: asyncio.PriorityQueue[PrioritizedItem]
    max_dispatch: InitVar[int] = 64

    _sem: asyncio.Semaphore = field(init=False)
    _pending_tasks: set[asyncio.Task[None]] = field(init=False, default_factory=set)

    def __post_init__(self, max_dispatch: int) -> None:
        self._sem = asyncio.Semaphore(max_dispatch + 1)

    async def dispatch(self) -> None:
        """
        Retrieves items from the queue and processes them based on their priority level.
        If multiple items share the same priority, they are processed concurrently, but
        only up to a certain limit (known as `max_dispatch`) of concurrent operations.
        """
        logger.debug("dispatching started (qsize: %d)" % self.queue.qsize())

        # Use a generator expression to iterate over the queue and process items
        # with the same priority concurrently
        async for prio, batch in asyncstdlib.groupby(
            self._queue_iter(), key=lambda x: x[0]
        ):
            logger.debug("priority %d" % prio)

            async with asyncio.TaskGroup() as tg:
                async for prio, item in batch:
                    await self._throttle(
                        self._create_task(
                            tg=tg,
                            coro=self._throttle(self._process(item)),
                            callback=self._pending_tasks.discard,
                        )
                    )

        logger.debug("dispatching finished")

    async def _queue_iter(self) -> AsyncIterator[PrioritizedItem]:
        try:
            yield await self.queue.get()
        except asyncio.QueueEmpty:
            return

    async def _create_task(
        self,
        tg: asyncio.TaskGroup,
        coro: Coroutine[None, None, None],
        callback: typing.Callable[..., None],
    ) -> None:
        task = tg.create_task(coro)
        task.add_done_callback(callback)
        self._pending_tasks.add(task)

    async def _throttle(self, coro: Coroutine[None, None, None]) -> None:
        async with self._sem:
            await coro

    async def _process(self, item: dto.BaseDTO) -> None:
        """Handles a single DTO."""
        match type(item):
            case dto.PasswordDTO:
                await self.passwd_svc.push(payload=item)
            case _:
                raise NotImplementedError("Unexpected object %r" % item)
        self.queue.task_done()
