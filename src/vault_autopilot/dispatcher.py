import asyncio
import logging
from dataclasses import InitVar, dataclass, field
from typing import Any, AsyncIterator

from . import dto, parser, processor, state, util
from ._pkg import asyva

logger = logging.getLogger(__name__)


@dataclass
class Dispatcher:
    """
    Dispatches user requests to the appropriate processors.

    The Dispatcher plays a crucial role in managing incoming requests by retrieving them
    from a queue and processing them concurrently until the queue is empty or an error
    arises. As a mediator between users and various processors, it ensures that requests
    are directed to the appropriate processor.

    Args:
        queue: The queue containing requests to be processed.
        max_dispatch: The maximum number of requests that can be dispatched & processed
            concurrently.
    """

    queue: parser.QueueType
    client: InitVar[asyva.Client]
    max_dispatch: InitVar[int] = 64

    _sem: asyncio.Semaphore = field(init=False)
    _pending_tasks: set[asyncio.Task[None]] = field(init=False, default_factory=set)

    def __post_init__(self, client: asyva.Client, max_dispatch: int) -> None:
        self._sem = asyncio.Semaphore(max_dispatch + 2)

        # Initialize processors
        self._payload_proc_map: dict[Any, Any] = {
            dto.PasswordCreateDTO: processor.PasswordCreateProcessor(
                state.PasswordState(client)
            ),
            dto.IssuerCreateDTO: processor.IssuerCreateProcessor(
                state.IssuerState(client), self._sem
            ),
            dto.PasswordPolicyCreateDTO: processor.PassowrdPolicyCreateProcessor(
                state.PasswordPolicyState(client)
            ),
        }

    async def _queue_iter(self) -> AsyncIterator[dto.BaseDTO]:
        while True:
            item = await self.queue.get()
            if isinstance(item, parser.EndByte):
                break
            yield item

    async def dispatch(self) -> None:
        async with asyncio.TaskGroup() as tg:
            async for payload in self._queue_iter():
                try:
                    await util.coro.create_task_throttled(
                        tg,
                        self._sem,
                        self._payload_proc_map[type(payload)].process(payload),
                    )
                except IndexError:
                    raise NotImplementedError(
                        "Unexpected request received (payload: %r)." % payload
                    )

        await self._payload_proc_map[dto.IssuerCreateDTO].postprocess()
