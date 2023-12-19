import asyncio
import logging
from dataclasses import InitVar, dataclass, field
from typing import Annotated, Any, AsyncIterator

import annotated_types

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
        max_dispatch: The maximum number of requests that can be dispatched and
            processed concurrently. Defaults to 0, which means no limit is set.
    """

    queue: "parser.QueueType"
    client: InitVar[asyva.client.Client]
    max_dispatch: InitVar[Annotated[int, annotated_types.Ge(0)]] = 0

    _sem: asyncio.Semaphore = field(init=False)

    def __post_init__(self, client: asyva.Client, max_dispatch: int) -> None:
        self._sem = (
            asyncio.Semaphore(max_dispatch)
            if max_dispatch > 0
            else util.coro.BoundlessSemaphore()
        )
        self._is_concurrency_enabled = max_dispatch != 1

        # Initialize processors
        self._payload_proc_map: dict[str, Any] = {
            "Password": processor.PasswordCreateProcessor(state.PasswordState(client)),
            "Issuer": processor.IssuerCreateProcessor(
                state.IssuerState(client), self._sem
            ),
            "PasswordPolicy": processor.PasswordPolicyCreateProcessor(
                state.PasswordPolicyState(client)
            ),
        }

    async def _queue_iter(self) -> AsyncIterator[dto.DTO]:
        while True:
            item = await self.queue.get()
            if isinstance(item, parser.EndByte):
                break
            yield item

    async def dispatch(self) -> None:
        async with asyncio.TaskGroup() as tg:
            async for payload in self._queue_iter():
                try:
                    proc = self._payload_proc_map[payload["kind"]]
                except IndexError:
                    raise TypeError(
                        "Unexpected request kind received: %r" % payload["kind"]
                    )

                coro = proc.process(payload)

                if self._is_concurrency_enabled:
                    await util.coro.create_task_limited(tg, self._sem, coro)
                else:
                    await coro

        await self._payload_proc_map["Issuer"].postprocess()
