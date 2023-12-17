import asyncio
from typing import Any, Coroutine, Literal

_pending_tasks: set[asyncio.Task[Any]] = set()


async def throttle(sem: asyncio.Semaphore, coro: Coroutine[Any, Any, Any]) -> None:
    async with sem:
        await coro


async def create_task_throttled(
    tg: asyncio.TaskGroup, sem: asyncio.Semaphore, coro: Coroutine[Any, Any, Any]
) -> None:
    async with sem:
        task = tg.create_task(throttle(sem, coro))
        _pending_tasks.add(task)
        task.add_done_callback(_pending_tasks.discard)


class BoundlessSemaphore(asyncio.Semaphore):
    def locked(self) -> bool:
        return False

    async def acquire(self) -> Literal[True]:
        return True

    def release(self) -> None:
        return
