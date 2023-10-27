import asyncio
from typing import Any, Coroutine

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
