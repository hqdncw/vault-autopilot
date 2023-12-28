import asyncio
import functools
from typing import Any, Coroutine, Literal

__all__ = "create_task_limited", "BoundlessSemaphore"

_pending_tasks: set[asyncio.Task[Any]] = set()


def _release_sem_and_remove_task(
    task: asyncio.Task[Any], *, sem: asyncio.Semaphore
) -> None:
    sem.release()
    _pending_tasks.discard(task)


async def create_task_limited(
    tg: asyncio.TaskGroup, sem: asyncio.Semaphore, coro: Coroutine[Any, Any, Any]
) -> None:
    """
    Create a task and store a reference to it until the task completes, respecting a
    semaphore limit.

    Args:
        tg: Task group to create the task in.
        sem: Semaphore to acquire before creating the task.
        coro: Coroutine to run as the task.
    """
    await sem.acquire()
    task = tg.create_task(coro)
    _pending_tasks.add(task)
    task.add_done_callback(functools.partial(_release_sem_and_remove_task, sem=sem))


class BoundlessSemaphore(asyncio.Semaphore):
    def locked(self) -> bool:
        return False

    async def acquire(self) -> Literal[True]:
        return True

    def release(self) -> None:
        return
