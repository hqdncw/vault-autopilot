from abc import abstractmethod
from asyncio import Task, get_event_loop, sleep
from dataclasses import dataclass, field
from datetime import datetime
from typing import AsyncGenerator, Optional

from humanize import precisedelta
from rich.console import Group, RenderableType
from rich.live import Live
from rich.padding import Padding
from rich.text import Text


@dataclass(slots=True)
class AbstractRenderer:
    @abstractmethod
    def compose_renderable(self) -> RenderableType: ...


@dataclass(slots=True)
class AbstractStage:
    title: str
    renderer: AbstractRenderer

    def compose_renderable(self) -> RenderableType:
        return self.renderer.compose_renderable()


@dataclass(slots=True)
class Workflow:
    _stages: list[AbstractStage]
    _index: int = field(init=False, default=-1)
    _started_at: datetime = field(init=False)
    _think_task: Task[None] = field(init=False)
    _stop_reason: str = ""

    _live: Live = field(init=False)

    @property
    def current_stage(self) -> Optional[AbstractStage]:
        return self._stages[self._index] if self._index != -1 else None

    def __del__(self) -> None:
        self.stop("cancelled")

    async def run(self) -> AsyncGenerator[AbstractStage, None]:
        self._think_task = get_event_loop().create_task(self.think())

        for stage in self._stages:
            self._index += 1
            self._started_at = datetime.now()
            self._stop_reason = ""

            self._live = Live(self._compose_renderable(stage), auto_refresh=False)
            self._live.start()

            yield stage

    async def think(self) -> None:
        while True:
            self.render()
            await sleep(0.1)

    def render(self) -> None:
        assert self.current_stage is not None
        assert self._live.is_started is True

        self._live.update(self._compose_renderable(self.current_stage), refresh=True)

    def _compose_renderable(self, stage: AbstractStage) -> RenderableType:
        label = f"[+] {stage.title} ({self._time_elapsed()})"

        if self._stop_reason:
            label += f" {self._stop_reason.upper()}"

        return Group(
            Text(label),
            Padding(stage.compose_renderable(), (0, 0, 0, 1)),
        )

    def _time_elapsed(self) -> str:
        return precisedelta(
            self._started_at - datetime.now(),
            minimum_unit="seconds",
            suppress=["days"],
            format="%0.4f",
        )

    def stop(self, reason: str) -> None:
        self._stop_reason = reason

        if not self._think_task.cancelling():
            self._think_task.cancel()

        # apply final update before shutting down
        if self._live.is_started:
            self.render()

        # graceful shutdown for the live display
        # https://rich.readthedocs.io/en/stable/live.html#transient-display
        self._live.stop()
