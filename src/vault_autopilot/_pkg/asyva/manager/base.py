import contextlib
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any, Self

import aiohttp
from pydantic import BaseModel


class AbstractResult(BaseModel):
    request_id: str
    lease_id: str
    renewable: bool
    lease_duration: int
    wrap_info: Any
    warnings: list[str] | None = None
    auth: Any

    @classmethod
    def from_response(cls, data: dict[str, Any]) -> Self:
        return cls.model_construct(**data)  # type: ignore[return-value]


@dataclass(slots=True)
class BaseManager:
    _sess: aiohttp.ClientSession | None = field(init=False, default=None)

    def configure(self, sess: aiohttp.ClientSession) -> None:
        self._sess = sess

    @contextlib.asynccontextmanager
    async def new_session(self) -> AsyncGenerator[aiohttp.ClientSession, None]:
        assert self._sess, "The manager isn't configured but session is requested"
        yield self._sess
