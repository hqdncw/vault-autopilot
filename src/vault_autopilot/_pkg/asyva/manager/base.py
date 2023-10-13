import contextlib
from dataclasses import dataclass, field
from typing import AsyncGenerator, Optional

import aiohttp


@dataclass
class BaseManager:
    _sess: Optional[aiohttp.ClientSession] = field(init=False, default=None)

    def configure(self, sess: aiohttp.ClientSession) -> None:
        self._sess = sess

    @contextlib.asynccontextmanager
    async def new_session(self) -> AsyncGenerator[aiohttp.ClientSession, None]:
        assert self._sess, "The manager isn't configured but session is requested"
        yield self._sess
