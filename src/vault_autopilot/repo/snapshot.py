from dataclasses import dataclass
from typing import Generic

from humps import camelize
from typing_extensions import TypeVar

from vault_autopilot.storage import KvV2SecretStorage

from ..dto.abstract import AbstractDTO

T = TypeVar("T", bound=AbstractDTO)


@dataclass(slots=True)
class SnapshotRepo(Generic[T]):
    prefix: str
    storage: KvV2SecretStorage
    snapshot_builder: type[T]

    def build_key(self, path: str) -> str:
        return self.prefix + path

    async def get(self, path: str) -> T | None:
        return (
            self.snapshot_builder.model_construct(**raw_data)
            if (raw_data := self.storage.get(self.build_key(path), {}))
            else None
        )

    async def put(self, path: str, payload: T) -> None:
        self.storage.update({self.build_key(path): camelize(payload.__dict__)})
