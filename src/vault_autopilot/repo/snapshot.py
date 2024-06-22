from dataclasses import dataclass
from typing import Any, Generic

from humps import camelize
from typing_extensions import TypeVar

from ..dto.abstract import AbstractDTO

T = TypeVar("T", bound=AbstractDTO)


@dataclass(slots=True)
class SnapshotRepo(Generic[T]):
    storage: dict[Any, Any]
    snapshot_builder: type[T]

    async def get(self, path: str) -> T | None:
        return (
            self.snapshot_builder.model_construct(**raw_data)
            if (raw_data := self.storage.get(path, {}))
            else None
        )

    async def put(self, path: str, payload: T) -> None:
        self.storage.update({path: camelize(payload.__dict__)})
