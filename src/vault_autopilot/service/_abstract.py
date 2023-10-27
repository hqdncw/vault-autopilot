import abc
from dataclasses import dataclass

from .. import dto


@dataclass
class Service(abc.ABC):
    @abc.abstractmethod
    async def push(self, payload: dto.BaseDTO) -> None:
        ...
