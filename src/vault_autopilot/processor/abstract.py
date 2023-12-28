import abc


class AbstractProcessor(abc.ABC):
    @abc.abstractmethod
    def register_handlers(self) -> None:
        ...
