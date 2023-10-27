import asyncio
import logging
import reprlib
import typing
from dataclasses import dataclass
from typing import IO, Any, Iterator, Type

import pydantic
import yaml

from . import dto, exc, util

if typing.TYPE_CHECKING:
    from yaml.reader import _ReadStream as ReadStream

QueueType = asyncio.Queue["dto.BaseDTO | EndByte"]

logger = logging.getLogger(__name__)


_KIND_SCHEMA_MAP = {
    "Password": dto.PasswordCreateDTO,
    "Issuer": dto.IssuerCreateDTO,
    "PasswordPolicy": dto.PasswordPolicyCreateDTO,
}


class EndByte:
    """Indicates that the parser has finished parsing."""


class Loader(yaml.SafeLoader):
    stream_scoped_anchors = False

    def __init__(self, stream: "ReadStream") -> None:
        self.locations: list[int] = []
        super().__init__(stream)

    def compose_document(self) -> Any:
        # Drop the DOCUMENT-START event.
        self.get_event()  # type: ignore[no-untyped-call]
        # Compose the root node.
        node = self.compose_node(None, None)  # type: ignore[arg-type]
        # Drop the DOCUMENT-END event.
        self.get_event()  # type: ignore[no-untyped-call]

        if not self.stream_scoped_anchors:
            self.anchors = {}

        return node

    # def construct_object(self, node: "yaml.nodes.Node", deep: bool = False) -> Any:
    #     obj = super().construct_object(node, deep=deep)
    #     num = node.start_mark.line
    #     self.locations[id(obj)] = isinstance(obj, dict) and num or num + 1
    #     return obj


# def load_all(
#     stream: "yaml.reader._ReadStream", loader: Loader, share_anchors: bool
# ) -> Iterator[tuple[Any, list[int]]]:
#     """
#     Parse all YAML documents in a stream and produce corresponding Python objects.
#     """
#     loader = parametrized_loader(Loader, share_anchors=share_anchors)(stream)
#     try:
#         while loader.check_data():
#             yield loader.get_data(), loader.locations
#     finally:
#         loader.dispose()


def with_parameters(cls: Type[Loader], stream_scoped_anchors: bool) -> Type[Loader]:
    setattr(cls, "stream_scoped_anchors", stream_scoped_anchors)
    return cls


@dataclass(slots=True)
class YamlParser:
    """
    This parser is responsible for processing YAML manifests received from the
    specified binary output. It extracts data from these manifests and creates
    DTO objects, which it then places in the FIFO queue.
    """

    # TODO: Implement a file-based queue modeled after
    #  tempfile.SpooledTemporaryFile to efficiently manage large datasets while
    #  avoiding memory overflow.

    queue: QueueType
    streamer: Iterator[IO[bytes]]
    file_scoped_anchors: bool

    async def execute(self) -> QueueType:
        logger.debug("parsing files started")

        for reader in self.streamer:
            try:
                for payload in yaml.load_all(
                    reader,
                    with_parameters(
                        Loader, stream_scoped_anchors=self.file_scoped_anchors
                    ),
                ):
                    await self._put(await self._validate(payload, filename=reader.name))
            except yaml.error.MarkedYAMLError as ex:
                raise exc.ManifestValidationError(
                    str(ex), filename=str(reader.name)
                ) from ex

        await self.queue.put(EndByte())

        logger.debug("parsing files finished")

        return self.queue

    async def _validate(self, payload: dict[str, Any], filename: str) -> dto.BaseDTO:
        if not isinstance(payload, dict) or (kind := payload.get("kind")) is None:
            raise exc.ManifestValidationError(
                "Mapping 'kind' is missing in %s" % reprlib.repr(payload),
                filename=filename,
            )

        if kind in _KIND_SCHEMA_MAP.keys():
            schema = _KIND_SCHEMA_MAP[kind]
        else:
            raise exc.ManifestKindMismatchError(
                "Unsupported kind %r. Supported object kinds include: %s"
                % (kind, str(_KIND_SCHEMA_MAP.keys())),
                filename=filename,
                provided_kind=kind,
            )

        try:
            return schema(**payload)
        except pydantic.ValidationError as ex:
            # TODO: print the contents of a YAML file, highlighting any invalid
            #  lines.
            raise exc.ManifestValidationError(
                str(util.pydantic.convert_errors(ex)), filename=filename
            )

    async def _put(self, payload: dto.BaseDTO) -> None:
        await self.queue.put(payload)
        logger.debug("put %r" % payload)
