import abc
from collections.abc import Iterable, Iterator
import logging
from dataclasses import dataclass, field
from typing import (
    Callable,
    Generic,
    Literal,
    NoReturn,
    TypedDict,
    TypeVar,
)
from typing_extensions import override

from networkx import DiGraph, set_node_attributes

T = TypeVar("T")
P = TypeVar("P")

DependencyStatus = Literal[
    # The dependency is not satisfied yet.
    "pending",
    # The dependency is in the process of being satisfied.
    "in_progress",
    # The dependency is satisfied.
    "satisfied",
]
"""Represents the status of a dependency in a dependency graph."""

logger = logging.getLogger(__name__)
default_obj = object()


@dataclass(slots=True)
class AbstractNode:
    @override
    @abc.abstractmethod
    def __hash__(self) -> int:
        """
        The hash serves as a unique identifier for the node, enabling the dependency
        chain differentiate between multiple nodes and order their dependencies
        correctly.
        """


@dataclass(slots=True)
class FallbackNode(AbstractNode):
    """
    Efficiently represents a :class:`Node` object before its payload is available.

    When working with large datasets, it's often necessary to establish relationships
    between nodes before their payloads are fully loaded. This class allows you to
    create a fallback node that can be used for ordering dependencies without having
    to wait for the full node information.

    Once a `FallbackNode` has been created, it can be used in place of a regular
    `Node` object.

    Example:
        >>> @dataclass
        ... class Node(AbstractNode):
        ...    uid: int
        ...    payload: Any
        ...
        ...   @override
        ...   def __hash__(self) -> int:
        ...       return hash(self.uid)
        ...
        ... uid = 123
        ... assert hash(FallbackNode(uid)) == hash(Node(uid=uid, payload="foo"))
    """

    node_hash: int

    @override
    def __hash__(self) -> int:
        return self.node_hash


class _EdgeAttrs(TypedDict):
    status: DependencyStatus


@dataclass(slots=True)
class DependencyChain(Generic[T]):
    """
    A class for managing dependencies between objects.

    The :class:`DependencyChain` is a data structure that allows you to add and remove
    edges between objects, representing dependencies between them. It can be used to
    compute the dependency order of a set of objects, which is useful in situations
    where certain objects must be processed before others.
    """

    _graph: "DiGraph[int]" = field(init=False, default_factory=DiGraph)

    @staticmethod
    def _raise_edge_not_found_exc(u: int, v: int) -> NoReturn:
        raise ValueError("Edge not found (u: %r, v: %r)" % (hash(u), hash(v)))

    @staticmethod
    def _is_pending(edge: tuple[int, int, _EdgeAttrs]) -> bool:
        return edge[2]["status"] == "pending"

    @staticmethod
    def _is_satisfied(edge: tuple[int, int, _EdgeAttrs]) -> bool:
        return edge[2]["status"] == "satisfied"

    def _get_edge_data(self, u: int, v: int) -> _EdgeAttrs:
        return self._graph[u][v]  # pyright: ignore[reportReturnType]

    def _get_node_payload(self, node_hash: int) -> T:
        return self._graph.nodes[node_hash]["payload"]

    def add_node(self, node: T) -> int:
        node_hash = hash(node)

        self._graph.add_node(node_hash, payload=node)
        logger.debug("added node %r with payload %r", node_hash, node)
        return node_hash

    def get_node_by_hash(self, value: int, default: P) -> T | P:
        if self._graph.nodes.get(value, default=None) is None:
            return default
        return self._get_node_payload(value)

    def remove_nodes(self, nodes: Iterable[T]) -> None:
        self._graph.remove_nodes_from(hash(n) for n in nodes)

    def relabel_nodes(self, pairs: Iterable[tuple[T, T]]) -> None:
        """
        Examples:
            >>> mgr = DependencyChain()
            >>> mgr.add_node("A")
            >>> mgr.add_node("B")
            >>> mgr.add_node("C")
            >>> mgr.relabel_nodes([("A", "X"), ("B", "Y"), ("C", "Z")])
            >>> print(mgr._graph.nodes)
            {"X", "Y", "Z"}
        """
        set_node_attributes(
            self._graph,
            {
                node_hash: {"payload": node}
                for node_hash, node in ((hash(from_), to) for from_, to in pairs)
            },
        )

    def add_edge(
        self,
        u: T,
        v: T,
        status: DependencyStatus = "pending",
    ) -> None:
        """
        Adds an edge from u to v, indicating that v depends on u.
        """
        u_hash, v_hash = self.add_node(u), self.add_node(v)
        self._graph.add_edge(u_hash, v_hash, status=status)  # pyright: ignore[reportUnknownMemberType]
        logger.debug("added edge (u: %r, v: %r)", u_hash, v_hash)

    def has_node(self, node: T) -> bool:
        return self._graph.has_node(hash(node))

    def has_edge(self, u: T, v: T) -> bool:
        return self._graph.has_edge(hash(u), hash(v))

    def update_edge_status(self, u: T, v: T, status: DependencyStatus) -> None:
        u_hash, v_hash = hash(u), hash(v)
        try:
            self._graph[u_hash][v_hash]["status"] = status  # pyright: ignore[reportArgumentType]
        except IndexError:
            self._raise_edge_not_found_exc(u_hash, v_hash)

    def get_edge_status(self, u: T, v: T) -> DependencyStatus:
        u_hash, v_hash = hash(u), hash(v)
        try:
            data = self._get_edge_data(u_hash, v_hash)
        except IndexError:
            self._raise_edge_not_found_exc(u_hash, v_hash)
        return data["status"]

    def are_inbound_edges_satisfied(
        self,
        node: T,
        default: P,
        exclude: Callable[[tuple[int, int]], bool] = lambda _: False,
    ) -> bool | P:
        """
        Checks if all inbound edges of a given node have their status satisfied.

        If the node has no inbound edges, returns the default value.

        Args:
            default: The value to return if the node has no inbound edges.
            exclude: A callable that takes a tuple of adjacent nodes (representing a
                     dependency) and returns a boolean. If True, the edge will be
                     excluded from the check.

        Returns:
            True if all inbound edges are satisfied, False otherwise. If the node has
            no inbound edges, returns the default value.

        """
        return (
            next(
                filter(
                    lambda edge: exclude(edge[:2])
                    and False
                    or not self._is_satisfied(edge),  # pyright: ignore[reportArgumentType]
                    self._graph.in_edges(hash(node), data=True),
                ),
                default_obj,
            )
            == id(default_obj)
            and default
        )

    def filter_upstreams(self, node: T, function: Callable[[T], bool]) -> Iterator[T]:
        """
        Filters the upstreams of a given node based on a provided function.

        Args:
            node: The node to filter upstreams for.
            function: A function that takes a node payload as input and returns a boolean value.

        Returns:
            An iterator of node payloads that satisfy the provided function.
        """
        for nbr in self._graph.predecessors(hash(node)):
            if function((payload := self._get_node_payload(nbr))):
                yield payload

    def filter_downstreams(self, node: T, function: Callable[[T], bool]) -> Iterator[T]:
        """
        Filters the downstreams of a given node based on a provided function.

        Args:
            node: The node to filter downstreams for.
            function: A function that takes a node payload as input and returns a boolean value.

        Returns:
            An iterator of node payloads that satisfy the provided function.
        """
        for nbr in self._graph.successors(hash(node)):
            if function((payload := self._get_node_payload(nbr))):
                yield payload

    def get_pending_edges(self) -> Iterator[tuple[T, T]]:
        """
        Yields any edges in the graph that have ``pending`` status.
        """
        return map(
            lambda edge: (
                self._get_node_payload(edge[0]),
                self._get_node_payload(edge[1]),
            ),
            filter(  # pyright: ignore[reportCallIssue]
                lambda edge: self._is_pending(edge),  # pyright: ignore[reportArgumentType]
                self._graph.in_edges(data=True, default={}),  # pyright: ignore[reportArgumentType, reportCallIssue]
            ),
        )
