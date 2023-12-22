import abc
import logging
from dataclasses import dataclass, field
from typing import (
    Generic,
    Iterable,
    Iterator,
    Literal,
    NoReturn,
    TypedDict,
    TypeVar,
    Union,
)

import more_itertools
import networkx as nx

logger = logging.getLogger(__name__)


T = TypeVar("T")
P = TypeVar("P")
EdgeStatusType = Literal["unsatisfied", "in_process", "satisfied"]


class AbstractNode:
    @abc.abstractmethod
    def __hash__(self) -> int:
        """
        The hash serves as a unique identifier for the node, enabling the manager to
        differentiate between multiple nodes and order their dependencies correctly.
        """


class _EdgeData(TypedDict):
    status: EdgeStatusType


@dataclass(slots=True)
class DependencyManager(Generic[T]):
    """
    A class for managing dependencies between objects.

    The :class:`DependencyManager` is a data structure that allows you to add and remove
    edges between objects, representing dependencies between them. It can be used to
    compute the dependency order of a set of objects, which is useful in situations
    where certain objects must be processed before others.
    """

    _graph: nx.DiGraph = field(init=False, default_factory=nx.DiGraph)

    @staticmethod
    def _raise_edge_not_found_exc(u: int, v: int) -> NoReturn:
        raise ValueError("Edge not found (u: %r, v: %r)" % (hash(u), hash(v)))

    def _assert_node_presence(self, node: T) -> None:
        assert hash(node) in self._graph.nodes

    @staticmethod
    def _edge_is_unsatisfied(edge: tuple[int, int, _EdgeData]) -> bool:
        return edge[2]["status"] == "unsatisfied"

    def _get_edge_data(self, u: int, v: int) -> _EdgeData:
        return self._graph[u][v]  # type: ignore[no-any-return]

    def _get_node_payload(self, node_hash: int) -> T:
        return self._graph.nodes[node_hash]["payload"]  # type: ignore[no-any-return]

    def add_node(self, node: T) -> None:
        hash_ = hash(node)
        self._graph.add_node(hash_, payload=node)
        logger.debug("added node %r with payload %r", hash_, node)

    def get_node_by_hash(self, value: int, default: P) -> Union[T, P]:
        if self._graph.nodes.get(value, default=None) is None:
            return default
        return self._get_node_payload(value)

    def remove_nodes(self, nodes: Iterable[T]) -> None:
        self._graph.remove_nodes_from(nodes)

    def relabel_nodes(self, pairs: Iterable[tuple[T, T]]) -> None:
        """
        Examples:
            >>> mgr = DependencyManager()
            >>> mgr.add_node("A")
            >>> mgr.add_node("B")
            >>> mgr.add_node("C")
            >>> mgr.relabel_nodes([("A", "X"), ("B", "Y"), ("C", "Z")])
            >>> print(mgr._graph.nodes)
            {"X", "Y", "Z"}
        """
        nx.set_node_attributes(
            self._graph,
            {
                hash_: {"payload": node}
                for hash_, node in ((hash(from_), to) for from_, to in pairs)
            },
        )

    def add_edge(
        self,
        u: T,
        v: T,
        status: EdgeStatusType = "unsatisfied",
    ) -> None:
        """
        Adds an edge from u to v, indicating that v depends on u.
        """
        self._assert_node_presence(u)
        self._assert_node_presence(v)
        u_hash, v_hash = hash(u), hash(v)
        self._graph.add_edge(u_hash, v_hash, status=status)
        logger.debug("added edge (u: %r, v: %r)", u_hash, v_hash)

    def update_edge_status(self, u: T, v: T, status: EdgeStatusType) -> None:
        self._assert_node_presence(u)
        self._assert_node_presence(v)
        u_hash, v_hash = hash(u), hash(v)
        try:
            self._graph[u_hash][v_hash]["status"] = status
        except IndexError:
            self._raise_edge_not_found_exc(u_hash, v_hash)

    def get_edge_status(self, u: T, v: T) -> EdgeStatusType:
        u_hash, v_hash = hash(u), hash(v)
        try:
            data = self._get_edge_data(u_hash, v_hash)
        except IndexError:
            self._raise_edge_not_found_exc(u_hash, v_hash)
        return data["status"]

    def are_edges_satisfied(self, node: T) -> bool:
        """Checks whether the inbound edges of a node are satisfied."""
        return not bool(
            more_itertools.first_true(
                self._graph.in_edges(hash(node), data=True, default={}),
                pred=self._edge_is_unsatisfied,  # type: ignore[arg-type]
                default=True,
            )
        )

    def find_unsatisfied_nodes(self, node: T) -> Iterator[T]:
        """Yields nodes with unsatisfied inbound edges coming from the given node."""
        return (
            self._get_node_payload(nbr)
            for nbr in self._graph.neighbors(hash(node))
            if not self.are_edges_satisfied(self._graph.nodes[nbr]["payload"])
        )

    def find_all_unsatisfied_edges(self) -> Iterator[tuple[T, T]]:
        """
        Yields all edges in the graph that have unsatisfied status.
        """
        return map(
            lambda edge: (
                self._get_node_payload(edge[0]),
                self._get_node_payload(edge[1]),
            ),
            filter(
                lambda edge: self._edge_is_unsatisfied(
                    edge  # pyright: ignore[reportGeneralTypeIssues]
                ),
                iter(self._graph.in_edges(data=True, default={})),
            ),
        )
