import abc
import logging
from dataclasses import dataclass, field
from typing import (
    Callable,
    Generic,
    Iterable,
    Iterator,
    Literal,
    NoReturn,
    TypedDict,
    TypeVar,
    Union,
)

import networkx as nx

T = TypeVar("T")
P = TypeVar("P")
EdgeStatusType = Literal["unsatisfied", "in_process", "satisfied"]

logger = logging.getLogger(__name__)
default_obj = object()


class AbstractNode:
    @abc.abstractmethod
    def __hash__(self) -> int:
        """
        The hash serves as a unique identifier for the node, enabling the manager to
        differentiate between multiple nodes and order their dependencies correctly.
        """


class _EdgeAttrs(TypedDict):
    status: EdgeStatusType


@dataclass(slots=True)
class DependencyChain(Generic[T]):
    """
    A class for managing dependencies between objects.

    The :class:`DependencyChain` is a data structure that allows you to add and remove
    edges between objects, representing dependencies between them. It can be used to
    compute the dependency order of a set of objects, which is useful in situations
    where certain objects must be processed before others.
    """

    _graph: nx.DiGraph = field(init=False, default_factory=nx.DiGraph)

    @staticmethod
    def _raise_edge_not_found_exc(u: int, v: int) -> NoReturn:
        raise ValueError("Edge not found (u: %r, v: %r)" % (hash(u), hash(v)))

    @staticmethod
    def _edge_is_unsatisfied(edge: tuple[int, int, _EdgeAttrs]) -> bool:
        return edge[2]["status"] == "unsatisfied"

    @classmethod
    def _edge_is_unsatisfied_with_exclude(
        cls,
        edge: tuple[int, int, _EdgeAttrs],
        exclude: Callable[[tuple[int, int]], bool],
    ) -> bool:
        if exclude(edge[:2]):
            return False
        return cls._edge_is_unsatisfied(edge)

    def _get_edge_data(self, u: int, v: int) -> _EdgeAttrs:
        return self._graph[u][v]  # type: ignore[no-any-return]

    def _get_node_payload(self, node_hash: int) -> T:
        return self._graph.nodes[node_hash]["payload"]  # type: ignore[no-any-return]

    def add_node(self, node: T) -> int:
        node_hash = hash(node)

        self._graph.add_node(node_hash, payload=node)
        logger.debug("added node %r with payload %r", node_hash, node)
        return node_hash

    def get_node_by_hash(self, value: int, default: P) -> Union[T, P]:
        if self._graph.nodes.get(value, default=None) is None:
            return default
        return self._get_node_payload(value)

    def remove_nodes(self, nodes: Iterable[T]) -> None:
        self._graph.remove_nodes_from(nodes)

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
        nx.set_node_attributes(
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
        status: EdgeStatusType = "unsatisfied",
    ) -> None:
        """
        Adds an edge from u to v, indicating that v depends on u.
        """
        u_hash, v_hash = self.add_node(u), self.add_node(v)
        self._graph.add_edge(u_hash, v_hash, status=status)
        logger.debug("added edge (u: %r, v: %r)", u_hash, v_hash)

    def has_node(self, node: T) -> bool:
        return self._graph.has_node(node)  # type: ignore[no-any-return]

    def has_edge(self, u: T, v: T) -> bool:
        return self._graph.has_edge(hash(u), hash(v))  # type: ignore[no-any-return]

    def update_edge_status(self, u: T, v: T, status: EdgeStatusType) -> None:
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

    def are_inbound_edges_satisfied(
        self,
        node: T,
        default: P,
        exclude: Callable[[tuple[int, int]], bool] = lambda _: False,
    ) -> Union[bool, P]:
        """
        Returns True if all inbound edges to the given node are satisfied, False
        otherwise.

        If the node has no inbound edges, returns the default value.

        Args:
            default: The value to return if the node has no inbound edges.
            exclude: A callable function that takes a tuple of two nodes and returns
                True if the edge between them should be excluded from the
                satisfaction check, False otherwise. Defaults to None,
                which means all edges are included.
        """
        unsatisfied_edge = next(
            filter(
                lambda edge: self._edge_is_unsatisfied_with_exclude(
                    edge, exclude  # pyright: ignore[reportGeneralTypeIssues]
                ),
                self._graph.in_edges(hash(node), data=True),
            ),
            default_obj,
        )

        if id(unsatisfied_edge) == id(default_obj):
            return default

        return not unsatisfied_edge

    def filter_nodes_for_satisfaction(self, node: T) -> Iterator[T]:
        """
        Yields nodes that have all their inbound edges satisfied, except for one inbound
        edge that comes from the specified node.
        """
        node_hash = hash(node)

        return (
            self._get_node_payload(nbr)
            for nbr in self._graph.neighbors(node_hash)
            if self.are_inbound_edges_satisfied(
                self._graph.nodes[nbr]["payload"],
                exclude=lambda edge: edge[0] == node_hash,
                default=True,
            )
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
                self._graph.in_edges(data=True, default={}),
            ),
        )
