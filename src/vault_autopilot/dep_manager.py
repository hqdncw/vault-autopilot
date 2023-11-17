import abc
import logging
from dataclasses import dataclass, field
from typing import Any, Generic, Iterator, Literal, NoReturn, TypeVar

import more_itertools
import networkx as nx

logger = logging.getLogger(__name__)


T = TypeVar("T")
EdgeStatusType = Literal["unsatisfied", "in_process", "satisfied"]


class AbstractNode:
    @abc.abstractmethod
    def __hash__(self) -> int:
        """
        The hash serves as a unique identifier for the node, enabling the manager to
        differentiate between multiple nodes and order their dependencies correctly.
        """


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
    _nodes: dict[int, T] = field(init=False, default_factory=dict)

    @staticmethod
    def _raise_edge_not_found_exc(u: T, v: T) -> NoReturn:
        raise ValueError("Edge not found (u: %r, v: %r)" % (u, v))

    @staticmethod
    def _edge_is_unsatisfied(edge: tuple[Any, Any, dict[Any, Any]]) -> bool:
        return bool(edge[2].get("status") == "unsatisfied")

    def _get_orphan_nodes(self) -> Iterator[int]:
        return (orphan[0] for orphan in self._graph.in_degree if orphan[1] == 0)

    def add_node(self, node: T) -> None:
        hash_ = hash(node)
        self._graph.add_node(hash_)
        self._nodes.update({hash_: node})
        logger.debug("add node %r (payload: %r)" % (hash_, node))

    def add_edge(
        self,
        predecessor: T,
        successor: T,
        status: EdgeStatusType = "unsatisfied",
    ) -> None:
        """
        Adds an edge from predecessor to successor, indicating that successor depends on
        predecessor.
        """
        pred_hash, sucr_hash = hash(predecessor), hash(successor)
        self._graph.add_edge(pred_hash, sucr_hash, status=status)
        logger.debug("add edge (%r, %r)" % (pred_hash, sucr_hash))

    def update_status(
        self, predecessor: T, successor: T, status: EdgeStatusType
    ) -> None:
        try:
            self._graph[hash(predecessor)][hash(successor)]["status"] = status
        except IndexError:
            self._raise_edge_not_found_exc(predecessor, successor)

    def get_edge_status(self, predecessor: T, successor: T) -> EdgeStatusType:
        try:
            return self._graph[hash(predecessor)][hash(successor)]["status"]  # type: ignore[no-any-return]
        except IndexError:
            self._raise_edge_not_found_exc(predecessor, successor)

    def is_node_exists(self, node: T) -> bool:
        return hash(node) in self._nodes

    def are_edges_satisfied(self, node: T) -> bool:
        """Checks whether the inbound edges of a node are satisfied."""
        return (
            more_itertools.first_true(
                self._graph.in_edges(hash(node), data=True, default={}),
                pred=self._edge_is_unsatisfied,  # pyright: ignore[reportGeneralTypeIssues]
                default=False,
            )
            is False
        )

    def find_unsatisfied_nodes(self, node: T) -> Iterator[T]:
        """Yields nodes with unsatisfied inbound edges coming from the given node."""
        for node_hash in self._graph.neighbors(hash(node)):
            if (nbr := self._nodes.get(node_hash)) and not self.are_edges_satisfied(
                nbr
            ):
                yield nbr

    def find_all_unsatisfied_nodes(self) -> Iterator[T]:
        """
        Yields all nodes in the graph that have at least one unsatisfied inbound edge.
        In other words, these are nodes that have incoming edges that have the
        "unsatisfied" status. This can be useful for identifying nodes that are not part
        of any connected component or cycle in the graph.
        """
        return map(
            lambda edge: self._nodes[edge[1]],
            filter(
                lambda edge: self._edge_is_unsatisfied(
                    edge  # pyright: ignore[reportGeneralTypeIssues]
                )
                and edge[1] in self._nodes,
                iter(self._graph.in_edges(data=True, default={})),
            ),
        )
