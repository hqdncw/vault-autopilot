from dataclasses import dataclass

from . import namespace, token


@dataclass
class StandardComposer(namespace.NamespaceComposer, token.TokenComposer):
    """
    This class combines commonly used logic for interacting with the Vault API into a
    single, cohesive class.
    """
