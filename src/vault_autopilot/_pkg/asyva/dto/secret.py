from typing import Any

from typing_extensions import NotRequired

from . import base


class SecretCreateDTO(base.PathMixin, base.MountPathMixin):
    data: dict[str, Any]
    cas: NotRequired[int]


class SecretGetVersionDTO(base.PathMixin, base.MountPathMixin):
    pass
