from typing_extensions import TypedDict


class MountPathMixin(TypedDict):
    mount_path: str


class PathMixin(TypedDict):
    path: str
