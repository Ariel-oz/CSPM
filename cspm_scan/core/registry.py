"""Check self-registration. Importing a check module registers its checks as a side effect."""

from .models import CheckMeta

CHECK_REGISTRY: dict[str, "BaseCheck"] = {}


class BaseCheck:
    meta: CheckMeta

    def execute(self, ctx, region: str | None = None) -> list:
        raise NotImplementedError


def register_check(meta: CheckMeta):
    def decorator(cls):
        if meta.check_id in CHECK_REGISTRY:
            raise ValueError(f"Duplicate check_id: {meta.check_id}")
        cls.meta = meta
        CHECK_REGISTRY[meta.check_id] = cls()
        return cls

    return decorator
