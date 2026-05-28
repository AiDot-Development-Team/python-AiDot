"""Base model for AiDot models."""

from dataclasses import dataclass, asdict
from typing import Any, TypeVar, Type

from dacite import Config, from_dict

T = TypeVar("T", bound="BaseModel")


@dataclass
class BaseModel:
    """Base model with common serialization methods."""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_json(cls: Type[T], data: dict[str, Any]) -> T:
        """Create instance from JSON dict."""
        return from_dict(data_class=cls, data=data, config=Config(check_types=False))
