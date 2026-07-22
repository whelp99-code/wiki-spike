"""Stable error taxonomy owned by the Phase 4 Runtime boundary.

Runtime deliberately does not import ``memory_core.errors``.  The frozen Phase 3
contract surface exposed to Runtime is limited to ``memory_core.contracts`` and
``memory_core.ports``; Runtime contract validation therefore owns an equivalent,
independent exception hierarchy.
"""
from __future__ import annotations


class RuntimeContractError(ValueError):
    """Base class for fail-closed Runtime contract validation errors."""


class UnsupportedContractVersion(RuntimeContractError):
    """Raised when a producer uses an unknown Runtime contract version."""


class UnknownContractField(RuntimeContractError):
    """Raised when a Runtime envelope contains fields outside its schema."""


class InvalidContractValue(RuntimeContractError):
    """Raised when a Runtime value cannot be represented canonically."""
