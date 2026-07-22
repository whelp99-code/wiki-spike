"""Stable error taxonomy for Phase 3 core contracts."""
from __future__ import annotations


class CoreContractError(ValueError):
    """Base class for fail-closed contract validation errors."""


class UnsupportedContractVersion(CoreContractError):
    """Raised when a producer uses an unknown contract version."""


class UnknownContractField(CoreContractError):
    """Raised when an envelope contains fields outside its schema."""


class InvalidContractValue(CoreContractError):
    """Raised when a value cannot be represented canonically."""
