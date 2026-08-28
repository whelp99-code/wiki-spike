"""Compatibility names for the GUI-facing local Second Brain façade.

No durable memory state lives in this package. The implementation is the existing
encrypted lifecycle authority wired by :mod:`wiki_spike.composition.local_second_brain`.
"""
from wiki_spike.composition.local_second_brain import (
    BACKUP_SCHEMA,
    NOTE_SCHEMA,
    LocalMemoryError,
    LocalMemoryStore,
    MemoryHit,
    SourceDocument,
    diagnose,
    read_passphrase,
)

BACKUP_VERSION = BACKUP_SCHEMA
SCHEMA_VERSION = NOTE_SCHEMA

__all__ = [
    "LocalMemoryError",
    "LocalMemoryStore",
    "MemoryHit",
    "SourceDocument",
    "diagnose",
    "read_passphrase",
    "BACKUP_VERSION",
    "SCHEMA_VERSION",
]
