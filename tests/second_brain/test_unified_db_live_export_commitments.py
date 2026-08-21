"""Parse tests for adapter, destination, and writer-quiescence commitments."""
from __future__ import annotations

from collections.abc import Mapping
from typing import cast

import pytest

from tests.second_brain.unified_db_live_export_support import (
    adapter_body,
    destination_body,
    identity_body,
    quiescence_body,
)
from wiki_spike.memory_core.contracts import JsonValue
from wiki_spike.memory_core.errors import (
    InvalidContractValue,
    UnknownContractField,
    UnsupportedContractVersion,
)
from wiki_spike.memory_core.unified_db_live_export_commitments import (
    UnifiedDbLiveExportAdapterV1,
    UnifiedDbLiveExportDestinationV1,
    UnifiedDbWriterQuiescenceV1,
)
from wiki_spike.memory_core.unified_db_postgres_identity import (
    PostgresIdentityReceiptV1,
)


def _source() -> str:
    return PostgresIdentityReceiptV1.from_mapping(identity_body()).identity_digest


def test_adapter_rejects_missing_extra_version_and_raw_number() -> None:
    missing = adapter_body()
    del missing["isolation"]
    with pytest.raises(InvalidContractValue, match="missing"):
        _ = UnifiedDbLiveExportAdapterV1.from_mapping(missing)
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbLiveExportAdapterV1.from_mapping(adapter_body() | {"extra": "no"})
    with pytest.raises(UnsupportedContractVersion):
        _ = UnifiedDbLiveExportAdapterV1.from_mapping(
            adapter_body(adapter_version="adapter-v0")
        )
    broken: dict[str, object] = dict(adapter_body())
    broken["read_only"] = 1
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbLiveExportAdapterV1.from_mapping(
            cast(Mapping[str, JsonValue], broken)
        )


def test_destination_rejects_import_or_serve_flags() -> None:
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbLiveExportDestinationV1.from_mapping(
            destination_body(import_requested=True)
        )
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbLiveExportDestinationV1.from_mapping(
            destination_body(serve_requested=True)
        )


def test_quiescence_requires_zero_writers_and_approval() -> None:
    source = _source()
    parsed = UnifiedDbWriterQuiescenceV1.from_mapping(quiescence_body(source))
    assert parsed.writer_count == "0"
    assert parsed.quiesce_approved is True
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbWriterQuiescenceV1.from_mapping(
            quiescence_body(source, writer_count="1")
        )
    with pytest.raises(InvalidContractValue):
        _ = UnifiedDbWriterQuiescenceV1.from_mapping(
            quiescence_body(source, quiesce_approved=False)
        )
    with pytest.raises(UnknownContractField):
        _ = UnifiedDbWriterQuiescenceV1.from_mapping(
            quiescence_body(source) | {"body": "secret"}
        )
