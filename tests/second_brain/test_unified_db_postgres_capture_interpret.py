"""Closed-catalog interpret refuses SQL that is not the closed query set."""
from __future__ import annotations

import pytest

from tests.second_brain.unified_db_postgres_capture_support import (
    APPLICATION_TABLE_SQL,
    closed_catalog_query_results,
)
from wiki_spike.memory_core.errors import InvalidContractValue
from wiki_spike.memory_core.unified_db_postgres_capture_interpret import (
    interpret_closed_catalog_results,
)
from wiki_spike.memory_core.unified_db_postgres_capture_query import (
    CLOSED_QUERY_SQL,
    CaptureQueryV1,
)


def _closed_queries() -> tuple[CaptureQueryV1, ...]:
    return tuple(CaptureQueryV1(kind, sql) for kind, sql in CLOSED_QUERY_SQL)


def _closed_results() -> tuple[tuple[tuple[str, ...], ...], ...]:
    by_sql = closed_catalog_query_results()
    return tuple(by_sql[sql] for _kind, sql in CLOSED_QUERY_SQL)


def test_interpret_rejects_when_sql_is_not_closed_for_kind() -> None:
    closed = _closed_queries()
    swapped = dict(CLOSED_QUERY_SQL)
    queries = (CaptureQueryV1(closed[0].query_kind, swapped["database_oid"]),) + closed[1:]
    with pytest.raises(InvalidContractValue, match="closed"):
        _ = interpret_closed_catalog_results(queries, _closed_results())


def test_interpret_rejects_when_sql_is_application_table() -> None:
    closed = _closed_queries()
    queries = (CaptureQueryV1(closed[0].query_kind, APPLICATION_TABLE_SQL[0]),) + closed[1:]
    with pytest.raises(InvalidContractValue, match="closed|forbidden|pg_catalog"):
        _ = interpret_closed_catalog_results(queries, _closed_results())


def test_interpret_rejects_when_queries_are_extra() -> None:
    extra = CaptureQueryV1("tables", dict(CLOSED_QUERY_SQL)["tables"])
    queries = _closed_queries() + (extra,)
    results = _closed_results() + ((),)
    with pytest.raises(InvalidContractValue, match="closed|count"):
        _ = interpret_closed_catalog_results(queries, results)


def test_interpret_rejects_when_queries_are_reordered() -> None:
    queries = list(_closed_queries())
    results = list(_closed_results())
    queries[0], queries[1] = queries[1], queries[0]
    results[0], results[1] = results[1], results[0]
    with pytest.raises(InvalidContractValue, match="closed"):
        _ = interpret_closed_catalog_results(tuple(queries), tuple(results))
