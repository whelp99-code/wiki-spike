"""Map closed catalog query results into identity scalars and typed rows."""
from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidContractValue
from .unified_db_postgres_capture_member_rows import (
    CatalogColumnRowV1,
    CatalogConstraintRowV1,
    CatalogIndexRowV1,
)
from .unified_db_postgres_capture_query import (
    CaptureQueryV1,
    require_closed_capture_queries,
)
from .unified_db_postgres_capture_rows import (
    CatalogRowV1,
    CatalogSchemaRowV1,
    CatalogTableRowV1,
)

type CatalogTable = tuple[tuple[str, ...], ...]


@dataclass(frozen=True, slots=True)
class ClosedCatalogCaptureV1:
    system_identifier: str
    database_oid: str
    server_version_num: str
    rows: tuple[CatalogRowV1, ...]


def interpret_closed_catalog_results(
    queries: tuple[CaptureQueryV1, ...],
    results: tuple[CatalogTable, ...],
) -> ClosedCatalogCaptureV1:
    """Parse exactly the closed eight query results in manifest order."""
    if len(queries) != len(results):
        raise InvalidContractValue("query result count does not match the closed manifest")
    require_closed_capture_queries(queries)
    system_identifier = ""
    database_oid = ""
    server_version_num = ""
    rows: list[CatalogRowV1] = []
    for query, table in zip(queries, results, strict=True):
        match query.query_kind:
            case "system_identifier":
                system_identifier = _one_cell(table, "system_identifier")
            case "database_oid":
                database_oid = _one_cell(table, "database_oid")
            case "server_version_num":
                server_version_num = _one_cell(table, "server_version_num")
            case "schemas":
                rows.extend(_schema_rows(table))
            case "tables":
                rows.extend(_table_rows(table))
            case "columns":
                rows.extend(_column_rows(table))
            case "constraints":
                rows.extend(_constraint_rows(table))
            case "indexes":
                rows.extend(_index_rows(table))
            case _:
                raise InvalidContractValue("query is not in the closed manifest")
    return ClosedCatalogCaptureV1(
        system_identifier, database_oid, server_version_num, tuple(rows)
    )


def _one_cell(table: CatalogTable, field: str) -> str:
    if len(table) != 1 or len(table[0]) != 1:
        raise InvalidContractValue(f"{field} must be a single catalog value")
    return table[0][0]


def _width(item: tuple[str, ...], width: int, label: str) -> None:
    if len(item) != width:
        raise InvalidContractValue(f"{label} row has the wrong width")


def _schema_rows(table: CatalogTable) -> tuple[CatalogSchemaRowV1, ...]:
    rows: list[CatalogSchemaRowV1] = []
    for item in table:
        _width(item, 2, "schema")
        rows.append(
            CatalogSchemaRowV1.from_mapping(
                {"kind": "schema", "schema_name": item[0], "schema_oid": item[1]}
            )
        )
    return tuple(rows)


def _table_rows(table: CatalogTable) -> tuple[CatalogTableRowV1, ...]:
    rows: list[CatalogTableRowV1] = []
    for item in table:
        _width(item, 4, "table")
        rows.append(
            CatalogTableRowV1.from_mapping(
                {
                    "kind": "table",
                    "schema_name": item[0],
                    "table_name": item[1],
                    "table_oid": item[2],
                    "relkind": item[3],
                }
            )
        )
    return tuple(rows)


def _column_rows(table: CatalogTable) -> tuple[CatalogColumnRowV1, ...]:
    rows: list[CatalogColumnRowV1] = []
    for item in table:
        _width(item, 6, "column")
        rows.append(
            CatalogColumnRowV1.from_mapping(
                {
                    "kind": "column",
                    "schema_name": item[0],
                    "table_name": item[1],
                    "column_name": item[2],
                    "ordinal": item[3],
                    "type_name": item[4],
                    "not_null": item[5],
                }
            )
        )
    return tuple(rows)


def _constraint_rows(table: CatalogTable) -> tuple[CatalogConstraintRowV1, ...]:
    rows: list[CatalogConstraintRowV1] = []
    for item in table:
        _width(item, 4, "constraint")
        rows.append(
            CatalogConstraintRowV1.from_mapping(
                {
                    "kind": "constraint",
                    "schema_name": item[0],
                    "table_name": item[1],
                    "constraint_name": item[2],
                    "constraint_type": item[3],
                }
            )
        )
    return tuple(rows)


def _index_rows(table: CatalogTable) -> tuple[CatalogIndexRowV1, ...]:
    rows: list[CatalogIndexRowV1] = []
    for item in table:
        _width(item, 4, "index")
        rows.append(
            CatalogIndexRowV1.from_mapping(
                {
                    "kind": "index",
                    "schema_name": item[0],
                    "table_name": item[1],
                    "index_name": item[2],
                    "unique": item[3],
                }
            )
        )
    return tuple(rows)
