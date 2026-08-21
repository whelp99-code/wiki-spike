"""Conservative tokenizer and denylist for body-free catalog SQL."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from .errors import InvalidContractValue

FORBIDDEN_FRAGMENTS: Final = (
    ";",
    "--",
    "/*",
    "*/",
    "$",
    "%",
    "{",
    "}",
    "?",
    "`",
    '"',
    "\\",
    "#",
    "\x00",
)
CLOSED_RELATIONS: Final = frozenset(
    {
        "pg_catalog.pg_control_system",
        "pg_catalog.pg_database",
        "pg_catalog.pg_namespace",
        "pg_catalog.pg_class",
        "pg_catalog.pg_attribute",
        "pg_catalog.pg_type",
        "pg_catalog.pg_constraint",
        "pg_catalog.pg_index",
    }
)
ALLOWED_FUNCTIONS: Final = frozenset({"current_database"})
ALLOWED_SHOW: Final = frozenset({"server_version_num"})
_IDENT: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_NUMBER: Final = re.compile(r"[0-9]+")
_LITERAL: Final = re.compile(r"^[A-Za-z0-9_]{1,16}$")
_KEYWORDS: Final = frozenset(
    {
        "SELECT",
        "SHOW",
        "FROM",
        "INNER",
        "JOIN",
        "ON",
        "WHERE",
        "AND",
        "OR",
        "NOT",
        "ORDER",
        "BY",
        "AS",
        "TRUE",
        "FALSE",
    }
)
_DENIED: Final = frozenset(
    {
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "CREATE",
        "ALTER",
        "COPY",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "EXECUTE",
        "CALL",
        "DO",
        "WITH",
        "INTO",
        "RETURNING",
        "UNION",
        "EXCEPT",
        "INTERSECT",
        "LIMIT",
        "OFFSET",
        "FETCH",
        "FOR",
        "LOCK",
        "LISTEN",
        "NOTIFY",
        "LOAD",
        "SET",
        "RESET",
        "PREPARE",
        "DEALLOCATE",
        "EXPLAIN",
        "VACUUM",
        "ANALYZE",
    }
)


@dataclass(frozen=True, slots=True)
class CaptureSqlInspection:
    statement_kind: str
    tokens: tuple[str, ...]
    relation_refs: tuple[str, ...]
    show_setting: str | None


def inspect_capture_sql(sql: str) -> CaptureSqlInspection:
    """Parse closed catalog SQL and reject any application-row capability."""
    if not sql.strip():
        raise InvalidContractValue("SQL must be a non-empty string")
    for fragment in FORBIDDEN_FRAGMENTS:
        if fragment in sql:
            raise InvalidContractValue("SQL contains a forbidden token")
    tokens = _tokenize(sql)
    for token in tokens:
        folded = token.upper()
        if folded in _DENIED:
            raise InvalidContractValue("SQL contains a forbidden keyword")
        if token == ".":
            continue
    head = tokens[0].upper()
    if head == "SHOW":
        return _inspect_show(tokens)
    if head == "SELECT":
        if any(token.upper() == "SELECT" for token in tokens[1:]):
            raise InvalidContractValue("SQL subquery is forbidden")
        return _inspect_select(tokens)
    raise InvalidContractValue("SQL must be SELECT or SHOW")


def _inspect_show(tokens: tuple[str, ...]) -> CaptureSqlInspection:
    if len(tokens) != 2 or tokens[1] not in ALLOWED_SHOW:
        raise InvalidContractValue("SHOW must name an allowlisted setting")
    return CaptureSqlInspection("SHOW", tokens, (), tokens[1])


def _inspect_select(tokens: tuple[str, ...]) -> CaptureSqlInspection:
    relations: list[str] = []
    index = 1
    while index < len(tokens):
        folded = tokens[index].upper()
        if folded in {"FROM", "JOIN"}:
            rest = tokens[index + 1 :]
            if rest and rest[0] == "(":
                raise InvalidContractValue("SQL derived relation is forbidden")
            ref, consumed = _parse_relation(rest)
            after = index + 1 + consumed
            if after < len(tokens) and tokens[after] == ",":
                raise InvalidContractValue("SQL comma join is forbidden")
            relations.append(ref)
            index = after
            continue
        if folded == "(":
            _reject_unknown_function(tokens, index)
        index += 1
    if not relations:
        raise InvalidContractValue("SELECT must read a pg_catalog relation")
    return CaptureSqlInspection("SELECT", tokens, tuple(relations), None)


def _reject_unknown_function(tokens: tuple[str, ...], index: int) -> None:
    if index == 0:
        raise InvalidContractValue("SQL function is not closed")
    callee = tokens[index - 1]
    catalog_func = (
        index >= 3
        and tokens[index - 3] == "pg_catalog"
        and tokens[index - 2] == "."
        and f"pg_catalog.{callee}" in CLOSED_RELATIONS
    )
    if catalog_func or callee in ALLOWED_FUNCTIONS:
        return
    if _IDENT.fullmatch(callee) is not None and callee.upper() not in _KEYWORDS:
        raise InvalidContractValue("SQL function is not closed")


def _parse_relation(tokens: tuple[str, ...]) -> tuple[str, int]:
    if len(tokens) < 3 or tokens[0] != "pg_catalog" or tokens[1] != ".":
        raise InvalidContractValue("SQL relation is not pg_catalog")
    name = tokens[2]
    if _IDENT.fullmatch(name) is None:
        raise InvalidContractValue("SQL relation is not pg_catalog")
    qualified = f"pg_catalog.{name}"
    if qualified not in CLOSED_RELATIONS:
        raise InvalidContractValue("SQL relation is not pg_catalog")
    consumed = 3
    if len(tokens) >= 5 and tokens[3] == "(" and tokens[4] == ")":
        consumed = 5
    rest = tokens[consumed:]
    if rest and rest[0].upper() == "AS":
        if len(rest) < 2 or _IDENT.fullmatch(rest[1]) is None:
            raise InvalidContractValue("SQL alias is invalid")
        consumed += 2
    elif rest and _IDENT.fullmatch(rest[0]) is not None and rest[0].upper() not in _KEYWORDS:
        consumed += 1
    return qualified, consumed


def _tokenize(sql: str) -> tuple[str, ...]:
    tokens: list[str] = []
    index = 0
    length = len(sql)
    while index < length:
        char = sql[index]
        if char in " \t\r\n":
            index += 1
            continue
        if char in ".,()=<>*":
            tokens.append(char)
            index += 1
            continue
        if char == "'":
            end = sql.find("'", index + 1)
            if end < 0:
                raise InvalidContractValue("SQL string is unterminated")
            literal = sql[index + 1 : end]
            if _LITERAL.fullmatch(literal) is None:
                raise InvalidContractValue("SQL string literal is not closed")
            tokens.append(f"'{literal}'")
            index = end + 1
            continue
        ident = _IDENT.match(sql, index)
        if ident is not None:
            tokens.append(ident.group(0))
            index = ident.end()
            continue
        number = _NUMBER.match(sql, index)
        if number is not None:
            tokens.append(number.group(0))
            index = number.end()
            continue
        raise InvalidContractValue("SQL contains a forbidden token")
    if not tokens:
        raise InvalidContractValue("SQL must be a non-empty string")
    return tuple(tokens)
