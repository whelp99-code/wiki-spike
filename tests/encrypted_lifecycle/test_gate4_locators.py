"""Gate 4 evidence-fragment locator validation and excerpt extraction tests."""
from __future__ import annotations

import json

import pytest

from wiki_spike.infrastructure.locators import (
    Locator,
    LocatorError,
    LocatorKind,
    extract_excerpt,
    validate_locator,
)

TEXT_BODY = "line one\nline two\nline three\n".encode("utf-8")

JSON_DOC = {
    "title": "hello",
    "nested": {"a/b": "slash-key", "a~b": "tilde-key"},
    "items": ["zero", "one", "two"],
}
JSON_BODY = json.dumps(JSON_DOC, separators=(",", ":"), sort_keys=True).encode("utf-8")


# ---------------------------------------------------------------------------
# BYTE_RANGE
# ---------------------------------------------------------------------------


def test_byte_range_positive_validate_and_extract():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "9", "locator_text": None}
    validate_locator(locator)
    assert extract_excerpt(locator, TEXT_BODY) == "line one\n"


def test_byte_range_end_exclusive_boundary():
    # end == len(body): slice runs exactly to the end, exclusive semantics.
    locator = {
        "locator_kind": "BYTE_RANGE",
        "locator_start": "9",
        "locator_end": str(len(TEXT_BODY)),
        "locator_text": None,
    }
    validate_locator(locator)
    assert extract_excerpt(locator, TEXT_BODY) == "line two\nline three\n"


def test_byte_range_rejects_non_null_text():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "1", "locator_text": "oops"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_must_be_null"


def test_byte_range_rejects_negative_start():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "-1", "locator_end": "3", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_not_decimal"


def test_byte_range_rejects_leading_zero():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "01", "locator_end": "3", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_not_decimal"


def test_byte_range_rejects_non_digit():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "3x", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_not_decimal"


def test_byte_range_rejects_int_type():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": 0, "locator_end": "3", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_not_string"


def test_byte_range_rejects_end_not_greater_than_start():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "5", "locator_end": "5", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.byte_range_not_increasing"


def test_byte_range_rejects_start_at_uint63_ceiling():
    huge = str(2 ** 63)
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": huge, "locator_end": str(2 ** 63 + 1), "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_out_of_range"


def test_byte_range_extract_out_of_bounds_rejected():
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": str(len(TEXT_BODY) + 5), "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        extract_excerpt(locator, TEXT_BODY)
    assert exc.value.code == "locator.byte_range_out_of_bounds"


def test_byte_range_extract_bad_utf8_boundary_rejected():
    body = "λ".encode("utf-8")  # 2-byte codepoint
    locator = {"locator_kind": "BYTE_RANGE", "locator_start": "0", "locator_end": "1", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        extract_excerpt(locator, body)
    assert exc.value.code == "locator.byte_range_not_utf8"


# ---------------------------------------------------------------------------
# LINE_RANGE
# ---------------------------------------------------------------------------


def test_line_range_positive_validate_and_extract():
    locator = {"locator_kind": "LINE_RANGE", "locator_start": "1", "locator_end": "2", "locator_text": None}
    validate_locator(locator)
    assert extract_excerpt(locator, TEXT_BODY) == "line one\nline two"


def test_line_range_inclusive_boundary_last_line():
    lines = TEXT_BODY.decode("utf-8").split("\n")
    last = str(len(lines))
    locator = {"locator_kind": "LINE_RANGE", "locator_start": last, "locator_end": last, "locator_text": None}
    validate_locator(locator)
    assert extract_excerpt(locator, TEXT_BODY) == ""  # trailing empty line after final \n


def test_line_range_rejects_zero_start():
    locator = {"locator_kind": "LINE_RANGE", "locator_start": "0", "locator_end": "1", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_out_of_range"


def test_line_range_rejects_start_greater_than_end():
    locator = {"locator_kind": "LINE_RANGE", "locator_start": "3", "locator_end": "2", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.line_range_not_ordered"


def test_line_range_rejects_non_null_text():
    locator = {"locator_kind": "LINE_RANGE", "locator_start": "1", "locator_end": "1", "locator_text": "x"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_must_be_null"


def test_line_range_extract_out_of_bounds_rejected():
    locator = {"locator_kind": "LINE_RANGE", "locator_start": "1", "locator_end": "999", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        extract_excerpt(locator, TEXT_BODY)
    assert exc.value.code == "locator.line_range_out_of_bounds"


# ---------------------------------------------------------------------------
# JSON_POINTER
# ---------------------------------------------------------------------------


def test_json_pointer_positive_validate_and_extract_nested_object():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/title"}
    validate_locator(locator)
    assert extract_excerpt(locator, JSON_BODY) == '"hello"'


def test_json_pointer_extract_array_index():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/items/1"}
    validate_locator(locator)
    assert extract_excerpt(locator, JSON_BODY) == '"one"'


def test_json_pointer_extract_tilde_escapes():
    # ~1 -> '/', ~0 -> '~'
    locator_slash = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/nested/a~1b"}
    validate_locator(locator_slash)
    assert extract_excerpt(locator_slash, JSON_BODY) == '"slash-key"'

    locator_tilde = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/nested/a~0b"}
    validate_locator(locator_tilde)
    assert extract_excerpt(locator_tilde, JSON_BODY) == '"tilde-key"'


def test_json_pointer_empty_pointer_returns_whole_doc():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": ""}
    validate_locator(locator)
    result = extract_excerpt(locator, JSON_BODY)
    assert json.loads(result) == JSON_DOC


def test_json_pointer_rejects_non_null_start():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": "0", "locator_end": None, "locator_text": "/title"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_must_be_null"


def test_json_pointer_rejects_null_text():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_required"


def test_json_pointer_rejects_too_long_text():
    long_text = "/" + ("a" * 1025)
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": long_text}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.pointer_too_long"


def test_json_pointer_rejects_bad_tilde_escape():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/a~b"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.pointer_bad_escape"


def test_json_pointer_rejects_trailing_bare_tilde():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/a~"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.pointer_bad_escape"


def test_json_pointer_rejects_missing_leading_slash():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "title"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.pointer_malformed"


def test_json_pointer_rejects_non_resolving_pointer():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/does/not/exist"}
    validate_locator(locator)  # syntactically valid
    with pytest.raises(LocatorError) as exc:
        extract_excerpt(locator, JSON_BODY)
    assert exc.value.code == "locator.pointer_not_found"


def test_json_pointer_rejects_array_index_leading_zero():
    locator = {"locator_kind": "JSON_POINTER", "locator_start": None, "locator_end": None, "locator_text": "/items/01"}
    validate_locator(locator)  # syntactically valid text; index validity checked during resolution
    with pytest.raises(LocatorError) as exc:
        extract_excerpt(locator, JSON_BODY)
    assert exc.value.code == "locator.pointer_bad_index"


# ---------------------------------------------------------------------------
# WHOLE_SOURCE
# ---------------------------------------------------------------------------


def test_whole_source_positive_validate_and_extract():
    locator = {"locator_kind": "WHOLE_SOURCE", "locator_start": None, "locator_end": None, "locator_text": None}
    validate_locator(locator)
    assert extract_excerpt(locator, TEXT_BODY) == TEXT_BODY.decode("utf-8")


def test_whole_source_rejects_non_null_start():
    locator = {"locator_kind": "WHOLE_SOURCE", "locator_start": "0", "locator_end": None, "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_must_be_null"


def test_whole_source_rejects_non_null_end():
    locator = {"locator_kind": "WHOLE_SOURCE", "locator_start": None, "locator_end": "1", "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_must_be_null"


def test_whole_source_rejects_non_null_text():
    locator = {"locator_kind": "WHOLE_SOURCE", "locator_start": None, "locator_end": None, "locator_text": "x"}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.field_must_be_null"


# ---------------------------------------------------------------------------
# Unknown kind
# ---------------------------------------------------------------------------


def test_unknown_kind_rejected():
    locator = {"locator_kind": "NOT_A_KIND", "locator_start": None, "locator_end": None, "locator_text": None}
    with pytest.raises(LocatorError) as exc:
        validate_locator(locator)
    assert exc.value.code == "locator.unknown_kind"


# ---------------------------------------------------------------------------
# Locator dataclass shape
# ---------------------------------------------------------------------------


def test_locator_dataclass_to_mapping_matches_identity_shape():
    locator = Locator(
        locator_kind=LocatorKind.WHOLE_SOURCE.value,
        locator_start=None,
        locator_end=None,
        locator_text=None,
    )
    mapping = locator.to_mapping()
    assert set(mapping) == {"locator_kind", "locator_start", "locator_end", "locator_text"}
    validate_locator(mapping)
