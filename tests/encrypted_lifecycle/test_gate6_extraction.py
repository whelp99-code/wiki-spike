"""Gate 6 extraction corpus, profiles, egress policy, and attempt-tracking tests."""
from __future__ import annotations

import pytest

from wiki_spike.infrastructure.extraction import (
    ApprovedEgressLedger,
    AttemptTracker,
    CorpusItem,
    EgressPolicy,
    ExtractionError,
    ExtractionResult,
    ExtractorProfile,
    EXTRACTION_CORPUS_60,
    extract_claims,
    run_corpus_evaluation,
)


# ---------------------------------------------------------------------------
# Frozen 60-item corpus
# ---------------------------------------------------------------------------


class TestCorpusComposition:
    def test_corpus_has_60_items(self):
        assert len(EXTRACTION_CORPUS_60) == 60

    def test_corpus_composition(self):
        positives = [i for i in EXTRACTION_CORPUS_60 if i.category == "positive"]
        negatives = [i for i in EXTRACTION_CORPUS_60 if i.category == "negative"]
        edge_cases = [i for i in EXTRACTION_CORPUS_60 if i.category == "edge_case"]
        assert len(positives) == 40
        assert len(negatives) == 10
        assert len(edge_cases) == 10

    def test_corpus_item_ids_unique(self):
        ids = [i.item_id for i in EXTRACTION_CORPUS_60]
        assert len(ids) == len(set(ids))

    def test_corpus_positive_items_expected_min_at_least_1(self):
        positives = [i for i in EXTRACTION_CORPUS_60 if i.category == "positive"]
        for item in positives:
            assert item.expected_claim_count_min >= 1

    def test_corpus_negative_items_expected_zero(self):
        negatives = [i for i in EXTRACTION_CORPUS_60 if i.category == "negative"]
        for item in negatives:
            assert item.expected_claim_count_min == 0
            assert item.expected_claim_count_max == 0


# ---------------------------------------------------------------------------
# Local-default egress policy
# ---------------------------------------------------------------------------


class TestLocalDefaultEgress:
    def test_local_rules_v1_allowed_under_local_only(self):
        item = EXTRACTION_CORPUS_60[0]
        result = extract_claims(item, profile=ExtractorProfile.LOCAL_RULES_V1, policy=EgressPolicy.LOCAL_ONLY)
        assert isinstance(result, ExtractionResult)
        assert result.extractor_profile == "LOCAL_RULES_V1"
        assert result.egress_policy == "LOCAL_ONLY"

    def test_local_model_v1_allowed_under_local_only(self):
        item = EXTRACTION_CORPUS_60[0]
        result = extract_claims(item, profile=ExtractorProfile.LOCAL_MODEL_V1, policy=EgressPolicy.LOCAL_ONLY)
        assert isinstance(result, ExtractionResult)
        assert result.extractor_profile == "LOCAL_MODEL_V1"

    def test_approved_external_v1_denied_under_local_only(self):
        item = EXTRACTION_CORPUS_60[0]
        with pytest.raises(ExtractionError) as excinfo:
            extract_claims(item, profile=ExtractorProfile.APPROVED_EXTERNAL_V1, policy=EgressPolicy.LOCAL_ONLY)
        assert excinfo.value.code == "egress_denied"


# ---------------------------------------------------------------------------
# Approved egress ledger
# ---------------------------------------------------------------------------


class TestApprovedEgressLedger:
    def test_authorized_egress_succeeds(self):
        ledger = ApprovedEgressLedger()
        ledger.approve_egress(destination="provider.a", approved_by="admin", purpose="recall", evidence_digest="aa" * 32)
        item = EXTRACTION_CORPUS_60[0]
        result = extract_claims(
            item,
            profile=ExtractorProfile.APPROVED_EXTERNAL_V1,
            policy=EgressPolicy.APPROVED_EXTERNAL,
            egress_ledger=ledger,
            destination="provider.a",
            purpose="recall",
        )
        assert isinstance(result, ExtractionResult)
        assert result.extractor_profile == "APPROVED_EXTERNAL_V1"

    def test_unauthorized_egress_denied(self):
        ledger = ApprovedEgressLedger()
        item = EXTRACTION_CORPUS_60[0]
        with pytest.raises(ExtractionError) as excinfo:
            extract_claims(
                item,
                profile=ExtractorProfile.APPROVED_EXTERNAL_V1,
                policy=EgressPolicy.APPROVED_EXTERNAL,
                egress_ledger=ledger,
                destination="provider.b",
                purpose="analysis",
            )
        assert excinfo.value.code == "unauthorized_egress"

    def test_is_approved(self):
        ledger = ApprovedEgressLedger()
        ledger.approve_egress(destination="provider.a", approved_by="admin", purpose="recall", evidence_digest="aa" * 32)
        assert ledger.is_approved("provider.a", "recall") is True
        assert ledger.is_approved("provider.a", "analysis") is False
        assert ledger.is_approved("provider.b", "recall") is False

    def test_egress_id_unique_per_destination_purpose(self):
        ledger = ApprovedEgressLedger()
        r1 = ledger.approve_egress(destination="d1", approved_by="admin", purpose="p1", evidence_digest="aa" * 32)
        r2 = ledger.approve_egress(destination="d1", approved_by="admin", purpose="p2", evidence_digest="bb" * 32)
        r3 = ledger.approve_egress(destination="d2", approved_by="admin", purpose="p1", evidence_digest="cc" * 32)
        assert r1.egress_id != r2.egress_id
        assert r1.egress_id != r3.egress_id
        assert r2.egress_id != r3.egress_id


# ---------------------------------------------------------------------------
# Bounded attempts
# ---------------------------------------------------------------------------


class TestAttemptTracker:
    def test_first_attempt_succeeds(self):
        tracker = AttemptTracker()
        n = tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_000)
        assert n == 1

    def test_second_attempt_succeeds(self):
        tracker = AttemptTracker()
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_000)
        n = tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_100)
        assert n == 2

    def test_third_attempt_blocked_within_window(self):
        tracker = AttemptTracker()
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_000)
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_100)
        with pytest.raises(ExtractionError) as excinfo:
            tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_200)
        assert excinfo.value.code == "attempt_limit_exceeded"

    def test_after_window_passes_retry_allowed(self):
        tracker = AttemptTracker()
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_000)
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_100)
        # After 432000 seconds the window clears
        n = tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_000 + 500_000)
        assert n == 1  # old records purged, counts as 1st

    def test_independent_sources_not_blocked(self):
        tracker = AttemptTracker()
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_000)
        tracker.record_attempt("source-1", timestamp_epoch_sec=1_000_100)
        n = tracker.record_attempt("source-2", timestamp_epoch_sec=1_000_200)
        assert n == 1

    def test_attempt_tracking_in_extract_claims(self):
        tracker = AttemptTracker()
        item = EXTRACTION_CORPUS_60[0]
        extract_claims(item, attempt_tracker=tracker, timestamp_epoch_sec=1_000_000)
        extract_claims(item, attempt_tracker=tracker, timestamp_epoch_sec=1_000_100)
        with pytest.raises(ExtractionError) as excinfo:
            extract_claims(item, attempt_tracker=tracker, timestamp_epoch_sec=1_000_200)
        assert excinfo.value.code == "attempt_limit_exceeded"


# ---------------------------------------------------------------------------
# Extraction logic: negative / injection items produce zero claims
# ---------------------------------------------------------------------------


class TestNegativeItems:
    def test_all_negative_items_produce_zero_claims(self):
        negatives = [i for i in EXTRACTION_CORPUS_60 if i.category == "negative"]
        for item in negatives:
            result = extract_claims(item, profile=ExtractorProfile.LOCAL_RULES_V1)
            assert len(result.extracted_claims) == 0, f"{item.item_id} should have 0 claims"
            assert result.forbidden_return is False

    def test_all_negative_items_produce_zero_forbidden_returns_local_model(self):
        negatives = [i for i in EXTRACTION_CORPUS_60 if i.category == "negative"]
        for item in negatives:
            result = extract_claims(item, profile=ExtractorProfile.LOCAL_MODEL_V1)
            assert len(result.extracted_claims) == 0
            assert result.forbidden_return is False


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_unicode_nfc_nfd_normalization(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_51"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        assert len(result.extracted_claims) >= 1

    def test_bom_prefixed_text(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_52"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        assert len(result.extracted_claims) >= 1

    def test_mixed_newlines(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_53"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        assert len(result.extracted_claims) >= 2

    def test_hedged_statements(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_54"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        assert len(result.extracted_claims) >= 1

    def test_empty_text_produces_zero_claims(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_55"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        assert len(result.extracted_claims) == 0

    def test_whitespace_only_produces_zero_claims(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_58"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        assert len(result.extracted_claims) == 0

    def test_special_characters_with_claim(self):
        items = [i for i in EXTRACTION_CORPUS_60 if i.item_id == "item_59"]
        assert len(items) == 1
        result = extract_claims(items[0], profile=ExtractorProfile.LOCAL_RULES_V1)
        # Should extract the snowman symbol claim
        assert len(result.extracted_claims) >= 1


# ---------------------------------------------------------------------------
# Full corpus evaluation
# ---------------------------------------------------------------------------


class TestCorpusEvaluation:
    def test_full_corpus_evaluation_with_local_rules(self):
        result = run_corpus_evaluation(
            profile=ExtractorProfile.LOCAL_RULES_V1,
            policy=EgressPolicy.LOCAL_ONLY,
        )
        assert result.total_items == 60
        assert result.positive_count == 40
        assert result.negative_count == 10
        assert result.edge_case_count == 10
        assert result.zero_forbidden_returns is True
        assert result.attempts_bounded is True
        assert result.precision_avg >= 0.8
        assert result.recall_avg >= 0.8

    def test_full_corpus_evaluation_with_local_model(self):
        result = run_corpus_evaluation(
            profile=ExtractorProfile.LOCAL_MODEL_V1,
            policy=EgressPolicy.LOCAL_ONLY,
        )
        assert result.total_items == 60
        assert result.zero_forbidden_returns is True
        assert result.precision_avg >= 0.8
        assert result.recall_avg >= 0.8

    def test_corpus_evaluation_attempts_bounded(self):
        tracker = AttemptTracker()
        result = run_corpus_evaluation(
            profile=ExtractorProfile.LOCAL_RULES_V1,
            policy=EgressPolicy.LOCAL_ONLY,
            attempt_tracker=tracker,
        )
        assert result.attempts_bounded is True
        assert result.total_items == 60


# ---------------------------------------------------------------------------
# ExtractionError combinations
# ---------------------------------------------------------------------------


class TestExtractionErrors:
    def test_unknown_extractor_profile_raises(self):
        item = EXTRACTION_CORPUS_60[0]
        with pytest.raises(ExtractionError) as excinfo:
            extract_claims(item, profile="BOGUS_PROFILE")
        assert excinfo.value.code == "unknown_extractor_profile"

    def test_unknown_egress_policy_raises(self):
        item = EXTRACTION_CORPUS_60[0]
        with pytest.raises(ExtractionError) as excinfo:
            extract_claims(item, policy="BOGUS_POLICY")
        assert excinfo.value.code == "unknown_egress_policy"

    def test_approved_external_without_ledger_raises(self):
        item = EXTRACTION_CORPUS_60[0]
        with pytest.raises(ExtractionError) as excinfo:
            extract_claims(
                item,
                profile=ExtractorProfile.APPROVED_EXTERNAL_V1,
                policy=EgressPolicy.APPROVED_EXTERNAL,
                destination="provider.a",
                purpose="recall",
            )
        assert excinfo.value.code == "unauthorized_egress"
