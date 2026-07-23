"""Phase 4 Runtime v1 public contract surface.

This module is the frozen public surface for the G4 checkpoint.  It intentionally
exports contracts and provider-neutral engines only; no credentials, connector,
UI, Storage implementation, or external action executor is reachable here.
"""
from .action_intent import ACTION_INTENT_VERSION, ActionIntent
from .attention import ATTENTION_RECORD_VERSION, AttentionRecord, InMemoryAttentionLedger
from .cache import CACHE_ENTRY_VERSION, CacheEntry, ModelCache
from .clarification import (
    CLARIFICATION_CANDIDATE_VERSION,
    CLARIFICATION_QUESTION_VERSION,
    ClarificationCandidate,
    ClarificationEngine,
    ClarificationQuestion,
    InMemoryClarificationLedger,
)
from .context import (
    CONTEXT_ITEM_VERSION,
    CONTEXT_PLAN_VERSION,
    EGRESS_DECISION_VERSION,
    ContextItem,
    ContextPlan,
    ContextPlanner,
    EgressDecision,
    EgressRoute,
    StaticEgressPolicy,
)
from .cost import COST_CONTEXT_VERSION, BudgetExceeded, CostContext, CostTracker
from .decision import (
    DECISION_CANDIDATE_VERSION,
    DECISION_INPUT_VERSION,
    DecisionCandidate,
    DecisionEngine,
    DecisionInput,
    DecisionKind,
    ProposedDecisionStatus,
)
from .degrade import DEGRADE_DECISION_VERSION, DegradeAction, DegradeDecision, DegradePolicy
from .evidence_pack import EVIDENCE_ATOM_VERSION, EVIDENCE_PACK_VERSION, EvidenceAtom, EvidencePack, EvidencePackBuilder
from .eval import OFFLINE_EVAL_REPORT_VERSION, LabeledOutcome, OfflineEvalReport
from .model_gateway import (
    MODEL_CALL_RESULT_VERSION,
    MODEL_ROUTE_VERSION,
    GatewayResponse,
    ModelCallResult,
    ModelErrorClass,
    ModelGateway,
    ModelGatewayError,
    ModelRoute,
)
from .proactive import PROACTIVE_INPUT_VERSION, PROACTIVE_SUGGESTION_VERSION, ProactiveEngine, ProactiveInput, ProactiveSuggestion
from .recall import RECALL_ANSWER_VERSION, RECALL_STATEMENT_VERSION, RecallAnswer, RecallDraftStatement, RecallEngine, RecallStatement
from .retrieval import (
    RETRIEVAL_CANDIDATE_VERSION,
    RETRIEVAL_QUERY_VERSION,
    RETRIEVAL_RESULT_VERSION,
    AuthoritativeObjectState,
    RetrievalBroker,
    RetrievalCandidate,
    RetrievalChannel,
    RetrievalQuery,
    RetrievalResult,
)
from .telemetry import ONLINE_METRIC_VERSION, OnlineMetric, TelemetrySink
from .verification import (
    VERIFICATION_CLAIM_VERSION,
    VERIFICATION_OUTCOME_VERSION,
    DefaultVerificationPolicy,
    DeterministicVerdict,
    PolicyVerdict,
    ProbabilisticVerdict,
    VerificationClaim,
    VerificationOutcome,
    VerificationPipeline,
)
from .write_proposal import WRITE_PROPOSAL_VERSION, InMemoryProposalReceiptStore, WriteProposal, WriteProposalGateway

PHASE4_RUNTIME_RELEASE = "phase4-runtime-v1.0.0"
G4_CHECKPOINT_SCHEMA = "phase4-g4-checkpoint-v1"

__all__ = [name for name in globals() if not name.startswith("_")]
