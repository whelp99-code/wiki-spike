# P4-10 Proactive Suggestion and Attention Ledger 적대적 검증 20라운드

**대상**: quiet hours, workspace caps, dedupe, expiry, no delivery  
**기준선**: P4-02 merged main `b60967d627a31ba7c340f398369c6df0019a5114`

## Round 01 — unknown version or field

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 unknown version or field을 유도한다.
- **방어**: strict version and field allowlists를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 02 — post-construction mutation

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 post-construction mutation을 유도한다.
- **방어**: content-bound IDs and canonical copies를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 03 — cross-workspace data leak

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 cross-workspace data leak을 유도한다.
- **방어**: workspace-scoped keys and filtering를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 04 — stale generation use

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 stale generation use을 유도한다.
- **방어**: explicit generation pin and authoritative recheck를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 05 — sensitivity downgrade

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 sensitivity downgrade을 유도한다.
- **방어**: monotonic sensitivity lattice를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 06 — credential smuggling

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 credential smuggling을 유도한다.
- **방어**: credential-field rejection를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 07 — unbounded token or item growth

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 unbounded token or item growth을 유도한다.
- **방어**: hard token/item limits를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 08 — retry duplication

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 retry duplication을 유도한다.
- **방어**: idempotent content-bound references를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 09 — concurrent stale writer

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 concurrent stale writer을 유도한다.
- **방어**: CAS/fencing or append-once semantics를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 10 — provider outage

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 provider outage을 유도한다.
- **방어**: bounded degrade or abstention를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 11 — prompt injection as control

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 prompt injection as control을 유도한다.
- **방어**: source content remains data를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 12 — missing evidence locator

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 missing evidence locator을 유도한다.
- **방어**: fail-closed verification를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 13 — modality escalation

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 modality escalation을 유도한다.
- **방어**: minimum source modality wins를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 14 — conflict hiding

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 conflict hiding을 유도한다.
- **방어**: explicit conflict groups and flags를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 15 — silent omission

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 silent omission을 유도한다.
- **방어**: bounded omission reason codes를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 16 — expired record reuse

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 expired record reuse을 유도한다.
- **방어**: absolute expiry enforcement를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 17 — telemetry body leak

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 telemetry body leak을 유도한다.
- **방어**: IDs, hashes, counts only를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 18 — external side effect

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 external side effect을 유도한다.
- **방어**: Runtime emits intent/proposal only를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 19 — non-deterministic serialization

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 non-deterministic serialization을 유도한다.
- **방어**: canonical UTF-8 JSON and sorted sets를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.

## Round 20 — completion by prose

- **공격**: Proactive Suggestion and Attention Ledger 경계에서 completion by prose을 유도한다.
- **방어**: machine gate and signed checkpoint를 계약과 테스트로 강제한다.
- **기계 증거**: `tests/phase4/test_p4_03_to_13_services.py` 및 G4 matrix의 `P4-10` 항목.
