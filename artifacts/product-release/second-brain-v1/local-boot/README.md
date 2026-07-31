# Local boot artifacts (non-production)

Generated: 2026-07-30T15:10:27Z

Local bootstrap receipt for Second-Brain V2:

1. dual-key signed DB-01..08 decision records
2. ResolvedScope + signed contract envelope (`RESOLVED`)
3. DB-05 evaluation-governance evidence via `scripts/second_brain_evaluation_governance.py`
4. authenticated `wiki status` => `authenticated V2 product ready`
5. synthetic ledger create/approve + recall smoke

## Layout
- `decisions/` signed records (public keys + signatures only)
- `evidence/` packs, design notes, DB-05 corpora/manifests/governance
- `contract-envelope.json`, `resolved-scope.json`, `boot-report.json`
- `public-keys.json` public keys only

## Never commit
- private keys (`~/keys/wiki-spike-local/*.pem`)
- runtime DB/CAS under `/private/tmp/wiki-spike-local-runtime-v2`

## Classification
`local-bootstrap-non-production`
