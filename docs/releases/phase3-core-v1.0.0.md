# Phase 3 Core release marker — `phase3-core-v1.0.0`

This file is an instruction record, not proof by itself. The signed checkpoint at
`artifacts/checkpoints/g3/phase3-g3-checkpoint.json` is the contract identity.

After P3-12 is merged and both required workflows are green on the merge commit:

```bash
git fetch origin main
git checkout --detach <P3-12_MERGE_COMMIT>
python scripts/verify_g3_checkpoint.py
python scripts/p3_12_conformance.py --verify-only
git tag -a phase3-core-v1.0.0 <P3-12_MERGE_COMMIT> \
  -m "Phase 3 Memory OS Core v1.0.0 — see signed G3 checkpoint"
git push origin refs/tags/phase3-core-v1.0.0
```

The tag must never be moved. A later contract uses a new semantic version and a new
signed checkpoint. Phase 4 must pin the checkpoint ID, source root, and tag commit.
