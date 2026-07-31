# Shadow Measurement Operations Runbook

Operating a native shadow-measurement cohort: provisioning, continuous
collection, failure modes, and recovery.

## The 60-minute cliff

`NativeShadowMeasurementCollector` enforces `_MAX_INTERVAL_SECONDS = 3600`
between consecutive samples. A gap longer than 60 minutes fails every
subsequent append with:

```
measurement interval gap or clock rollback; reset cohort
```

**This is unrecoverable.** The cohort cannot be repaired, resumed, or
back-filled — that is the point. A 72-hour continuity claim must not survive
an unobserved hole, so the collector refuses to pretend otherwise. The only
remedy is to archive the dead cohort and provision a new one, restarting the
72-hour clock.

This has already claimed one cohort in practice: collection was configured
after provisioning rather than alongside it, an 8-hour gap opened overnight,
and the cohort was dead by morning.

Consequences to plan for:

- **Never provision a cohort before its collector is running.** Provision and
  start collection in the same operation.
- **Machine sleep is fatal.** A laptop asleep for more than an hour kills the
  cohort. Run the cohort on a machine set to stay awake, or accept restarts.
- A 5-minute collection interval leaves a 12x margin against the cliff.

## Provisioning

```sh
/usr/local/bin/python3.12 scripts/provision_shadow_measurement.py \
  --output-dir artifacts/second-brain/operational-cohort
```

This generates, in one shot: the retained authority (Ed25519 signing key plus
append-only journal), the measurement keypair, all six digest-bound manifests,
a signed cohort checkpoint, and the initialized cohort.

The directory must not already exist or contain state; provisioning refuses to
overwrite a cohort.

### The cohort directory cannot be moved

The authority endpoint is an **absolute path** baked into the signed checkpoint
root:

```
retention-authority://local/<absolute path>/authority
```

The collector verifies the live authority's endpoint against that pin on every
open. Moving or renaming the cohort directory changes the endpoint, fails the
pin check, and kills the cohort exactly as an interval gap would. Choose the
path at provisioning time and leave it there.

### Keys

`measurement.key` and `authority/authority.key` are raw Ed25519 private keys
written `0600`. They are covered by the repository's `*.key` ignore rule, and
the whole cohort directory is ignored as runtime state. Losing
`measurement.key` means no further samples can be signed; the cohort is then
readable but closed.

## Continuous collection

A launchd agent runs the collector every 5 minutes:

`~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist`

```sh
launchctl load   ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
launchctl unload ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
launchctl list | grep shadow-collector     # second column is last exit status
```

Point `ProgramArguments` at a checkout that does **not** move between branches.
A worktree pinned to the implementation branch works well; the main checkout
does not, because switching branches removes the collector script and opens a
gap that will kill the cohort.

Logs land in the cohort directory as `collector.log` and `collector.err`.

### Health check

```sh
C=artifacts/second-brain/operational-cohort
grep -o '"collected_at": "[^"]*"' $C/collector.log | tail -3   # 5 min apart
cat $C/collector.err                                            # must be empty
```

Consecutive `collected_at` values more than an hour apart mean the cohort is
already dead, whatever the log says afterwards.

### Watching for the cliff

`scripts/watch_shadow_measurement.py` classifies the cohort and, with
`--notify`, raises a macOS notification when that classification changes:

| State | Meaning |
|---|---|
| `collecting` | healthy and inside the window |
| `stalling` | no sample for 40 minutes; the cohort is still saveable |
| `dead` | a gap, rollback, or unreadable journal already ended it |
| `complete` | every SLO reason cleared |

```sh
/usr/local/bin/python3.12 scripts/watch_shadow_measurement.py \
  --cohort-dir artifacts/second-brain/operational-cohort
```

A second agent, `com.wiki-spike.shadow-watcher`, runs this every 15 minutes
with `--notify`.

The `stalling` state is the point of the watcher. The cliff is unrecoverable
once crossed, so an alert that arrives with the cohort already dead tells you
only that three days are gone. Warning at 40 minutes leaves 20 minutes to wake
the machine or reload the collector while the cohort can still be saved.

Transitions are announced once each, tracked in `.watch-state`, so the agent
does not repeat itself.

## What the collector actually measures

`scripts/collect_shadow_samples.py` is a **pipeline canary**, not a
measurement. It emits synthetic samples with hardcoded outcomes to exercise the
append / sign / authority / journal path end to end.

Its output must never be read as evidence for a cutover decision. Genuine
measurement requires source-specific adapters that query real Codex,
Claude/Memory Bank, Git, and Markdown sources and record real outcomes. Until
those exist, a cohort proves the plumbing works and nothing about recall
quality.

## Reading status

```sh
PYTHONPATH=src /usr/local/bin/python3.12 scripts/second_brain_shadow_measurement.py status \
  --db <cohort>/cohort.json \
  --authority-endpoint "$(python3 -c "import json;print(json.load(open('<cohort>/authority/metadata.json'))['endpoint'])")" \
  --measurement-public-key <cohort>/measurement.pub \
  --measurement-key-fingerprint <fingerprint> \
  --resolved-scope <cohort>/scope.json --contract <cohort>/contract.json \
  --source-manifest <cohort>/source.json --capability-manifest <cohort>/capability.json \
  --benchmark-manifest <cohort>/benchmark.json --holdout-manifest <cohort>/holdout.json
```

`NOT_READY` with reasons is the expected state for the entire 72-hour window.
`EVIDENCE_COMPLETE_NON_SERVING` requires every reason to clear: 72 hours of
continuous wall-clock, 500 cohort queries, 200 parity cases per source, zero
safety violations, and every Wilson lower bound above its floor. There is no
third outcome and no serving state.

At 4 samples per 5-minute cycle the denominators clear comfortably: 48 samples
per hour is 864 per source across 72 hours, against a 200 floor.

## Recovery

**Interval gap or clock rollback** — the cohort is dead. Archive it under a
name that records the cause, then provision fresh with the collector already
running:

```sh
launchctl unload ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
mv artifacts/second-brain/operational-cohort \
   artifacts/second-brain/cohort-dead-interval-gap-<date>
/usr/local/bin/python3.12 scripts/provision_shadow_measurement.py \
  --output-dir artifacts/second-brain/operational-cohort
launchctl load ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
```

Keep the dead cohort. Its journal is signed evidence of what actually happened.

**Torn authority journal** — a crash mid-append can leave a partial frame.
`LocalRetainedAuthority` fails closed on a malformed frame rather than
truncating, so the authority will not open. There is no repair tool; treat it
as a dead cohort and reset.

**Authority pins changed** — the endpoint, identity, policy id, or key
fingerprint no longer match the signed root. Usually means the cohort directory
was moved or the authority key was replaced. Not repairable; reset.
