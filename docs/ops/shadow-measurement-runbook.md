# Shadow Measurement Operations Runbook

Operating a native shadow-measurement cohort: provisioning, cumulative active
observation, failure modes, and recovery. This is evidence collection only; it
does not grant live, shadow, cutover, or serving authority.

## Effective observation and gaps

The 72-hour requirement is **cumulative effective observation time**, not 72
uninterrupted calendar hours. For each pair of adjacent recorded samples,
`NativeShadowMeasurementCollector` counts the delta only when it is positive
and no more than `_MAX_INTERVAL_SECONDS = 3600`. A longer gap is retained in
the immutable signed journal but contributes zero effective seconds.

This makes normal mobile use safe: the laptop may sleep, power off, move, or be
offline. Resume collection with the same cohort; valid previously accumulated
effective time remains intact. The calendar date at which 72 effective hours
finish can therefore be later than three days.

Reports expose `effective_seconds`, `excluded_gap_seconds`, and
`excluded_gap_count`. The compatibility `continuous_seconds` value is only the
current uninterrupted active run after the latest excluded gap; it is not the
readiness authority. Readiness uses `effective_seconds` plus every existing
SLO denominator and quality check.

Only a clock rollback/non-positive delta is rejected. Journal corruption or
unreadability also remains fail-closed. Neither condition can be repaired by
back-filling time.

Consequences to plan for:

- A 5-minute collection interval gives good active-observation coverage.
- Do not rewrite or back-fill the journal after a gap; the gap must remain
  visible as evidence.

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
pin check, and is a fatal authority mismatch. This is distinct from an ordinary
positive collection gap, which is retained and excluded from effective time.
Choose the path at provisioning time and leave it there.

### Keys

`measurement.key` and `authority/authority.key` are raw Ed25519 private keys
written `0600`. They are covered by the repository's `*.key` ignore rule, and
the whole cohort directory is ignored as runtime state. Losing
`measurement.key` means no further samples can be signed; the cohort is then
readable but closed.

## Active collection

A launchd agent runs the collector every 5 minutes:

`~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist`

```sh
launchctl load   ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
launchctl unload ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
launchctl list | grep shadow-collector     # second column is last exit status
```

Point `ProgramArguments` at a checkout that does **not** move between branches.
A worktree pinned to the implementation branch works well; the main checkout
does not, because switching branches can interrupt collection or remove the
collector script. Such a positive interruption is an excluded pause, not cohort
death; endpoint-pin mismatch or journal corruption remains fatal.

Logs land in the cohort directory as `collector.log` and `collector.err`.

### Health check

```sh
C=artifacts/second-brain/operational-cohort
grep -o '"collected_at": "[^"]*"' $C/collector.log | tail -3   # 5 min apart
cat $C/collector.err                                            # must be empty
```

Consecutive `collected_at` values more than an hour apart are excluded gaps,
not cohort death. The next collected sample resumes the same valid cohort.

### Watching pauses

`scripts/watch_shadow_measurement.py` classifies the cohort and, with
`--notify`, raises a macOS notification when that classification changes:

| State | Meaning |
|---|---|
| `collecting` | samples are arriving |
| `paused` | the laptop is asleep, offline, or otherwise silent; resume preserves accumulated effective time |
| `dead` | a clock rollback or corrupt/unreadable journal prevents use |
| `blocked` | another contract or authority error needs manual investigation and is preserved, never auto-restarted |
| `complete` | every SLO reason cleared |

```sh
/usr/local/bin/python3.12 scripts/watch_shadow_measurement.py \
  --cohort-dir artifacts/second-brain/operational-cohort
```

A second agent, `com.wiki-spike.shadow-watcher`, runs this every 15 minutes
with `--notify`.

The watcher reports remaining effective seconds, not a fixed wall-clock ETA.
Calendar completion can be later than 72 hours because excluded gaps do not
count. A pause must never archive or reprovision the cohort.

Transitions are announced once each, tracked in `.watch-state`, so the agent
does not repeat itself.

### Surviving a shutdown

A shutdown, sleep, or offline break is an excluded interval, not cohort death.
On restart, the collector appends a new sample to the same journal and starts
accumulating active intervals again. It does not count the shutdown gap.

With `--auto-restart`, the watcher may archive and reprovision only a cohort
that is dead because its journal cannot be read or its clock rolled back. It
never restarts a `paused` cohort.

```sh
/usr/local/bin/python3.12 scripts/watch_shadow_measurement.py \
  --cohort-dir artifacts/second-brain/operational-cohort --notify --auto-restart
```

Launch agents reload at login, so after a reboot the collector resumes the
existing cohort. Planned downtime delays calendar completion but does not
discard valid prior effective observation.

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

The standalone `scripts/second_brain_shadow_measurement.py` CLI deliberately
fails closed without deployment-injected authority evidence. Read status only
through that authenticated composition path; this runbook command does not
grant authority to create, attach, or operate a cohort.

`NOT_READY` with reasons is the expected state until the effective-observation
window and all SLOs clear. `EVIDENCE_COMPLETE_NON_SERVING` requires every
reason to clear: 72 hours of cumulative effective observation, 500 cohort
queries, 200 parity cases per source, zero
safety violations, and every Wilson lower bound above its floor. There is no
third outcome and no serving state.

At 4 samples per 5-minute cycle the denominators clear comfortably: 48 samples
per hour is 864 per source across 72 hours, against a 200 floor.

## Recovery

**Clock rollback or corrupt/unreadable journal** — the cohort is dead. Archive
it under a name that records the cause, then provision fresh with the collector
running:

```sh
launchctl unload ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
mv artifacts/second-brain/operational-cohort \
   artifacts/second-brain/cohort-dead-authority-or-journal-<date>
/usr/local/bin/python3.12 scripts/provision_shadow_measurement.py \
  --output-dir artifacts/second-brain/operational-cohort
launchctl load ~/Library/LaunchAgents/com.wiki-spike.shadow-collector.plist
```

**Long sleep/offline gap** — do not archive, reset, or back-fill. Resume normal
collection; the journal preserves the excluded gap and the report preserves
previous effective seconds.

Keep a dead cohort. Its journal is signed evidence of what actually happened.

**Torn authority journal** — a crash mid-append can leave a partial frame.
`LocalRetainedAuthority` fails closed on a malformed frame rather than
truncating, so the authority will not open. There is no repair tool; treat it
as a dead cohort and reset.

**Authority pins changed** — the endpoint, identity, policy id, or key
fingerprint no longer match the signed root. Usually means the cohort directory
was moved or the authority key was replaced. Not repairable; reset.
