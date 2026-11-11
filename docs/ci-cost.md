# CI cost

This is the record of what seam-sdk's GitHub Actions spend is, and what each cost pass changed.
Decisions behind it are in `DECISIONS.md` (D-CI-PUSH-MAIN, D-CI-CONCURRENCY, D-CI-RUNNER, D-CI-PATHS);
the path-filter call is also A-BP8S-2 in `ASSUMPTIONS.md`.

## How it is billed

- Every job runs on Blacksmith (since #279; first Blacksmith job 2026-10-20 UTC). Blacksmith bills per job, per started minute:
  $0.004/min on `blacksmith-2vcpu-ubuntu-2404`, $0.008/min on `blacksmith-4vcpu-ubuntu-2404`.
- Before #279, jobs ran on GitHub-hosted `ubuntu-latest`. The repo is public, so those standard-runner
  minutes are free; every billed dollar is Blacksmith.
- There is **no merge queue**. A PR runs `ci.yml` once per push (superseded runs are cancelled), and the
  merge commit runs it once more on `main`. The required check is `ci-ok` alone.

## Measured spend (2026-10-09 .. 2026-11-08)

Billed minutes on Blacksmith since 2026-10-20, by workflow and trigger:

| Workflow | Trigger | Runs | Billed min | min/run |
|----------|---------|-----:|-----------:|--------:|
| ci | push to main | 70 | 1048 | 15.0 |
| ci | push of a release tag | 69 | 1040 | 15.1 |
| ci | pull_request | 43 | 622 | 14.5 |
| ci | push to a PR branch | 42 | 607 | 14.5 |
| publish (internal) | push / dispatch | 38 | 272 | 7.2 |
| registry drift | schedule / dispatch | 141 | 141 | 1.0 |
| release (follow runtime) | dispatch | 39 | 46 | 1.2 |
| framework co-install | pull_request / schedule | 35 | 35 | 1.0 |
| **Total** | | | **3811** | |

Over a 30-day window that is about 5,770 min, roughly $46 at the 4vcpu rate. GitHub-hosted minutes before
2026-10-20 (3,701) were free and are not counted.

A `ci` run is 14 jobs, each one under a minute of wall clock on 4vcpu (latest green main run: guards 53 s,
python 42 s, integration 29 s, kotlin 26 s, verify-msrv 24 s, typescript 21 s, go 20 s, verify 19 s,
java 19 s, spec pin 15 s, sibling quotes 9 s, version lockstep 6 s, preflight 4 s, ci-ok 3 s). So each job bills
one minute, and the run's cost is set by the job count and the per-minute rate, not by speed.

## Pass 1 — #336 (2026-11-05): push on main only, cancel superseded PR runs

- `push:` became `branches: [main]`. That removed the push-to-PR-branch and push-of-a-tag rows above.
- Superseded `pull_request` runs are cancelled.
- Estimated 30-day spend: about 5,770 → 3,270 min (about $46 → $26).

## Pass 2 — BP-8 PR (2026-11-08): the smallest runner that fits

- Every `ci.yml` job except `integration` moved from 4vcpu to 2vcpu, as did `registry-drift.yml`'s and
  `framework-coinstall.yml`'s job.
  - The jobs are I/O- and setup-bound, finishing in under a minute on 4vcpu, so 2vcpu costs half per minute.
    The risk is a job crossing a minute boundary on the slower runner, which turns 1 billed minute into 2.
  - `integration` stays on 4vcpu. On a cache miss it builds `seamd` from source under a 45-minute timeout,
    which is a measured need for the larger runner.
  - `publish.yml` and `release-on-runtime.yml` are deploy/publish jobs and were not touched.
- Estimated saving: about $8 a month (the 13 moved `ci` jobs at half the rate, over about 2,000 `ci` job-minutes
  a month after pass 1).
- Per-job durations on 2vcpu, from this PR's own CI run, are in the table below. If a job's duration
  regularly crosses 60 s, move that one job back to 4vcpu; that is a one-line change.

| Job | 4vcpu (latest green main run) | 2vcpu (this PR's run) |
|-----|------------------------------:|----------------------:|
| guards (no credentials required) | 53 s | 43 s |
| python (ruff · pytest) | 42 s | 39 s |
| integration (live seam-grpc round-trip) | 29 s | 42 s (stays 4vcpu) |
| kotlin (gradle test) | 26 s | 25 s |
| verify (builds at its declared MSRV) | 24 s | 25 s |
| typescript (typecheck · build · test) | 21 s | 28 s |
| go (test) | 20 s | 26 s |
| verify (the independent verifier) | 19 s | 26 s |
| java (gradle test) | 19 s | 18 s |
| spec pin (the vendored spec is verbatim and current) | 15 s | 19 s |
| sibling quotes (claims about seam-adapters) | 9 s | 10 s |
| version lockstep (python == typescript) | 6 s | 8 s |
| preflight (secret gating) | 4 s | 5 s |
| ci-ok | 3 s | 6 s |

Every job stays under 60 s on 2vcpu (longest: guards, 43 s), so each still bills one minute and the
rate halves as estimated. Run 42534222847 (PR #338) against run 42500484461 (main); single runs, so a few seconds of noise.

## Considered and not adopted

- **Path filters (D-CI-PATHS).** seam-sdk has no merge queue, so there is no `merge_group` run to filter. On
  `pull_request`, skipping a language's jobs would mean `ci-ok` deciding which skips are legitimate, and
  `publish.yml` / `release-on-runtime.yml` read `ci-ok` by SHA as a full-suite green. A per-path `ci-ok` would
  let a release commit's green mean less than it does now. The PR-event analogue would save about 145 min per
  30 days, about $1 a month after pass 2.
- **Back to GitHub-hosted runners.** Reverting #279 would make non-publish CI free on this public repo (about
  $20 a month of non-publish spend before this pass, roughly $12-15 after it, → $0). #279 was an org-level Blacksmith migration, so it is the owner's call,
  recorded in `DEFERRED.md`.
