# Partner registry drift — seam-sdk#203 acceptance

> **📦 ARCHIVED 2026-10-18 — DELIVERED, merged as PR #252 (`179a7fa`, closes #203).** Archived during `/sweep`
> after a delivery verification against this tree. All three phases are DONE and reachable from `main`.
> `scripts/check_registry_drift.py` reads `zer07labs/partner` with the one resolved token, and fails when partner lags
> internal. Partner issues file under `PARTNER_DRIFT_TITLE` with their own suppression scope. Tracking issue
> [seam-sdk#203](https://github.com/zer07labs/seam-sdk/issues/203) is **CLOSED**. This plan's five `ASSUMPTIONS.md`
> entries were confirmed by `/reconcile` on 2026-10-18 (PR #267, `460c161`; `DECISIONS.md`'s 2026-10-18 entry). That
> left none `UNCONFIRMED`. The last 10 scheduled `registry-drift.yml` runs before archiving
> (2026-10-16 → 2026-10-18) all succeeded.

**Issue:** [seam-sdk#203](https://github.com/zer07labs/seam-sdk/issues/203). Its first ask, promoting
the current release to `partner`, was done before this plan by `publish.yml`'s `promote-partner`
job, `promote-partner-backfill.yml` and `scripts/promote-to-partner.sh`. On 2026-10-12, live
listings showed `partner` holding every `seam-sdk` version ≥ 0.7.47 in both formats, including the
latest, 0.45.0. The only versions missing are 0.3.0–0.7.43, which predate the backfill boundary.
That leaves the acceptance clause still open: *"the check fails if `partner` lags `internal`"*.
`scripts/check_registry_drift.py` queries only `zer07labs/internal` (`REGISTRY_URL`, line 190).

**Ground truth, checked live on 2026-10-12:**
- `CLOUDSMITH_API_KEY`, the credential `registry-drift.yml` already resolves first, returns
  HTTP 200 with rows for **both** `internal` and `partner`. No new secret or permission is needed.
- Every `CANARY_VERSIONS` entry (0.7.71, 0.7.50, 0.7.65, 0.7.75) is on `partner` in both formats, so
  the same roster can prove the partner instrument.
- ~~`CARGO_REGISTRIES_ZER07LABS_TOKEN`, the workflow's fallback, returns 401 on both registries.~~
  **Corrected 2026-10-12:** that was measured with Doppler's copy, which is stale (#251). The
  GitHub org secret the workflow uses is live: it published `seam-verify v0.3.0` on 2026-10-09.

**Semantics.** The check asks two questions about main's declared version, with one clock and one
grace ladder:
1. Does `internal` serve it in both formats? This is the existing question, unchanged.
2. Does `partner` serve it in both formats? This is new.

`publish.yml`'s `promote-partner` job runs in the same workflow as the publish, so the existing
soft/hard windows bound it too. A version missing from `internal` is reported as today; the
partner gap follows from it, because promotion copies from internal. A version on `internal` and
missing from `partner` is a **promotion lag**. It gets its own issue title, so it never collides
with the internal drift issue or `release-outcome`'s, plus its own suppression scope and its own
remediation pointing at `promote-partner-backfill.yml` and `scripts/promote-to-partner.sh`.

**PR strategy: one PR.** The three phases make one reviewable story of about one script, its test
file and docs. None of them is independently useful to ship.

---

## Phase 1: query and verdict for `partner`
- **Risk:** complex. It crosses the network boundary and reshapes the verdict path later phases
  build on.
- **Delivers:** a `PARTNER_REGISTRY_URL` beside `REGISTRY_URL`. `fetch_registry` and
  `assert_live_instrument_healthy` take the registry URL, defaulting to internal. Live mode
  proves each registry's instrument with the canary roster before its target is read, giving 4
  GETs on the happy path in the order internal canary, internal target, partner canary, partner
  target. Offline mode adds `--partner-packages-json`. Without it, partner is **not checked**, and
  the output says so explicitly; a clean verdict never claims partner. The workflow never runs
  offline mode, which is already pinned by a test. Partner missing formats feed the same tiers
  (deferred / warned / drift) on the same clock. A new remediation, "State P", names promotion.
  Any `InfraError` from either registry is still exit 2.
- **Files:** `scripts/check_registry_drift.py`, `scripts/test_registry_drift_gate.py`.
- **Acceptance:**
  1. Live, with both registries serving the target: exit 0, exactly 4 curl calls in the order
     above, and the clean line names both registries.
  2. Live, internal serving and partner empty, past the hard window: exit 1 with "State P"
     remediation naming `promote-partner-backfill.yml` and `scripts/promote-to-partner.sh`.
     Inside the soft window: exit 0, deferred. Inside the warn band: exit 0 with `::warning::`.
  3. Live, partner canaries all empty and internal fine: exit 2, and the message names partner.
  4. Partner's URL is the internal URL with only the repository slug changed, and its query is
     the same `_query_for`. A test pins this.
  5. Offline without `--partner-packages-json`: the existing behaviour is unchanged, and stdout
     says partner was not checked. Offline with the flag: partner rows are checked through
     `assert_offline_instrument_healthy`. An empty file exits 2.
  6. The token never appears in output on any new path.
- **Tests:** the curl stub gains per-registry routing (`/partner/` in the URL). There is a new
  test for each acceptance item, and the existing call-count and order tests are updated to 4.
- **Revised after plan re-verify (2026-10-12):**
  - *Partner failure must not blind internal.* The internal question is answered first. A
    partner `InfraError` is captured instead of raised. If internal is past the hard window and
    missing formats, the run exits 1 with that verdict and prints the partner error as
    `::error::`. Otherwise a partner `InfraError` exits 2. If internal does not serve the
    version, a partner gap is a consequence of that, never a second verdict.
  - *Windows.* The `SOFT_GRACE_MINUTES` comment is updated so the declared ceilings include
    `promote-partner`'s 20 minutes (`publish.yml:768-773`), about 60 minutes in total, which is
    still under 90.
  - *Canary evidence.* The `CANARY_VERSIONS` comment gains a partner clause: all four were
    observed on partner in both formats on 2026-10-12.
  - *Error messages* from `fetch_registry` and `assert_live_instrument_healthy` name the registry.
  - *State P remediation* says to first confirm that `registry-smoke` passed for v{version},
    because `promote-partner` is skipped when smoke fails and the backfill does not re-check it.
  - *Test stub.* Partner mirrors the internal responses by default; a `partner_responses`
    argument overrides it. The stub logs the registry slug, and a `registries_queried` helper
    returns `(registry, version)` pairs. The partner output line must not start with
    `registry serves:`, and the clean line keeps "both formats".
  - *Phase 3 check.* The workflow YAML is parsed before and after; the parsed data must be equal.
- **As built, and where it diverged:**
  - `registries_queried` parses the slug from the URL the stub logs, rather than the stub
    logging it separately. Equivalent.
  - An added refusal: `--partner-packages-json` without `--packages-json` exits 2, so a saved
    partner answer is never compared with a live internal one.
  - `_load_packages_json(path, flag)` names the flag that was actually passed.
  - Any non-`InfraError` raised by the partner block is captured as a partner fault, so it
    cannot pre-empt internal's verdict.
  - Partner fault beside a SUPPRESSED internal drift exits 2: there is no finding left for the
    fault to stand beside.
  - Carried to Phase 2: partner verdicts return before reporting, which also skips the heartbeat.
    Phase 2 replaces that early return.
- **Status:** DONE

## Phase 2: reporting for a partner lag
- **Risk:** complex. It writes to GitHub issues and adds a title namespace that must not collide.
- **Delivers:** `PARTNER_DRIFT_TITLE = "Registry drift: seam-sdk {version} is not on partner"`.
  When internal is clean and partner is missing, the drift path files, comments and reopens with
  the same decision table, and suppression applies, on that title. When internal is missing, the
  internal issue is filed as today and its body notes whether partner is also missing; no second
  issue is filed. `report_clean` also emits the "can be closed" notice for an open partner issue.
- **Files:** `scripts/check_registry_drift.py`, `scripts/test_registry_drift_gate.py`.
- **Acceptance:**
  1. A partner-only drift run with `--report` creates exactly one issue with
     `PARTNER_DRIFT_TITLE`, and its body carries State P remediation.
  2. A closed and labelled partner issue suppresses: exit 0 with `::warning::`. A closed,
     unlabelled one gets comment-then-reopen.
  3. No title prefix-collides with `DRIFT_TITLE` or `RELEASE_NOTICE_TITLE` in either direction.
  4. A clean run with an open partner issue prints the `::notice::`.
  5. With internal and partner both missing, one issue is filed, the internal one, and its body
     mentions partner.
  6. The partner "can be closed" notice is printed only when partner was actually checked. An
     offline `--report` run without `--partner-packages-json` never prints it.
  7. One `fetch_issues` listing per run, so the drift path's `gh` call count is unchanged. The
     partner issue body cross-links an open `release-outcome` issue, as `report_drift` does.
- **As built, and where it diverged:**
  - Phase 1's early return for partner verdicts is gone; the heartbeat now runs after a partner
    drift too.
  - The internal issue's partner row states only what the run observed: "not checked" (offline,
    no dump), "**could not be read**" (queried and failed), "serves it", or "also missing …".
    "Expected" is claimed only for formats internal is missing too; a format internal serves and
    partner does not is named as a promotion lag of its own.
  - Added beyond the plan: a partner-lag drift prints the "can be closed" notice for an open
    INTERNAL issue on the same version (internal serving it is what made this a partner lag),
    from the same listing. The deferred/warned partner tiers still print nothing and read
    nothing from GitHub — the grace invariant outranks the notice.
  - No `or set()` fallback on the partner call: the subject is partner only when partner was
    read and is short, so an empty set cannot reach it.
- **Status:** DONE

## Phase 3: workflow comments and docs
- **Risk:** simple.
- **Delivers:** the `registry-drift.yml` header and the step comment say the check covers both
  repositories with one credential. README.md § registry drift, CLAUDE.md's command line and the
  script's module docstring are updated.
- **Files:** `.github/workflows/registry-drift.yml` (comments only), `README.md`, `CLAUDE.md`,
  `scripts/check_registry_drift.py` (docstring).
- **Acceptance:** the workflow logic is byte-identical outside comments, and every existing
  workflow-structure test passes.
- **As built, and where it diverged:**
  - The step's "one credential" comment sits in the `env:` map, not in the `run: |` script as
    first drafted. A shell comment inside the block scalar is part of the parsed data, and the
    before/after `yaml.safe_load` comparison caught it.
  - The header's "ONE issue per version" became "per version per title".
  - CLAUDE.md and README now say `python/.venv/bin/python` (3.11+). The old `python3` example
    was already wrong on this workstation, where the system python3 is 3.9 and the script
    refuses it.
- **Status:** DONE
