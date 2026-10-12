# Partner serves the newest release on internal — seam-sdk#253

**Issue:** [seam-sdk#253](https://github.com/zer07labs/seam-sdk/issues/253). It follows #203 (PR #252, `179a7fa`) and closes the
coverage limit recorded in `ASSUMPTIONS.md` ("Partner is judged on main's declared version only").

**Question:** does `zer07labs/partner` serve the newest `seam-sdk` version that `zer07labs/internal` serves in both
formats? Today `scripts/check_registry_drift.py` asks about partner only for main's declared version, and only when
internal serves it.

**Decided by the owner (2026-10-12):**
- **D4, title.** Reuse `PARTNER_DRIFT_TITLE`: one issue per missing version, whichever question finds it. The issue
  body says which question found it.
- **D6, scope.** Check the newest version only. The residual case is recorded rather than covered.

## Ground truth, checked live on 2026-10-12

All reads were read-only, with `CLOUDSMITH_API_KEY`.

- **`sort=-version` is honoured and numeric.** It was checked over 231 rows on internal in 3 pages. `sort=version`
  reverses the order.
- **A wrong value fails, a wrong name does not.** `sort=-bogus` returns HTTP 400. `ordering=…`, a wrong parameter
  name, is silently ignored and the server falls back to `-date`. So `NEWEST_QUERY` is pinned by a test, and the
  client checks the ordering itself.
- **The data is uniform.** There are no pre-releases, and every row carries `uploaded_at`. Partner rows carry their
  own `uploaded_at`, about 60 s after internal's.
- **Partner has no gap today.** It holds every internal version ≥ 0.7.47. The newest version on internal is 0.45.0;
  main declares 0.45.1, which is a suppressed internal drift (#250).

## Corrections to the issue's premise

- **0.40.0, 0.41.0, 0.42.0, 0.43.0 and 0.43.2 never reached internal.** They were internal publish refusals, not
  promotion failures. No partner check can see them. The `ASSUMPTIONS.md` example that cites them is corrected in
  Phase 3.
- **"Newest" catches a failed promotion of a short-lived version only if that version stays newest past the hard
  window**, about 6 h. This residual is recorded, not covered (D6).

## Design

- **D1. Finding the newest version.** One unscoped, sorted GET of internal:
  `NEWEST_QUERY = "?query=seam-sdk&sort=-version&page_size=<PAGE_SIZE>"`, a constant. The client picks the largest
  `SAFE_VERSION` int tuple whose rows carry both `REQUIRED_FORMATS`.
  - The curl, decode and parse steps move into a shared `_curl_json(url, query)`. `fetch_registry` keeps its
    version-scoped guards on top of it; `fetch_newest` adds its own.
  - **`fetch_newest`'s guards:**
    - The response is a non-empty list containing `seam-sdk` rows.
    - The plain versions are non-increasing in tuple order.
    - **Page-edge rule:** on a full page, the lowest version on the page is never chosen.
    - The newest version is at least the canary that proved internal this run.
    - The newest version is at least the declared version whenever internal serves the declared version.
  - Any guard failure is an InfraError (exit 2).
- **D2. Clock.** The latest `uploaded_at` among internal's rows at V_new in the required formats. The same `_tier`
  ladder and soft/hard minutes apply, on this question's own clock. The skew guard applies.
  `_parse_upload_stamp` takes a `str` that matches a strict ISO-8601 regex, and it never prints the value.
- **D3. Composition.**
  - **Skip:** when V_new equals the declared version and the declared check already read partner, the question is
    already answered.
  - **When it runs:** after the partner block and before the clock section, captured the same way as the partner
    block.
  - **Precondition:** partner's instrument was proven this run.
  - **The partner read** reuses `fetch_registry(V_new, …, PARTNER_REGISTRY_URL)`.
  - **Calls:** 5 GETs when V_new equals the declared version, otherwise 6.
  - **Exit codes:**

    | Newest question | Declared question | Exit |
    |---|---|---|
    | drift (unsuppressed) | any | 1 |
    | fault | unsuppressed drift | 1 + `::error::` |
    | fault | clean, grace or suppressed | 2 |

  - **GitHub:** one issue listing per run, fetched once and passed in.
    - The grace rule applies per question.
    - A newest-clean "can be closed" notice is posted only when the declared question already reached GitHub.
    - The heartbeat fires once, if and only if the run read GitHub.
- **D4. Reporting.** `PARTNER_DRIFT_TITLE` with a `question="newest"` lede that names V and D. State P remediation
  and the `release-outcome` cross-link apply, both for V.
- **D5. Instrument health.** The existing canaries prove the credential and the query shape. The unscoped query's own
  checks prove the sort. An empty or garbage response is exit 2.
- **D7. Offline mode.** The newest version is computed from the `--packages-json` dump, with no ordering or page-edge
  check. Partner at V_new comes from `--partner-packages-json`. Without that dump the question is NOT CHECKED.
  `rows()` fixtures gain `uploaded_at`.
- **D8. Token safety.** Every invariant from #203's final verify holds. In addition, `uploaded_at` never reaches the
  output, and only `SAFE_VERSION` values are echoed.

**PR strategy:** one PR. The three phases are one story: one script, its tests and the docs. Phase 1 alone would
print newest drifts without filing them.

---

## Phase 1: newest-version discovery, verdict and exit
- **Risk:** complex. It adds a network query shape and changes the exit mapping.
- **Delivers:**
  - **New code:** `NEWEST_QUERY`, `_curl_json`, `fetch_newest`, `newest_complete_version`, `_parse_upload_stamp`.
  - **In `main()`:** a captured newest block, offline handling, the newest clock, a `newest on internal: …` line,
    tier messages, and the D3 exit table.
  - **Interim:** `--report` prints a newest drift without filing it. Phase 2 replaces that.
- **Files:** `scripts/check_registry_drift.py`, `scripts/test_registry_drift_gate.py`.
- **Acceptance:**
  1. Live, newest equals declared and both registries serve it: exit 0, exactly 5 curl calls in the order internal
     canary, internal target, partner canary, partner target, internal unscoped. The 5th URL is exactly
     `REGISTRY_URL + NEWEST_QUERY`.
  2. Declared version missing on internal, newest 0.7.78 served by partner, past the hard window: exit 1 (the
     declared drift), 6 calls with the 6th `("partner","0.7.78")`. With the declared drift suppressed, exit 0.
  3. Newest lag, with the declared version clean: `uploaded_at` 30 / 200 / 14400 minutes old gives DEFERRED (0),
     `::warning::` (0) and State P (1) respectively. The tier follows `uploaded_at`, never git.
  4. Each of these exits 2 with the declared verdict still printed: `[]`, ascending order, a full page of one
     version, newest below the proving canary, newest below a served declared version, a missing or garbage
     `uploaded_at`, a future `uploaded_at`.
  5. The D3 table holds row by row.
  6. A partner fault makes the newest question NOT CHECKED: no unscoped GET and no newest-partner GET.
  7. Offline:
     - no partner dump gives NOT CHECKED;
     - a shuffled dump gives the same newest version;
     - non-plain versions are excluded and counted.
  8. The token appears on no output path.
- **Tests:**
  - `curl_stub` serves unscoped queries from the union of the responses, sorted descending, with an `unscoped=`
    override. It fails if partner is ever asked an unscoped query.
  - `registries_queried` gains a `<newest>` marker.
  - All call-count and order assertions are updated.
  - A request-shape test pins `NEWEST_QUERY`.
  - The hostile-body set is extended to the new fetches.
- **As built, and where it diverged:**
  - **Clock read:** the upload clock is read on every non-skip run, before the partner GET, so a broken stamp
    surfaces on every run, not only on the run that needs it.
  - **Declared floor:** applies only when the declared version is complete in both formats.
  - **Page edge:** taken over every row, other packages included, because the sort is global. The full page is
    `len >= PAGE_SIZE`, since a server that ignored `page_size` is no more trustworthy at its cut.
  - **New code** uses `SAFE_VERSION.fullmatch`. With `$`, `.match` lets a trailing newline through.
  - **`_parse_upload_stamp`** takes `object` and refuses non-strings itself. It accepts `Z` or `±HH:MM`. It
    refuses an impossible date without chaining the `ValueError`, whose message would quote the value.
  - **Git-clock fault:** the newest answer has already been computed, so it is printed, and the exit follows D3
    with the declared question at 2 (`_with_newest(2, …)`). When newest is the declared version, the line says the
    declared question was not answered rather than "answered above". Neither appears in the plan.
  - **Offline:** a dump without `uploaded_at` is refused, naming the file. Both offline flags' help text says the
    field is needed.
- **Status:** DONE

## Phase 2: reporting a newest-version lag
- **Risk:** complex. It writes issues and restructures the issue listing.
- **Delivers:**
  - `report_drift` and `report_clean` take a pre-fetched `issues`.
  - A newest drift files, comments and reopens under `PARTNER_DRIFT_TITLE.format(V)` with the newest lede.
  - A newest clean posts the "can be closed" notice only when the declared question reached GitHub.
  - Suppression is per version.
  - The heartbeat fires if and only if the run read GitHub.
- **Files:** the same two.
- **Acceptance:**
  1. A suppressed declared drift plus a newest lag gives: one list, one create (partner title, body naming V and D
     and State P), the heartbeat, exit 1.
  2. An existing open partner issue for V, filed by the declared question: no write.
  3. Closed and labelled gives a warning and exit 0. Closed and unlabelled gives a comment, then a reopen.
  4. A declared drift plus a newest drift gives one list and two creates.
  5. Declared in grace plus newest clean: zero gh calls. Declared in grace plus newest drift: list, create,
     heartbeat.
  6. Exactly one listing in every combination.
  7. A gh outage gives exit 2, with both verdicts printed first.
  8. No token appears in gh argv, and the gh verbs are unchanged.
- **Tests:** one per item. Mutation-check the single listing, the heartbeat condition and the close-notice guard.
- **As built, and where it diverged:**
  - *The listing is lazy and cached.* `main` holds a `listing()` getter that fetches on the first
    question to reach GitHub and caches the result, a failure included, so a second question
    cannot retry it and list twice. Lazy rather than up-front because of the newest clean's close
    notice: it may read a listing the declared question fetched and must never cause one. With an
    up-front fetch the `declared_reaches` guard was redundant, so a mutant dropping it could not be
    killed; with the getter, dropping it is an observable extra read.
  - *The git-clock fault path files nothing*, a newest drift included. The checkout cannot be read
    (the newest issue's own tag row needs it), and no write leaves a run whose instrument is
    broken. The newest drift is printed and the exit carries it (1); the next healthy run files it.
  - *Every partner issue body gains a "found by" row*, the declared-version check or the
    newest-version check (D4). This is a wording change for issues and comments written from now
    on; existing bodies are never edited.
  - *The heartbeat is "only on a run that read GitHub", not "iff".* A `gh` failure on a path with
    a finding to deliver (either question's drift) returns 2 from the reporting handler before the
    heartbeat, as the declared drift path always has. Only a failed listing wanted solely by a
    clean declared question is softened, and that run still reaches the heartbeat.
  - *A newest drift beside a gh outage exits 2*, the rule a declared drift has followed since #203:
    an undelivered finding is infrastructure, and both verdicts are printed before reporting. The
    clean path's outage warning is reworded when a newest drift is pending, so it no longer says
    "only the advisory notice is missing" on a run about to exit 2.
  - Added beyond the plan: the newest issue's tag row is read from git for V, and its
    `release-outcome` cross-link is V's; an open one only for D is not linked.
- **Status:** DONE

## Phase 3: docs, workflow comments, assumptions
- **Risk:** simple.
- **Delivers:**
  - **Docstring:** the two-repositories section and the Usage/Exit section, plus the `SOFT_GRACE_MINUTES` comment
    (upload clock; `registry-smoke` has no timeout).
  - **Workflow:** comments only, with the parsed YAML equal before and after.
  - **README:** one sentence.
  - **ASSUMPTIONS:** the "declared version only" entry is CHANGED, the 0.40.0 example is corrected, and new entries
    cover the sort, the clock, the shared title and the residual.
  - **PROGRESS:** a new section.
- **Acceptance:**
  - parsed YAML equal;
  - workflow tests pass;
  - `pytest scripts/` green;
  - `ruff check` clean.
- **Status:** TODO
