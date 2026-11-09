# Changelog

All notable changes to Peregrine are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adopts [Conventional Commits](https://www.conventionalcommits.org/) for
release automation.

> **Release-ladder reconciliation (2026-11-09).** The headings below used to
> follow the design-doc milestone stream (0.7.0 → 1.2.0 for M6 → M9 v1), but
> the published tags compressed that stream: everything through the M9 v1
> engine shipped squashed in **v0.2.0**; the M9 GA tiers then shipped as
> **v0.3.0** (the per-symbol propagation planner), **v0.4.0** (the
> segment-relayout tier), **v0.5.0** (the GA hardening pass) and **v0.6.0**
> (tier 2c, the resolve's record-side wiring, the resident fusion wire rung
> and the audited fusion rung). The prose is unchanged; only the section
> structure now matches the published tags (v0.2.0–v0.7.0; Cargo.toml
> carries 0.7.0).

## [Unreleased]

## [0.7.0] - 2026-11-09

### Features

- **daemon/driver/emit:** M9 output-residency rung (wire v5) — the §7.2
  buffer-residency work, the last deferred fusion item. The session stores
  every served image as resident output state (a content-addressed blob
  under the same ceiling and LRU as every other blob), so the warm cycle's
  previous output stops re-crossing the wire (the `BLOB` negotiation finds
  it; eviction is harmless — the client re-uploads). A tiles-asking client
  (the v5 request flag, set by `LinkJob::build_incremental`) receives a
  patched relink as the changed 16 KiB-tile stream
  (`pgr_emit::incremental::TilePatch` — `diff_tiles`, `apply_tiles`, the
  bytes-level twin of the file patch) plus the patched image's content
  hash; an untouched relink ships an empty stream and rewrites nothing.
  The client replays the stream against its local previous output and
  hash-verifies the result before the atomic write; a diverged replay is
  refused with the miette-rendered `TileReplayRefusal` (help text, not
  just a verdict) and stands down to the in-process relink. The daemon
  still never touches the filesystem — residency is state, never a write
  path — and `LinkOutcome` carries the transport (`Transport::Full` /
  `Transport::Tiles`) that the CLI prints and the benches record. tracing
  spans ride the new seams (`diff_tiles`, `apply_tiles`,
  `resident_tile_replay`, the residency store).

- **daemon/driver:** M9 GA rung 2 — the daemon serves the
  `-incremental-verify` audit (wire v4; the audited fusion rung, the last
  cheap rung before the §7.2 buffer-residency work). The request's
  `audit` flag asks the session to run the §7.3 gate's bytes-level twin
  on the patched relink: byte-identity against the reference emit (the
  full fused emit of the same plan) plus the strict verifier with the
  deliberate-unsigned carve-out, verdict on the wire. The audit lives in
  the engine (`pgr_emit::incremental::audit` — `audit_patch`,
  `audit_image`, the miette-rendered `AuditRefusal`), shared by the
  driver's in-process gate and the session's, so both paths gate with one
  implementation; a divergence is healed in memory from the reference
  emit (re-recorded, outcome adjusted) before the verdict crosses, and
  the client refuses to write a failing verdict — §7.2 crash-safety
  unchanged. The driver routes `-resident -incremental
  -incremental-verify` through the daemon first (standing down to the
  in-process audited relink without one), `LinkOutcome` carries the
  audit's summary, and the refusal ships with help text instead of the
  old `Tbd` shoehorn (a `.tbd`-parse error variant no longer carries
  verifier verdicts)

### Tests

- `pgr-emit/tests/incremental.rs` (2 new): the tile stream's gates — the
  lossless replay over every transport shape (interior edit, grow, the
  shrink rung's truncation, untouched) and the content-hash replay gate
  (a tampered tile is named, never shipped)
- `pgr-daemon` session gates (4 new): served images become resident
  output (cold and patched), the tiles relink serves the changed-tile
  stream (a fraction of the image, replaying losslessly), the untouched
  relink ships an empty stream, and a flag-less request keeps the v4
  shape; the memory-ceiling gate now replays the client's re-upload after
  the served image's residency evicts (the designed loop)
- `pgr-driver/tests/m9_resident_fusion.rs` (1 new): the residency cycle
  end to end — the cold link's image becomes the session's state, the
  patched relink rides `Transport::Tiles` (a fraction of the file size),
  the output stays byte-identical to the one-shot cycle, and the
  untouched relink rewrites nothing
- `pgr-emit/tests/incremental.rs` (3 new): the audit twin's gates — the
  audited tier-1 loop (identity holds, a flipped byte breaks it), the
  strict pass with the unsigned carve-out (a tampered page is named, an
  unsigned link audits clean besides its deliberate shape), and the
  refusal's rendered help text
- `pgr-daemon` session gates (2 new): the audited relink reports the
  verdict (and its image IS the reference emit), a full link and an
  untouched relink serve no audit; protocol v4 round-trips the audited
  request
- `pgr-driver/tests/m9_resident_fusion.rs` (2 new, 1 rewritten): the
  audit is served by the daemon (verdict on the outcome, bytes still
  match the audited one-shot cycle) and the audited relink stands down to
  the in-process audit without a daemon; the old "stays in-process" gate
  rewritten for the rung

### Performance

- `pgr-emit/wire-tiles` bench (new): the rung's CPU price — `diff_tiles`
  and the client-side `apply_tiles` replay over an 8 MiB image (one-tile
  edit and the untouched scan), recorded in docs/BENCHMARKS.md next to
  the wire bytes the rung saves
- `pgr-driver/resident-fusion` bench: the warm relink now asserts the
  tile-stream transport (the wire's honest record) and re-recorded on
  the rung — the previous output's upload and the patched image's
  download are gone from the loop
- `pgr-driver/resident-fusion-audited` bench (new):
  `fusion_relink_audited_64_objects` — the audited warm relink against
  the unaudited fusion group; the overhead is the rung's honest price
  (the reference emit plus the strict pass per audited relink), recorded
  in docs/BENCHMARKS.md

### Fixed

- **core:** `build_func_starts` emitted **absolute** offsets into
  `LC_FUNCTION_STARTS`'s **delta**-encoded ULEB128 stream — semantically
  wrong since M0 and invisible until the audited fusion rung's
  symbol-heavy bench corpus (64 objects × 2 048 function symbols)
  overflowed the decoder's accumulator past `__TEXT` (the strict gate's
  `function start ... beyond __TEXT`). Small corpora masked it because
  the accumulated sum stayed under vmsize. Now delta-encoded the way the
  verifier and dyld decode it, with a regression gate in
  `m9_resident_fusion.rs` (a symbol-heavy corpus full-links and relinks
  strict-clean through the audit)

### Build

- workspace gains `tracing` (spans on the audit/relink seams — inert
  until a subscriber installs; `pgr`/`pgrd` install one under
  `PGR_INCREMENTAL_DEBUG`/`PGR_RESIDENT_DEBUG`) and `miette` (the
  refusal's help text)

### Docs

- the release ladder reconciled with the published tags (the note below),
  the README badge and status version refreshed, docs/TDD.md's status row
  carried to the audited fusion rung, docs/COMPAT.md's deferred list
  narrowed to the buffer-residency rung, and a consumer example for the
  verifier's library surface (`pgr-verify/examples/verify_report.rs`) and
  the audited session (`pgr-daemon/examples/fusion_audit_session.rs`)

## [0.6.0] - 2026-11-09

### Features

- **daemon/driver:** M9 GA — the resident fusion wire rung (architecture
  doc §7.3 + §7.2; the last open GA scope's first rung). The daemon wire
  (protocol v3) carries the incremental halves: the request brings the
  previous link record and the previous output's content hash (bytes ride
  the `BLOB` exchange), the reply brings the refreshed record plus the
  patch outcome. The session serves the §7.3 ladder in memory — integrity
  gate on the transferred output, the anchored relink config derived from
  the record (slack anchors, stable imports, signature boundary,
  resolve-reuse seed), the pipeline warm over the session's POIs, the
  patch plan, the in-memory patch through the engine's new bytes-level
  twin (`apply_patch_bytes`, gated byte-identical to the file path) — and
  any refusal falls back inside the daemon to its clean full link, which
  captures whenever asked. The driver routes `-resident -incremental`
  through the daemon first (standing down to the in-process relink, then
  the full link — every rung always available), keeps `-incremental-verify`
  on the audited in-process path, and stores the daemon's renewed record,
  so the incremental cycle survives daemon fallbacks instead of silently
  dead-looping on a stale sidecar. The daemon still holds no output state:
  the client writes the file (§7.2 crash-safety unchanged)

- **core:** M9 tier 2c — the incremental resolve over the propagation
  index (architecture doc §7.3 step 3, the GA rung the roadmap names
  before the resident fusion). The tier-2b planner scopes *bytes*; the
  new `pgr_core::resolve::ResolutionSnapshot` records the Pass-2 decision
  state — the complete candidate stream (name-grouped for the replay) and
  the winners keyed by their digest-vouched `(file, symbol)` positions —
  and `pgr_core::resolve_reuse` plans the reuse: shape-guarded on the
  input file list and the dylib export surface (either moving refuses the
  plan and the relink resolves in full), seeded by the same section-digest
  diff the byte planner runs, copying every recorded winner the seeds
  cannot touch (no name-keyed join on the hot path) and replaying the
  full precedence rules over every name they can. The contract is
  equality with the full resolve — gated per relink shape and across a
  randomized edit walk in `tests/m9_resolve_reuse.rs`

- **driver:** `-incremental-verify`'s strict-verifier audit no longer
  counts the deliberate "arm64 images require an ad-hoc code signature"
  error against a deliberately unsigned link (`-no_adhoc`): the audit
  gates fixups, chains, segments and symtab at full strictness, and the
  missing-signature shape is the config's own choice, not a patch defect.
  Signed links keep the signature gate unchanged



### Tests

- `pgr-core/tests/m9_resolve_reuse.rs` (new): the tier-2c equality gates
  — unchanged relinks reuse every winner, body edits re-decide only the
  seeded sections' names, a weak/strong rank flip retargets the reused
  winner, a duplicate strong definition lands the same `LinkError::Symbol`
  both paths reach, moved file lists and dylib export sets refuse with
  `ReuseFallback`, and a seeded xorshift64* walk (30 steps) keeps the
  reused resolution indistinguishable from the full one

### Performance

- `pgr-core/benches/resolve.rs` (new): `resolve_pass2` pits the full
  `Resolution::install` against `plan_reuse` + `install_reused` (the plan
  hoisted out of the timed loop — the digest diff is plan-side, computed
  once per relink beside the byte planner's). Recorded honestly on the
  dev sandbox: break-even past ~32 inputs, −21% at 64 files × 49 externals
  (352 µs → 278 µs median), +19% at 16 files where the plan-read machinery
  still costs more than the full walk's get/decision work

## [0.5.0] - 2026-11-08

### Features

- **emit:** M9 GA hardening — the relayout tier's **shrink rung** (the
  tier-2 trigger's mirror; architecture doc §7.3 "the fallback must
  always be available" cuts both ways). An unsigned relink (`-no_adhoc`)
  has no signature boundary to anchor the `__LINKEDIT` tail, so a
  symtab/string-pool shrink — the local-symbol block removed — moves the
  chunk-stream end down and the image shrinks with it. The planner now
  admits that shape as a relayout patch plan when the content skeleton is
  frozen end to end (any content-section resize beside a shrinking image
  stays structural and falls back): the clone is truncated to the new
  size, the moved chunk tail is re-emitted from the span diff, and the
  byte-identity contract (patched == full fused emit of the same plan) is
  unchanged. A signed relink never shrinks — the sig anchor pins the
  boundary — so this rung serves exactly the corpus the signed tiers
  could not

### Tests

- `pgr-emit/tests/incremental.rs` (1 new, 1 rewritten): the shrink-rung
  byte-identity gate (shrink patches through the relayout tier, the
  shrunk state is a relinkable baseline for a tier-1 body edit and a
  tier-2 regrow), and the M9 GA randomized-edit walk grows the symtab
  churn dimension (grow past / shrink below the boundary reservation) and
  a `PGR_RANDOMIZED_STEPS` profile knob — 2000 sequences × 5 steps is the
  roadmap's 10⁴-step GA bar

- `pgr-driver/tests/m9_randomized.rs` (new): the GA randomized
  edit-sequence gate end to end — a seeded xorshift64* walk over body
  flips, growth within slack, symtab churn (the shrink rung's side) and
  no-ops, driving the real `-incremental -incremental-verify` loop over
  files with the record sidecar in the mix; every step must land on a
  patch that reuses most tiles, an untouched no-op, or an honest
  fallback that re-records, and every output must verify clean

- `pgr-driver/tests/m9_incremental.rs` (1 new): the shrink rung end to
  end — the unsigned shrinking relink patches through the relayout tier,
  the image shrinks, the output verifies, and the shrunk baseline still
  relinks



### Performance

- `pgr-driver/incremental_shrink` bench: new `linkedit_shrink_relink_8mib`
  group (an unsigned 8 MiB corpus alternating a 512-local-symbol object
  with the pristine one — shrink and regrow through the tail) with a
  per-direction bytes-written accounting pass


## [0.4.0] - 2026-11-08

### Performance

- **emit:** M9 tier 2 — the **segment-relayout patch tier** executes (the
  §7.3 ladder's middle rung; architecture doc §10.4 row M9 GA). A skeleton
  shift no longer falls straight to the clean link: a section that
  overflows its slack anchor within the ladder's bound (growth beyond the
  previous pad ≤ the policy max — `SlackPolicy::fits` says
  `SegmentRelayout` for every resized section) holds its base while
  everything behind it shifts, and an outgrown `__LINKEDIT` reservation
  moves the signature boundary with it. The planner admits the shifted
  skeleton as a relayout patch plan (`pgr_emit::incremental::RelayoutDelta`,
  `PatchPlan::relayout`): the previous output is cloned and resized, the
  moved suffix's tiles are re-emitted from the new plan, page 0 is rebuilt
  with the derived `LC_UUID`, and the `CodeDirectory` is re-signed from the
  merged hash table at the moved boundary — the byte-identity contract
  (patched == full fused emit of the same plan) is unchanged and gated

- **emit:** the record's **v4 output-section content digest table**
  (`LinkRecord::content_digests`): SHA-256 over each output section's
  copy-run bytes (placement-invariant concatenation), computed in parallel
  at record time and copy-or-rehash per plan (only run-touched sections
  hash). The relayout tier's **shift-exemption** compares a moved section's
  recorded digest against the new plan's: a byte-identical move is
  explained by the skeleton shift alone — its derived bytes (relocations,
  chain words) are re-emitted and re-proven — while genuine content churn
  inside the moved suffix must still sit inside the propagation scope (the
  tier-2b gate, with old-side diff ranges translated by the section's
  shift). The moved-away `CodeDirectory` span joins the diff so the patch
  overwrites it; oversized growth (beyond the policy max) still escalates
  to the clean link, and the §7.3 economics gate still declines
  whole-image patches

- **driver:** `-incremental` reports the patched state's file size (the
  relayout tier grows the image) and the relayout path is exercised
  end-to-end with `-incremental-verify`



### Tests

- `pgr-emit/tests/incremental.rs` (6 new): the tier-2 byte-identity loop
  over an overflowing corpus (exec, unsigned, dylib), the `__LINKEDIT`
  overflow trigger, the ladder's honest top rung (growth beyond the policy
  max still falls back), and the relayout state as a fixpoint

- `pgr-driver/tests/m9_incremental.rs` (3 new, 1 rewritten): the e2e
  relink patches through the relayout tier and recovers incrementally,
  oversized growth still falls back and re-records, and
  `-incremental-verify` audits the relayout patch; the old
  "skeleton move falls back" gate now pins the tier-2 patch



### Performance

- `pgr-driver/incremental` bench: new `segment_relayout_relink_8mib` group
  (a monotone +64 KiB growth ladder — anchors absorb alternating
  same-size cycles, so the bench climbs) with a per-step bytes-written
  accounting pass; the tier-1 accounting loop's input-index bug fixed
  (it swapped the extern-provider dylib out of input 0, which would have
  broken the link if run). Sandbox numbers (2-core-class container, ext4 —
  no reflink, so the clone is a full copy): each +64 KiB growth step
  patches **1.2 MiB of 9.4 MiB image bytes (13%)** where the full relink
  writes every byte; the tier-2 relink mean (34.2 ms, 8 tier-2 : 1 tier-1
  mix) is a wash against the tier-1 mean (32.2 ms) and the full relink
  (17.4 ms) on this filesystem — the same ext4-clone verdict the tier-1
  bench recorded, with the bytes-written gate met; the record-time
  content-digest hash adds no measurable full-link cost (parallel; full
  relink 17.4 ms vs 17.4 ms baseline)



## [0.3.0] - 2026-11-08

### Features

- **core:** M9 tier 2b — the per-symbol change-propagation planner
  (architecture doc §7.3 step 3). The record's section-digest table (v3:
  content + symbol records) is diffed against the relink's parse, and the
  planner's **propagation gate** requires every changed content span to
  sit inside `pgr_core::propagate::predict`'s scope — the seeds'
  output-section extents plus the reverse-index closure of their
  dependents — falling back to the full link when a span diff escapes the
  scope (the stale-record shape, or literal-pool dedup churn the scope
  does not model). The M8 reverse reference index and the
  insertion-stable import table anchor the scope's input side

## [0.2.0] - 2026-11-08

The design-doc milestone stream (M0–M9 v1) shipped squashed in this
release: the sections below keep their original prose, grouped under the
design-ladder versions they were written against. Everything from the M0
format layer through the M9 in-place incremental relink engine is in
v0.2.0.

#### Shipped inside v0.2.0 — design-ladder 1.2.0 (2026-11-08)

#### Features

- **emit:** M9 in-place incremental relink engine (architecture doc §10.4
  row M9, §7.3 Stage C tier 1) — the new `pgr-emit::incremental` module
  records a full link's state (`LinkRecord`: the emit plan's byte-producing
  spans with per-tile-piece SHA-256 digests, the frozen skeleton, the
  signature's final page-hash table) into a versioned, checksum-framed,
  pointer-free sidecar; plans the next relink by diffing the new plan's
  spans against the record (dirty 16 KiB tiles + the §7.3 skeleton gate);
  and patches the output in place — clone the previous image (APFS
  copy-on-write via `fclonefileat` on macOS, `copy_file_range` on Linux),
  `pwrite` only the dirty tiles, rebuild page 0 with the derived `LC_UUID`,
  re-sign from the merged hash table (recorded hashes for clean pages,
  recomputed for dirty ones), rename. **Contract: the patched file is
  byte-identical to the full fused emit of the same plan** — gated in
  tests, auditable per link
- **emit:** the planner's fallback ladder — any skeleton move (section or
  segment placement, signature boundary, file size, identity), output
  change (missing, resized, or failed the sampled integrity gate), or
  record problem (missing, corrupt, foreign format) falls back to the full
  link, which is always available and always correct; when every content
  tile is dirty the planner declines on economics; §7.3 ladder tiers are
  classified through `SlackPolicy::fits` for the diagnostics
- **core:** M9 slack anchors (`LinkConfig::slack_anchor` +
  `SlackPolicy::pad_section_anchored`) — the previous link's reserved
  section sizes are a layout input, so a changed section keeps its on-disk
  place while its content fits (the in-place patch tier's precondition);
  an empty anchor list reproduces M8-c exactly (gated)
- **driver:** `-incremental` / `-no_incremental` / `-incremental-verify` —
  the relink loop over real files with the record sidecar
  (`<output>.pgr-inc`, `PGR_INCREMENTAL_RECORD`), silent fallbacks
  (`PGR_INCREMENTAL_DEBUG=1` prints reasons), and the audit gate
  (byte-identity against the full emit, then a strict `pgr-verify` pass on
  the patched bytes; a divergence never ships). `-incremental` implies
  slack layout for the whole link cycle so the cold full link reserves
  exactly what its record describes
- **daemon:** wire protocol v2 — the config carries the M9 slack anchors
  (a version mismatch stays a hard proto error; clients fall back to the
  one-shot link)

#### Tests

- `pgr-core/tests/m9_foundations.rs` (4): anchored relink stability,
  overflow to the natural pad, anchor determinism, M8-c reproduction
- `pgr-emit/tests/incremental.rs` (9) + `pgr-emit::incremental` unit tests
  (16): the byte-identity contract across executables, dylibs, no-slack
  and unsigned corpora; growth within slack patches in place (LINKEDIT
  churn included — the skeleton freezes the segment extent, not the chunk
  offsets); no-op relinks; symbol-count and ladder fallbacks; the
  integrity gate's honest sampling; codec roundtrip and corruption
  tolerance (never a panic)
- `pgr-driver/tests/m9_incremental.rs` (11): the end-to-end loop — record,
  patch, no-op, every fallback path, verifier-clean patched output,
  `-incremental-verify`, option surface, error propagation

#### Performance

- `pgr-driver/incremental` bench: full relink 16.4 ms vs incremental
  17.6 ms on the 8.53 MiB sandbox corpus (a wash — ext4 has no reflink, so
  the clone degrades to a full copy; recorded as-is), untouched relink
  13.3 ms, and the §7.3 bytes-written gate met: **1.2% of the image bytes
  per one-function edit** (105 KB: two dirty tiles + the CodeDirectory)


#### Shipped inside v0.2.0 — design-ladder 1.1.0 (2026-11-08)

#### Features

- **daemon:** M8 resident link server — the new `pgr-daemon` crate ships
  `pgrd` (unix-domain socket, idle timeout, `--shutdown`) and the client
  `pgr -resident` uses. The session keeps the Pass 1 product of every
  direct input (POI frames keyed by the Stage A versioned content key),
  the input bytes (content-hash keyed, transferred once), and the fused
  emit buffer (reused across links — the §10.4 M8 "page-fault cost
  eliminated (buffer reuse)" groundwork). Blob negotiation sends only
  bytes the daemon does not hold; `-resident_socket <path>` /
  `PGR_DAEMON_SOCK` pick the socket; `pgr` starts `pgrd` on demand (the
  binary beside it) and **falls back to the one-shot link on any failure**
  (§7.2 "optional and transparent"; `PGR_RESIDENT_DEBUG=1` prints the
  fallback reason)
- **daemon:** M8 correctness gates — resident output byte-identical to the
  one-shot link in deterministic mode (executable/dylib/archive corpora,
  cold and warm, gated end-to-end); daemon SIGKILL/restart never changes a
  byte (the daemon holds no output state; clients write via the Pass 5
  atomic path); concurrent clients serialize with identical results; link
  errors surface through the fallback with the one-shot message text
- **core:** M8 `link_from_objects` — Passes 1b–3 over already-parsed
  direct inputs (the resident path's entry point); the S7 archive pull
  fixpoint, interning, resolution, liveness/ICF and layout run exactly as
  in `link_cached`, and the pre-parsed layout is gated identical;
  `-u` enforcement shared via the new `check_load_symbols` (driver and
  daemon run the same gate)
- **core:** M8-a reverse reference index (`pgr_core::revindex`) — symbol →
  referencing `(file, section, offset)` sites over the parsed inputs,
  recorded at full links (§7.3 step 3); dead-atom references drop when the
  M5 live set is active; sites total-ordered and deduplicated (the index
  is a pure function of the inputs)
- **core:** M8-b insertion-stable import table (`pgr_core::stable_imports`)
  — canonical ordinals on a clean build ((name, ordinal, addend, weak)
  order — address-independent, D7's property made load-bearing); growth
  keeps every existing ordinal and appends new imports canonically (§7.3
  step 5, the M9 relink ordinal-reuse foundation); the table drops
  straight into the `pgr_format` import/name-pool shape
- **core:** M8-c slack-aware layout with fallback (`pgr_core::slack`) —
  `LinkConfig::layout_slack` reserves per-section growth room (10% text /
  5% data, clamped, aligned; synthetic `__got`/`__stubs`/`__chain_starts`
  stay contract-exact) so a changed atom usually fits where it was;
  default off — v1.0 packing is byte-unchanged, and slack padding is a
  pure function of size (deterministic both ways); the §7.3 fallback
  ladder (in-place → segment re-layout → clean link) is a pure decision
  function
- **emit:** `build_image_fused_into` — the fused tile emit into a
  caller-owned buffer (cleared + resized, capacity retained), the reuse
  path the resident session's scratch buffer rides on

#### Performance

- **bench:** `pgr-driver/resident` — the warm-relink path recorded
  honestly: one-shot 224.3 ms vs resident-warm 260.3 ms on the
  parse-heavy 64×2048×2 KiB corpus (POI hits 64/64, no input re-transfer,
  buffer reuse). The finding replays M6's: the corpus is Pass 2/3-bound
  and the POI decode measures ≈ a fresh parse on this sandbox, so the
  skipped Pass 1 does not yet cover manifest+wire overhead; the §10.4 M8
  performance gates (≥ 5× ld-prime) stay hardware-gated. Full phase
  breakdown in docs/BENCHMARKS.md
- **bench:** client manifest hashing runs on the shared compute pool (one
  SHA-256 per input, parallelized)

#### Tests

- **core:** `m8_foundations.rs` — reverse-index gates (site lists,
  dead-atom filtering under the live set, total order, schedule
  independence), import-table canonical order + ordinal stability across
  growth rounds + key shape (ordinal/addend/weak distinguish), slack
  padding math + fallback ladder + layout gates (pieces never move,
  synthetics exact, deterministic both ways), pre-parsed-layout equality,
  fixup-word equality, archive pull through the preparsed path, shared
  `-u` gate
- **daemon:** protocol round-trips (rich/default configs, version
  mismatch, truncation/trailing-byte rejection, frame bounds), session
  gates (cold-vs-warm byte identity incl. one-shot parity, changed-input
  POI reuse, missing-blob and hash-mismatch refusal, LRU memory ceiling,
  scratch reuse, archive inputs), `pgrd_binary.rs` — strict-verifier-clean
  resident output, SIGKILL restart identity, error survival, idle exit
- **driver:** `m8_resident.rs` — resident-vs-one-shot byte identity over
  executable/dylib/archive corpora (cold + warm), POI-hit counters across
  the wire, fallback transparency (absent daemon), restart transparency,
  4-way concurrent clients, `-u` parity through the fallback
- **emit:** the fused `_into` variant is byte-identical to the allocating
  path (reused by the M4 gates)


#### Shipped inside v0.2.0 — design-ladder 1.0.0 (2026-11-07)

#### Features
- **core:** M7 versioned cache format v2 — `CACHE_FORMAT_VERSION = 2` plus a
  parser revision recorded in every POI/frozen-`.tbd` frame *and* bound into
  the cache key (`sha256(bytes ‖ flags ‖ format ‖ parser)` — stale entries
  are unreachable, not merely unread); entries record the parse-affecting
  flag and decode rejects mismatches; the directory carries a
  `PGR_CACHE_FORMAT` marker and self-heals on foreign or legacy content
  (pgr-shaped files reclaimed, foreign files untouched); v1 frames are
  silently missed (determinism-gated cached-vs-uncached equality re-asserted
  on v2)
- **core:** M7 size-bounded caches — oldest-mtime (LRU) eviction with
  recency refresh on hits; the just-stored entry is never evicted; store +
  evict serialized per cache so Pass 1's concurrent stores cannot wipe the
  directory (regression-gated by a 30-iteration parallel-store stress test)
- **driver:** M7 `-cache_max <bytes>` / `PGR_CACHE_MAX` (default 2 GiB,
  0 = unbounded)
- **driver:** M7 build-system surface — `@response-file` expansion (nested,
  depth-bounded; ld64 tokenization with `#` comments, quote grouping and
  backslash escapes; **opportunistic** expansion — a non-existent `@path`
  passes through, keeping `-install_name @rpath/libfoo.dylib` intact)
- **driver:** M7 `-syslibroot <dir>` (repeatable) with the ld64 pairing
  rule: one root searches only prefixed variants of every `-L`/`-F` dir and
  the defaults; two or more roots search the union including the original
  path (`effective_lib_dirs`/`effective_framework_dirs`)
- **driver:** M7 accepted no-ops with fixtures — `-demangle`/`-no_demangle`
  /`-no_deduplicate` (arm64 defaults already match) and
  `-object_path_lto <path>` (value consumed; LTO inputs stay diagnosed)
- **driver:** M7 compatibility suite (`m7_compat.rs`) — the agreed list as
  38 fixture-backed end-to-end cases (load commands, image contracts,
  driver flags & search, M7 surface, determinism, diagnostics), each strict
  verifier-clean, with the roadmap's **≥ 98% pass** gate pinned by its own
  test (currently **38/38 = 100%**)
- **fuzz:** M7 fuzzing at scale — new targets `dyld_info_streams` (classic
  rebase/bind opcode decoders) and `cache_entries` (v2 cache decoders),
  valid framed/streamed seeds in `emit_corpus`, and the six-target nightly
  matrix
- **fixtures:** `emit_link_inputs` example — the deterministic
  hello/greet/tbd inputs the runtime-validation job links
- **docs:** `docs/MIGRATION.md` — the ld64 → pgr migration guide (flag
  mapping, no-ops, cache semantics, determinism contract, exit codes)

#### Bug Fixes
- **format:** `parse_imports` bounds `imports_count` by the payload before
  pre-allocation (a mutated/truncated image once drove `count × 16` to
  68 GiB and aborted; typed `Overrun` now; unknown formats rejected up
  front) and `read_u32_slice` bounds its count — M7 fuzzing finds
- **core:** cache unframe uses `checked_add` for the framed length (the
  `cache_entries` fuzzer wrapped `HEADER_LEN + len` on a hostile header);
  object relocation decode caps `with_capacity(nreloc)` by the file's
  bytes (the `link_object` fuzzer drove an 8 GiB allocation)
- **verify:** hostile-header arithmetic overflow battery — `nsections`
  accumulation and segment/branch/chain/pair address computations all
  saturate (`structural`, `dyld_info`, `pair`, `chain_starts`,
  `branch_range`); each crash has a deterministic regression test
- **fuzz:** the `link_object` target links again (the M5 `link()`
  signature change had broken its compile)

#### Performance
- **bench:** `pgr-driver/cache_evict` — the LRU bound costs only on cold
  stores: 9.73 ms bounded vs 9.12 ms unbounded (+6.7%) on the 4-object
  parse-heavy corpus; warm (all-hit) links are unchanged — no stores, no
  scans
- **bench:** every M4–M6 gate re-measured with M7 in the pipeline and
  holding: large link 175.6 ms, dead-strip 136.4 ms (1.93× vs off), ICF
  +14.8% (gate ≤ 25%), fused emit 1.38× the reference, warm cache 173.7 ms
  (was 172.8 — the v2 key/marker/touch cost nothing measurable), frozen
  `.tbd` 19.8 µs, trie 10⁵ exports 27.9 ms, archive parse 12.2 GiB/s
  (docs/BENCHMARKS.md records the full table; the M5 row's "~118 µs" unit
  slip is corrected there)

#### Tests
- **core:** v2 frame/key/flag gates, marker self-heal (foreign + legacy
  dirs), LRU eviction + recency, hostile framed-length miss, parallel-store
  stress (30 bounded links)
- **driver:** response-file e2e (expansion order-preserving, byte-identical
  to the plain link), syslibroot single-root prefix-only + two-root union,
  `-cache_max` bound e2e, frozen-`.tbd` v2 round-trip, the 38-case compat
  suite
- **format:** bounded imports count / unknown format, hostile framed
  lengths
- **verify:** saturated arithmetic on mutated headers (chain walks, branch
  ranges, segment contracts)


#### Shipped inside v0.2.0 — design-ladder 0.7.0 (2026-11-07)

#### Features
- **core:** M6 branch thunks/veneers — out-of-range `B`/`BL` sites (beyond
  the ±128 MiB arm64 reach) get a 3-instruction veneer (`adrp x16/add
  x16/br x16`) inserted into the same output section right after the
  site's piece, inside the layout fixed point; the veneer reaches its
  target through ADRP's ±4 GiB window so no chaining is ever required;
  giant-atom sites (a single atom larger than the branch range) fail with
  ld64-style diagnostics; determinism-gated (double-link layout equality)
- **verify:** M6 branch-range checker — every `B`/`BL` in the executable
  sections is decoded and its target must land back inside `__TEXT`,
  4-byte aligned (`Code::BranchRange`); the architecture doc's "thunk
  placement verified by a branch-range checker in `pgr-verify`" gate
- **format:** M6 classic `LC_DYLD_INFO` opcode streams — rebase/bind
  encoders and decoders (ULEB/SLEB, trailing-flags symbols, special
  ordinals), round-trip and malformed-input gated, never panics
- **core:** M6 `LC_DYLD_INFO_ONLY` legacy fallback — chained fixups are a
  macOS ≥ 12 format (TDD §3.6 invariant 3), so `minos < 12.0.0` and
  `-no_fixup_chains` emit classic rebase/bind streams instead of the
  chained payload (slot bytes stay zero, no `__chain_starts`); the import
  metadata (symtab/indirect construction) is built identically to the
  chained path via the shared `build_import_table`
- **emit:** the classic rebase/bind streams land in `__LINKEDIT` (both
  the reference and fused tile emitters write them identically)
- **verify:** classic dyld-info stream walk — both streams decoded the
  way dyld does; slot bounds/alignment, bind ordinals vs the
  `LC_LOAD_DYLIB` list, special ordinals only in flat images, non-empty
  symbol names (`Code::DyldInfoStreams`)
- **core:** M6 ICF (identical code folding) — `-icf=safe`/`-icf=all`/
  `-no_icf` (ld64 vocabulary, default none); Hopcroft-style color
  refinement over per-atom `(content, ordered relocation fingerprints)`
  signatures with byte hashing on the shared compute pool and
  deterministic first-occurrence class ids; `-icf=safe` never folds
  address-taken atoms, weak definitions never fold, section-relative
  targets never fold (unredirectable); folded aliases keep their symtab
  names at the canonical copy's address and output section; composes with
  `-dead_strip` and the D4 cstring merge
- **core:** M6 Stage A caches (architecture doc §7.1) — the POI (Parsed
  Object Image) cache stores everything Pass 1 produces pre-interning
  (sections with raw relocations, typed symbols, the name pool, D1 atom
  ranges) content-addressed by `sha256(input || flags)`; frozen `.tbd`
  caches the parsed stub; both are checksum-framed (`PGRPOI1`/`PGRFTBD1`),
  atomically written (unique temp + rename — the shared-temp race is
  regression-gated), and corruption/version tolerant (silent re-parse)
- **driver:** M6 flag surface — `-icf=`/`-icf <level>`/`-no_icf`,
  `-cache <dir>` / `PGR_CACHE_DIR` / `-no_cache`; cached vs uncached
  output byte-identical (the §7.1 gate); LTO bitcode inputs (raw
  `BC\xC0\xDE` and `0x0B17C0DE` wrapper) detected up front with a clear
  `-fno-lto` diagnostic instead of a deep Mach-O parse failure
- **core:** M6 Stage A plumbing — `link_cached` threads the POI cache
  through direct inputs and archive members alike (member keys hash the
  member bytes; `from_archive`/archive-name stay call-site properties)
- **fixtures:** `ObjectBuilder::set_subsections_via_symbols` (chained
  form) already exercised by the M5 tests; M6 corpora add ObjC/Swift
  metadata sections (`__objc_classrefs`, `__objc_selrefs`,
  `__swift5_types`) and `-icf` fold corpora

#### Performance
- **bench:** `pgr-driver/link_icf` — the "ICF ≤ 25% added wall" gate:
  17.29 ms fold-off vs 19.37 ms `-icf=safe` on the fully-foldable 32×512
  corpus (**+12.0%**, 16,383 atoms folded, ~192 KiB of duplicate text
  removed)
- **bench:** `pgr-driver/link_cache` — Stage A: cold 177.8 ms vs warm
  172.8 ms on the parse-heavy 64K-symbol corpus (−2.8% wall; the corpus
  is Pass 2/3-bound, so the POI cache's Pass 1 elimination is bounded by
  Pass 1's share — recorded honestly with the pass profile)
- **bench:** `pgr-driver/tbd` — the "`.tbd` startup cost < 1 ms" gate:
  frozen export-set decode **19.9 µs** vs 35.8 µs YAML text parse (1.8×,
  both ≪ 1 ms)
- **bench:** M4/M5 gates re-measured with M6 in the pipeline: large link
  175.7 ms (was 174–176), dead-strip 259.0/136.0 ms off/on (1.90×, was
  1.90×) — the veneer scan, fixup-command dispatch and fold-empty fast
  path cost nothing measurable

#### Tests
- **core:** veneer insertion on forward/backward overflow (one veneer per
  site, in-range final deltas, double-link determinism, no veneers when
  in range); ICF fold/keep/alias gates (identical fold, distinct targets
  stay, safe vs all address-taken split, dead-strip composition,
  parallel-vs-serial equality); POI round-trip, corruption battery, cache
  key stability, cached-vs-uncached layout equality, consecutive-hit
  equality (the shared-temp store race is regression-gated); frozen-`.tbd`
  round-trip; classic stream planning (slot order, ordinals, specials,
  addends) and segment-bound errors
- **format:** opcode encoders (ULEB/SLEB vs LLVM vectors), rebase/bind
  round-trips, `dyld_info_command` parse gates, truncated-stream battery
- **verify:** branch-range decode battery (B/BL shapes, register-branch
  shapes), in-range pass, out-of-range/misaligned/negative-target errors,
  truncated tails tolerated; classic stream slot/ordinal/name checks
- **driver:** `m6_thunks` (giant-text e2e), `m6_legacy` (minos 11 +
  `-no_fixup_chains` + rebase/bind stream contents + determinism + dylib
  bind names), `m6_icf` (CLI parse, fold e2e with strict verifier,
  `-icf=all` superset), `m6_cache` (byte-identity, corruption re-parse,
  frozen-`.tbd` dylib links, `-no_cache`), `m6_ecosystem` (LTO detection,
  ObjC/Swift pass-through + determinism)


#### Shipped inside v0.2.0 — design-ladder 0.6.0 (2026-11-06)

#### Features
- **format:** M5 `!<arch>` archive parser — Apple `__.SYMDEF`/`__.SYMDEF_64`
  and GNU `/` ranlib tables (32/64-bit entries), BSD `#1/<len>` and GNU `//`
  long-name tables, ranlib member-offset resolution (header offset first,
  data-offset fallback); total parser (typed errors, never panics), fuzz-
  and proptest-gated
- **core:** M5/S7 archive liveness — the pull fixpoint walks the ranlib
  index in command order and parses only the members that resolve an
  unresolved name (weak references never pull; `-u` names seed the loop;
  `-all_load`/`-force_load` short-circuit to eager); ranks 3/4
  (`ArchiveStrong`/`ArchiveWeak`) keep direct definitions winning without
  duplicate errors — ld64 semantics; pull order a pure function of the
  inputs (FileIds continue after direct inputs in pull order)
- **core:** D1 atomization — `MH_SUBSECTIONS_VIA_SYMBOLS` sections split at
  symbol boundaries (`N_ALT_ENTRY` merges into the preceding atom;
  `S_CSTRING_LITERALS` sections split at NUL terminators); deterministic
  per-section atom tables, borrowed throughout (no per-call clones)
- **core:** D12 `-dead_strip` — mark-sweep liveness over the D1 atoms
  (roots: entry, `-u` names, all extern defs for dylibs/bundles,
  `__mod_init_func`, `S_ATTR_NO_DEAD_STRIP`); dead atoms leave the layout,
  symtab and trie; edge graph built in one pass per section (relocations
  bucketed into atoms), liveness queries O(log atoms)
- **core:** D4 `__cstring` merging (ld64-default-on) — cross-input dedup of
  `S_CSTRING_LITERALS` via a hash-map pass over string atoms; the first
  live instance is canonical; symbol- and section-relative references remap
  to the single copy through the M5 containment tables; cooperates with
  dead-strip (unreferenced literals strip)
- **driver:** M5 flag surface — `.a` inputs (ranlib pre-parsed, members
  lazy), `.a` in `-l` search after dylib candidates, `-all_load`,
  `-force_load <archive>`, `-u` member pull, `-dead_strip`/
  `-no_dead_strip`, `-filelist <path>[,<dir>]`, `-framework`/`-F` (`.tbd`/
  dylib payloads), `-sectcreate <seg> <sect> <file>` (synthetic
  single-section object); stale M2/M3 force-load message replaced
- **fixtures:** `ArchiveBuilder` (deterministic libtool-style archives,
  name-sorted ranlib table from the member symtabs),
  `set_subsections_via_symbols`/`set_alt_entry`, section-relative reloc
  ctors (`unsigned_sect`, `page21_sect`, `pageoff12_sect`)
#### Performance
- **bench:** `pgr-format/parse_archive` — 11.9 GiB/s structural archive
  parse (64 members + ranlib index)
- **bench:** `pgr-driver/link_archive` — S7 decision recorded: lazy pull
  4.02 ms vs `-all_load` 49.06 ms on the 64-member corpus (12.2×; the
  adoption rule was ≥ 20%)
- **bench:** `pgr-driver/link_dead_strip` — 134 ms with `-dead_strip` vs
  255 ms without on the 50%-dead corpus (gate was ≤ 30% overhead; the first
  mark-sweep draft measured 911 ms and was closed by O(log atoms) liveness
  queries + one-pass-per-section edge bucketing + borrowed atom tables)
- **bench:** `pgr-driver/link_cstring` — 1.69 ms for the 16-object shared-
  pool corpus (deduped); M4 gates re-measured and holding (emit 1.39× the
  reference, full-pipeline parity within noise)
#### Tests
- **format:** archive round-trips (libtool/GNU/BSD shapes, `__.SYMDEF_64`),
  malformed-input battery, mutation/arbitrary-byte proptests
- **core:** atom-boundary and `N_ALT_ENTRY` gates, dead-strip closure
  (transitive roots, dylib export surface, `__mod_init_func`,
  `S_ATTR_NO_DEAD_STRIP`, `-u` roots), schedule-independence with
  dead-strip on
- **driver:** `m5_archives` (pull/no-pull/order/all_load/force_load/-u/-l/
  weak-ref/collision/determinism), `m5_deadstrip` (strip on/off byte
  checks, byte-identity, `-u` roots, dylib exports, archive transitive
  closure), `m5_cstring` (dedup + symbol remap + dyld-simulated
  section-relative pointer remap + dead-strip cooperation), `m5_flags`
  (filelist/framework/sectcreate/search order)

#### Shipped inside v0.2.0 — design-ladder 0.5.0 (2026-11-06)

#### Features
- **emit:** M4 fused tile emit (`build_image_fused`) — parallel 16 KiB
  tiles copy coalesced runs, apply relocations, encode chained-fixup
  words, place the `__LINKEDIT` chunks and hash the 4 KiB signature pages
  in one pass (perf doc §4.4, D14); UUID derives from the fused hash
  table, only page 0 re-hashes; parallel pre-fault of the zero-page-backed
  output buffer (D10); the pre-fusion M1–M3 body stays verbatim as the
  reference (`build_image`)
- **core:** M4 Pass 1 — LPT-scheduled parallel parse (longest input first
  on the shared compute pool) with giant-object splitting (inputs ≥ 64 MiB
  or ≥ 2²⁰ symbols decode their symtab in deterministic index chunks) and
  the parallel canonicalizing interner sort; `Parallelism::Serial` keeps
  the M1–M3 reference path (perf doc §4.1)
- **core:** D8 `resolved[]` de-indirection — per-file flat
  `ResolvedFile { syms, sects }` tables written once per layout fixed-point
  iteration; the relocation scan reads the file-local array and the M1–M3
  `addr_of`/`def_addr` map walks leave the hot path
- **core:** copy-run coalescing (perf doc §4.3) — `Layout.runs` merges
  pieces contiguous in input and output into one `memcpy`; coverage and
  disjointness gated
- **core:** shared compute pool (D9) — one process-wide rayon pool sized
  `PGR_JOBS` → `available_parallelism` (the macOS P-core default joins
  with the P0 rig, spike S4)
- **emit:** S1 writer pool — extent preallocation (`set_len`) plus a
  4-writer `pwrite` pool over disjoint 8 MiB blocks; fresh-vnode + fsync +
  atomic-rename contract unchanged
- **driver:** the fused pipeline becomes the default (`link_to_bytes`);
  `link_reference_bytes`/`link_reference_image` expose the pre-fusion
  reference for the M4 byte-identity gate and benches
#### Performance
- **bench:** `pgr-emit/emit` gate — fused tile emit 1.59 ms vs reference
  2.18 ms for ~0.94 MiB signed images (1.37×, 605 vs 441 MiB/s) on the
  2-core dev sandbox; full-pipeline benches record fused vs reference on
  all corpora (bind-path links 1.10–1.11×; resolution-heavy static corpus
  is Pass 2/3-bound as before); `PGR_JOBS=1` scaling recorded
#### Tests
- **emit:** ten fused-vs-reference byte-identity gates over every M3
  corpus shape (executables, dylibs, bundles, re-exports, export filters,
  flat namespace, `-no_fixup_chains`, `-no_adhoc`, wide multi-tile
  corpora); pooled-writer byte-exactness across 8 MiB block boundaries
- **core:** copy-run coverage/partition gates, parallel-vs-serial layout
  fingerprint equality, `resolved[]` table checks, giant-object chunked
  decode vs serial decode
- **driver:** M4 e2e gates — byte-identity with the reference pipeline,
  strict verifier + bundle/dylib contracts on fused outputs, fused
  double-link determinism


#### Shipped inside v0.2.0 — design-ladder 0.4.0 (2026-11-06)

#### Features
- **driver:** M3 CLI — `-dylib`/`-bundle` outputs, `-install_name`,
  `-current_version`/`-compatibility_version`, `-reexport_library`,
  `-exported_symbols_list`/`-unexported_symbols_list`,
  `-mark_dead_strippable_dylib`; Mach-O dylib inputs (`.dylib` scan for
  direct inputs and `-l` search); symbol-list files (one name per line,
  `#` comments)
- **core:** M3 layout — `OutputType` drives the image base (0 for
  dylibs/bundles, no `__PAGEZERO`), the load-command set (no `LC_MAIN`/
  `LC_LOAD_DYLINKER`; `LC_ID_DYLIB` for dylibs) and header flags
  (`MH_NOUNDEFS` iff no undefineds, `MH_PIE` exec-only,
  `MH_NO_REEXPORTED_DYLIBS`, `MH_DEAD_STRIPPABLE_DYLIB`); export filters
  hide externals as `N_PEXT` locals; local definitions shadow re-exports
- **core:** range-partition export-trie builder — multikey quicksort over
  `(name, index)` (deterministic, prefix-skip), compressed edges created
  exactly once, packed-row offset fixpoint from a 4-byte upper bound,
  allocation-free serialization; REEXPORT terminals (ordinal + imported
  name); 8–11× the M2 builder (see BENCHMARKS)
- **verify:** dylib/bundle contract checks (`LC_ID_DYLIB` presence,
  `MH_PIE` sanity, version ordering), REEXPORT trie-node validation with
  re-export-aware exports, and the M3 **pair gate**
  `verify_dylib_pair` — replays the executable's chained binds the way
  dyld does and asserts every two-level bind into the dylib resolves to a
  name its trie exports
- **format:** total export-trie walker (re-export nodes, cycle/offset
  rejection) and `LC_REEXPORT_DYLIB` classification
- **emit:** chain words at `vaddr − image_base`; ad-hoc signature carries
  `execSegFlags = CS_EXECSEG_MAIN_BINARY` only for executables
#### Performance
- **bench:** export-trie build gate — 31.5 ms for 10⁵ exports vs 363 ms
  for the legacy M2 builder on the dev sandbox (11.5×); legacy builder
  kept verbatim in the bench as the measured baseline
- **core:** hash-set import dedup and hash-map indirect-symbol lookup
  replace two O(n²) scans
- **bench:** `-dylib`/`-bundle` output-kind link benches
#### Tests
- **driver:** M3 e2e gates — strict-verified dylib/bundle outputs, the
  pair gate over a scanned dylib binary, re-export trie shape, export
  filters (`N_PEXT` symtab + trie exclusion), deterministic double-link

<!-- generated by git-cliff -->


#### Shipped inside v0.2.0 — design-ladder 0.3.0 (2026-11-05)

#### Continuous Integration
- Parse_tbd fuzz target + got/tbd corpus seeds (ab3d31f)
#### Documentation
- M2 README gates + D13 compat checklist; version 0.3.0 (659f4bc)
#### Features
- **driver:** M2 dynamic link CLI — tbd inputs, -l/-L, flat namespace (b3c275b)- **verify:** Export-trie walk for LC_DYLD_EXPORTS_TRIE (c8a50fa)- **emit:** Synthetic slot pieces + indirect symbol table chunk (1a1edd1)- **core:** M2 passes 1-3 — GOT/stub synthesis, binds, import table, trie (4732cf2)- **core:** Two-level resolution, dylib rank, GOT-load relocations (3d3fc9a)- **fixtures:** LLVM single-segment object convention, GOT relocations (d3f6e39)- **format:** .tbd v3/v4 stub parser, unsigned bind-word addend codec (585c30d)
#### Performance
- **bench:** Dylib-linked bind-path baseline (M2) (34fc15e)
#### Tests
- **driver:** M2 e2e gates — printf-from-tbd, flat namespace, lld golden (14fe25c)

<!-- generated by git-cliff -->


#### Shipped inside v0.2.0 — design-ladder 0.2.0 (2026-11-05)

#### Features
- **driver:** M1 static hello-world link pipeline: ld64-compatible option
  surface (`-o -arch -platform_version -e -static -fixup_chains -adhoc
  -headerpad -segalign`), Pass 0 mapping and the Pass 1–5 driver loop
- **core:** Passes 1–3: arm64 relocatable-object parser (pair-resolving
  relocation decode), canonicalizing interner, Mach-O precedence resolution
  (strong > weak > common, coalescing), §8 layout engine (16 KiB congruence,
  constant-delta segments, `__LINKEDIT` chunk order), §7 chained-fixup
  planner (stride-bounded packer, rebase-only payload, `__chain_starts`
  static mirror) and the fully-resolved patch plan
- **emit:** Passes 4–5: single-allocation output buffer, arm64 immediate
  patching (ADRP/imm12/BR26, subtractor writes), chain-word encoding,
  `__LINKEDIT` assembly, two-pass content-derived UUID, ad-hoc SHA-256
  signature, atomic page-granular writer
- **verify:** `__chain_starts` mirror-vs-payload agreement check and the
  canonical segment-order check for executables
- **fixtures:** deterministic arm64 relocatable-object (`MH_OBJECT`)
  builder with clang-convention symtab grouping and relocation tables
- **driver:** end-to-end link benchmark (small/large corpora) recorded as
  the M4 baseline

#### Continuous Integration
- Fuzz schedule extended with the `link_object` target (Pass 1 parser +
  Pass 2/3 pipeline) and object seeds in the fuzz corpus


#### Shipped inside v0.2.0 — design-ladder 0.1.0 (2026-11-05)

#### Bug Fixes
- **format:** Panic-free casts on misaligned mutated input (a5e3a4f)
#### Continuous Integration
- Fmt/clippy/test/doc/bench gates, fuzz schedule, git-cliff release pipeline (c3234fa)
#### Features
- **verify:** M0 verifier v1 with chain-walk simulation (408eb90)- **fixtures:** Deterministic Mach-O image builder (eb69c00)- **format:** Zero-copy Mach-O primitives, cursor and codecs (5ccacc8)
#### Performance
- **bench:** Parser-throughput baseline (GB/s) (d80515d)
#### Refactor
- **fixtures:** Bundle fixup-payload inputs into FixupContext (f583287)

<!-- generated by git-cliff -->

#### Build

- **build:** restore criterion's `cargo_bench_support` to the workspace
  feature set — criterion 0.7 split the measuring harness out of the
  default features, and with `default-features = false, features =
  ["html_reports"]` every bench compiled, "passed" and measured nothing
  (the CI `bench --no-run` gate could not see it); the harness runs again



