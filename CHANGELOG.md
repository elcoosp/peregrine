# Changelog

All notable changes to Peregrine are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adopts [Conventional Commits](https://www.conventionalcommits.org/) for
release automation.
## [Unreleased]

### Added (M95)

- **M95** — the SARIF face for the universal container: the M75 CLI refusal ("SARIF anchors
  name file bytes; a container's slices ride their own windows — re-anchoring would
  re-shape") had its premise backwards — the slices ride *inside* the audited file, so
  re-anchoring is not re-shaping. `pgr_verify::sarif::render_universal` renders the M71
  container verdict as one deterministic SARIF 2.1.0 document: one run per declared slice, in
  table order, the rule table the union of the slices' codes (the built-ins in `Code::ALL`
  canonical order, the custom tokens after them, named once however many slices carry them),
  and every anchored result riding a container-absolute `region.byteOffset`
  (`slice.offset + anchor`) — the anchor names the audited file's own bytes, which is what a
  triage tool reads; an unanchored issue rides no location and the severity map is the M69
  one (the only two severities the verifier reports). `pgr-verify <fat> --sarif` rides the
  same render (the refusal retires with its premise; the whole-verdict exit gate keeps, a
  malformed container's `REFUSED` rides the face the report would have), the two-machine-face
  and baseline refusals stay, the `sarif_universal` bench group pins the render's price
  beside the single-image face (linear in the slices), and the `universal_sarif` example
  walks the two-slice container beside its document. The render's shared writer keeps the
  M69 single-image document byte-identical (the refactor is the same shape, one run).

### Added (M94)

- **M94** — the verifier's initializer-surface gate: the rung the M16 design record named
  ("the verifier's own `init_offsets` gate — a hand-broken section is named — is the next
  rung") joins the M12 registry as the twelfth family (`Check::InitOffsets`, code
  `init_offsets`, module `pgr_verify::init_offsets`). The sections dyld's load-time
  initializer walk consumes must ride whole strides — the `__init_offsets` u32-offset form
  on the 4-byte stride, the classic `__mod_init_func` pointer form on the 8-byte stride —
  each `__init_offsets` entry must name a target an executable segment maps (dyld's own
  "initializer does not point within executable segment" check replayed read-side, entry by
  entry against the segments the image actually maps: an unmapped target and a target inside
  a never-executable segment each name themselves, the entry index and the resolved address
  riding the message), and the offsets form below the platform's chained-fixups floor names
  the floor (`pgr_format::consts::chained_fixups_floor`, the one table — the producer refuses
  the same premise at link time; the gate is the read-side backstop for shapes built
  independently of it). The classic pointer form's file bytes are fixup words, so the gate
  reads its stride and leaves the slot walk to the `fixups` family; an `MH_OBJECT` carries
  no dyld walk, so the family self-gates to the kinds dyld loads (the object contract owns
  the relocatable shape). Shapes are built by hand in the gate matrix (`m94_init_offsets.rs`,
  the §11 different-code-path rule), the `init_offsets` bench pins the family's price beside
  the whole pass (a per-section stride read plus a per-entry segment lookup — ~0.9% of the
  pass on the bench fixture), and the `init_offsets_gate` consumer example walks the honest
  shapes beside the broken one and the `--checks init_offsets` selection.

### Added (M93)

- **M93** — the served liveness ask: the M92 resident refusal retires — the wire (v48) carries the `-why_live` names beside the provenance asks, the session's own walk carries the mark record (`LinkResult::liveness`, `Some` exactly when the strip ran), and the reply's provenance tail carries the rendered chains verbatim beside the M79 answers (the M62 convention — the wire never re-shapes the face the client prints). Every lane serves the query: the one-shot and the in-process ladder from their own walks (M92), the resident full link from the session's warm pipeline, and the fusion ladder's replay from its own walk (`serve_relink` runs the full Passes 1–3, so `result.liveness` is the replay's mark record — the M88 shape; the v48 tail already had the shape to carry it, no wire shape moves); the client prints the served chains beside the resident link exactly as the cold lane prints its own, a vacuous query's `ERROR` is the fallback cue the cold lane's refusal speaks (the misspelling named either lane), and the decode gate refuses the ask beside a relocatable config (the M83 replay-face rule — `-r` preserves input sections verbatim and carries no strip, no mark record exists to walk). M93 also closes the gap the served rung surfaced: the pre-M93 relocatable lane silently ignored the query — the surface now refuses the premise (`OptsError::WhyLiveConflict`, the verdict names `-r`'s missing strip), instead of a vacuously empty answer. The `wire_liveness` bench pins the codec's price (the request-side names, the reply-side chains), and the `why_live_session` example drives the capture → edit → relink cycle whose verdict flips with the edit (dropped cold, kept warm, the chain naming the keeper the new reference introduced).

### Added (M92)

- **M92** — the liveness-provenance query (`-why_live <symbol>`): ld64's flag (`Options::printWhyLive`) — previously unknown on the surface — is the M5 mark-sweep's own decision made nameable (`pgr_core::why_live`), the third provenance face beside `-why_export` (M56) and `-why_load` (M57): the mark phase records, from data it already had, the first way each atom went live — the root that named it (the entry point, the export surface, `-u`, an alias, `-export_dynamic`, the init/term/no-dead-strip sections, the unwind anchors) or the first reference that reached it (the referrer atom, the referenced name, the relocation site) — and the record rides the link result (`LinkResult::liveness`, `Some` exactly when the strip ran; the layout is planned after the extraction, so the record never feeds a pass and a queried link plans the identical layout). The query walks the record from the queried definition back to its root — one keeper per hop, the root decision named last, the dead verdict the answer (not an error); the refusals name their premise (the misspelling, the dylib-bound name, the link that never stripped — the M56 convention), `render`/`render_json` are the deterministic faces (the M55 escape rules, the M56 definition object shared), the one-shot lane and the in-process ladder answer and the resident lanes refuse the ask this rung (the wire's provenance tail v45 carries the why_export/why_load asks — the served rung is a later milestone), and the `why_live` bench pins the walk's price beside the corpus's own depth while the `why_live_link` example renders both faces beside the refusals.

### Added (M91)

- **M91** — the `-sectorder __TEXT __cstring` cstring face serves: the M90 rung's refusal retires — the file's escape-decoded literal contents (`pgr_core::order::CstringOrder`, the ld64 `cstringSymbolName` escape set with the named divergences) rank the `S_CSTRING_LITERALS` sections' literals through the D4 canonical sort (the remap lands every duplicate on the single output copy whatever the ranks say), the unmatched entry rides the `cstring_order_unmatched` advisory, the table crosses the wire (it rides the v47 tail — the rebuild-refusing table is a malformed request), and the default keeps every pre-M91 link byte-identical (the `sectorder_cstring` bench group and the `cstring_order_link` example ride along).

### Added (M90)

- **M90** — ld64's per-section order flag rides the M11 rank seam: `-sectorder <seg> <sect> <file>` (`pgr_core::order::classify_section_order` mirroring `parseSectionOrderFile`) — the rank-append face composes every order source into the ONE rank table in command-line order (`SymbolOrder::compose`, the cross-source duplicate refusing with both sources named; the repeated `-order_file` last-wins read retires), the `__TEXT,__literal*` face is the warned no-op (the file never read), and the cstring face refuses this rung with the mode named (M91 hands it its own rung); the composed table rides the v47 wire and the ladder unchanged (the `sectorder_compose`/`sectorder_link` bench groups and the `sectorder_link` example ride along).

### Added (M89)

- **M89** — the fusion ladder's dependency record: the M85 lane contract (a record-bearing
  fusion relink stands the resident attempt down — "the fusion ladder's reads live inside
  the daemon") flips to service the M88 way: the premise voids itself, because the §7.2
  contract already forbids the daemon touching the filesystem — the reads the stand-down
  worried about never happen, and the relink cycle's real reads are the client's own
  Pass 0, which `resident_relink` already runs to build the job (`PreparedLink::deps`, the
  read set recorded while the reads happen). The sidecar the fusion relink writes names the
  files the cycle actually mapped — never the previous link's list — with the output rows
  joining at the write site and the map landing first so the record's output row names a
  sidecar that exists (the one-shot's own order); the parity gate is the rung's own
  contract: either lane, one Pass 0, one document; the `resident` bench gains the
  record-bearing fusion relink beside the plain one, and the `fusion_dep_info_link`
  example walks the capture → edit → record-bearing relink beside the decoded rows

### Added (M88)

- **M88** — the fusion ladder's served provenance: the M84 lane contract (a query-bearing
  fusion relink stands the resident attempt down — "the session's patch serves bytes, not
  answers") flips to service the M87 way: the premise was outdated, because the session's
  ladder is not a byte-replay either — `serve_relink` runs the full Passes 1–3
  (`link_from_objects`), so `result.resolution`/`result.loads` are the walk's own Pass-2
  products, in the session's memory, and the v45 provenance tail already has the shape to
  carry them (no wire shape moves). The decode gate's refusal arm retires; the session
  renders the M56/M57 answers over its own walk at both exits (the patched exit and the
  untouched one — the answers name the resolution the patch plan read, never the record's
  stale product; a vacuous query refuses the replay exactly as it refuses the full link),
  the driver's fusion relink rides the ask on the request, and the client prints the
  served renders beside the patched image exactly as the resident full link prints its own
  — an old server's refusal is the `ERROR` reply the stand-down already speaks, the
  in-process ladder answering either way; the `resident` bench gains the query-bearing
  fusion relink beside the plain one, and the `fusion_provenance_link` example walks the
  capture → edit → served fusion answers beside the vacuous refusal

### Added (M87)

- **M87** — the fusion ladder's served map: the M86 lane contract (a map-bearing fusion
  relink stands the resident attempt down — "the session's patch serves bytes, not the
  placed layout") flips to service the M80/M86 way: the premise was outdated, because the
  session's ladder is not a byte-replay either — `serve_relink` runs the full Passes 1–3
  (`link_from_objects`), so `result.layout` is the walk's own Pass-3 product, in the
  session's memory, and the v46 map tail already has the shape to carry it (no wire shape
  moves). The decode gate's refusal arm retires; the session renders
  `pgr_core::map::build_link_map` over its own walk at both exits (the patched exit and
  the untouched one — the document names the placed image the patch plan read, never the
  previous link's), the driver's fusion relink rides the ask on the request, and the
  client writes the served bytes to the `-map` path exactly as the in-process ladder
  writes its own — an old server's refusal is the `ERROR` reply the stand-down already
  speaks, the in-process ladder answering either way; the `resident` bench gains the
  map-bearing fusion relink beside the plain one, and the `fusion_map_link` example walks
  the capture → edit → served fusion map beside the transport that names the lane

### Added (M86)

- **M86** — the incremental ladder's link map: the M11/M80 lane contract (`-map`
  refused beside `-incremental` — "the map reports the full emit's layout") flips to
  service the M84/M85 way: the premise was outdated, because the relink is not a replay
  of recorded bytes — its walk runs the full Passes 1–3 (`pgr_core::link_cached` inside
  `incremental_relink`), so `LinkResult::layout` is the walk's own Pass-3 product, in the
  relink's own memory, and `pgr_core::map::build_link_map` renders the same face the
  one-shot writes. The map the ladder writes is the relink's own placed image — never
  the previous link's document — at both success exits (the patched exit and the
  untouched one; the map lands before the record write, so the dependency record's
  output row names a sidecar that exists), and an untouched relink's map is the
  capture's own document (nothing moved, the walk re-derived the same placed image).
  The fusion lane keeps its edge — the session's patch serves bytes, not the placed
  layout (no wire tail carries the ladder's map), so a map-bearing relink stands the
  resident attempt down to the in-process ladder, whose own walk renders the document;
  the `incremental` bench gains the map-bearing relink beside the plain one, and the
  `incremental_map` example walks the capture → edit → map-bearing relink beside the
  rendered segments

### Added (M85)

- **M85** — the incremental ladder's dependency record: the M60 lane contract (`-dependency_info`
  refused beside `-incremental` — "the relink patches the recorded plan and re-reads no input
  file") flips to service the M84 way: the premise was outdated, because the relink's Pass 0
  (`prepare_link`) re-reads every input it maps — the re-parse is the digest source the
  propagation gate compares — and records the read set while the reads happen
  (`PreparedLink::deps`, the same recording the one-shot's Pass 0 runs). The sidecar the relink
  rewrites names the files the ladder actually read, never the previous link's list, and the
  output row joins at the write site — the record stays read-set-derived on either tier (the
  patched exit and the untouched one both rode the mapping). The fusion lane keeps its edge —
  the session's reads live inside the daemon and the wire carries no read set, so a
  record-bearing relink stands the resident attempt down to the in-process ladder, whose own
  Pass 0 records the files it mapped. `OptsError::DependencyInfoConflict` retires with the
  gate; the `incremental` bench gains the record-bearing relink beside the plain one, and the
  `incremental_dep_info` example walks the capture → edit → record-bearing relink beside the
  decoded rows

### Added (M84)

- **M84** — the incremental ladder's provenance queries: the M56/M57 lane contract
  (`-why_export`/`-why_load` refused beside `-incremental` — "the ladder's replay product is the
  record's, not the walk's") flips to service the M79 way: the verdict was the M9 GA rung's
  outdated premise, because the relink is not a replay of recorded bytes — `incremental_relink`
  re-parses the inputs and runs the full Passes 1–3 (`pgr_core::link_cached`), so
  `LinkResult::resolution` and `LinkResult::loads` are the walk's products, in the relink's own
  memory. The answers serve from the relink's own walk at both success exits (the patched exit
  and the untouched one — the walk ran either way, one question, one answer, either lane), the
  same faces the one-shot prints; a vacuous query refuses the relink exactly as it refuses the
  cold link (the misspelling named, never silently empty), the faces ordered after `store_record`
  so a refusal leaves the next relink re-planning from the renewed record. The fusion lane keeps
  its edge — the session's patch serves bytes, not answers (no wire tail carries the walk's
  Pass-2 product), so a query beside `-resident -incremental` stands the resident attempt down
  to the in-process ladder, whose own walk serves the answers. `OptsError::WhyExportConflict`
  retires with the gate; the `incremental` bench gains the queried relink beside the plain one,
  and the `incremental_provenance` example walks the capture → edit → queried relink beside the
  vacuous refusal

### Added (M83)

- **M83** — the resident lane's relocatable shape: the M8 lane contract (`-r` named "no
  resident shape") flips to service the M82 way: the session's raw blobs are the walk's
  inputs, and the object path re-parses them (the POI cache is the segmented pipeline's
  optimization, not a prerequisite). The wire value the config body reserved for the
  relocatable filetype decodes now (an old server's refusal is the `ERROR` the client's
  fallback speaks — honest degradation), the session's walk runs the object path over the
  raw blobs (`pgr_core::link_reloc`, the cold lane's own entry — the observed variant when a
  face asks, the report naming the object shape's own phases, the emit band absent) and
  `pgr_emit::build_object_image` assembles the `MH_OBJECT` the reply carries verbatim, so
  `-r -resident` plans the object the cold lane plans (byte-identical; the M10 two-step gate
  relinks the served object into an executable), the provenance queries ride the object's
  Pass-2 product (the same arena the cold lane's `-why_export` reads — `serve_provenance_from`
  is the parts face both shapes share), the replay faces refuse at the wire and at the
  session (no record, tiles, audit, `-verify` or `-map` beside a relocatable config — the
  surface's knob refusals mirrored exactly), and a stand-down hands over to the one-shot
  relocatable link, whose own walk produces the same bytes — either lane, one walk, one
  object. The `resident` bench's reloc group pins the object shape's session cost beside the
  one-shot's, and the `resident_reloc_link` example walks the parity gate beside the
  two-step relink

### Added (M82)

- **M82** — the resident lane's arm64e chain words: the M10 rung-4 lane contract
  (`-fixup_chains_format arm64e` rode Offset64 shapes beside `-resident` — the surface's own
  verdict named the session's reuse gates "planning Offset64 shapes this slice, the v6 wire
  mirrors the family") flips to service the M81 way: the family is config, and the config
  crosses the wire — the v6 tail byte has mirrored it since M10, so no wire shape moves.
  `pgr_core::fixups::FixupPlan::chain_word_format` is the seam (the plan names its own
  encoding — one source, no re-derivation), the record carries it now (v7 — one byte;
  v1–v6 records decode to `None` and re-record, the designed path; the codec is lossless
  over the family), and `pgr_emit::incremental::LinkRecord::admits` is the named admission
  both relink ladders read (the session's §7.3 ladder and the driver's in-process one): a
  config naming a different family than the record's declines to the full link — which
  re-plans the family the request named and re-records — never a patch across word shapes.
  So `-resident -fixup_chains_format arm64e` links with the image the cold lane plans
  (byte-identical; the payload declares the arm64e family, the strict pass walks the served
  words), the fusion ladder patches arm64e records in place, and a family flip lands the
  family the client asked for on either lane. The `resident` bench's arm64e group pins the
  plan-side price beside the lane's own warm shape, and the `resident_arm64e_link` example
  walks the parity gate beside the record's family and the flip's full link. Alongside: the
  vestigial `FixupPlan::payload_off` field (always 0 since the `__LINKEDIT` plan owned the
  authoritative offset; no reader anywhere) is dropped from the plan constructor surface

### Added (M81)

- **M81** — the wire carries the order-file rank table: the M11 lane contract (`-order_file`
  is a driver-side Pass-3 input, so the resident lane refused it — the surface's own verdict
  named the wire config "not carrying the rank table") flips to service the M80 way: the
  table is config, and the config crosses the wire. The rank table rides the request's
  config tail now (v47 — a present byte, count-prefixed entries with their object scope and
  diagnostics line; the empty absence is the pre-M81 shape, byte-identical on the decode
  side; a table the constructor refuses — an empty list, two ranks for one symbol — is a
  malformed request at the wire, never a silently misread table), and
  `pgr_core::order::SymbolOrder::from_entries` is the pgr-core seam the decode side builds
  through (the same refusals the file parse carries, the lines named). `-resident
  -order_file` links with the layout the cold lane plans now — the parity gate is the rung's
  own contract (byte-identical images), and it caught the drift it exists for: the Pass-1
  atom-split decision (a rank table feeds the split the same way dead-strip does) was the
  cold lane's inline `||` — `pgr_core::split_symbols_for` is the named rule both lanes read,
  so a warm ordered link plans the atom shape the cold one plans. The ladder's replay beside
  the `record` rides the table the way the cold ladder always has (the table is config, not
  a product), the unmatched-name advisory stays the cold lane's stderr face (the product is
  the bytes, and the bytes are what cross), and the fallback ranks the one-shot's own way.
  The `wire_order` bench pins the config tail's encode/decode price at the build-system
  scales (8 and 64 entries beside the table-free shape), and the `ordered_resident_link`
  example walks the parity gate beside the placed order

### Added (M80)

- **M80** — the resident lane's served map: the M11 lane contract (`-map` reads the one-shot
  link's layout, so the resident lane refused it — the surface's own verdict named the wire
  "never returning the layout the map reports") flips to service the M79 way: the session's
  warm pipeline *is* the walk (parse from resident POIs, intern, resolve, layout), the layout
  and the interner are in its memory, and the driver never asked. The map ask rides the
  request now (v46 — the `-map` flag; a map beside the `record` is a malformed request at the
  wire: the §7.3 ladder's replay patches the recorded plan in place, and the map reports the
  full emit's layout — the fusion lane keeps refusing, no wire caller can plan the shape
  either), the session renders the placed image's report from its own walk
  (`pgr_core::map::build_link_map`, the same pure function the cold lane's `-map` calls — the
  document cannot disagree with the bytes the reply carries), and the reply's IMAGE tail
  carries the rendered document verbatim (the M62 convention — the wire never re-shapes the
  face the client writes), so the driver writes the served bytes to the `-map` path exactly as
  the cold lane writes its own — the daemon never touches the filesystem, the client does. The
  fallback story stays honest: a resident attempt that stands down hands over to the one-shot
  link, whose own render writes the file — either lane, one walk, one document (`m80_served_map`
  pins the byte parity and the fallback's). The `wire_map` bench pins the tail's encode/decode
  price beside the image pages it rides, and the `served_map_link` example walks the served
  face beside the fallback's parity gate

### Added (M79)

- **M79** — the resident lane's served provenance: the M56/M57 lane contract (`-why_export`/
  `-why_load` read the one-shot link's Pass-2 product, so the resident lane refused them —
  the product never crossed the wire) flips to service the M76 way: the session's warm
  pipeline *is* the walk (parse from resident POIs, intern, resolve, layout), the product is
  in its memory, and the driver never asked. The queries ride the request now (v45 — the
  `-why_export` names in flag order, the `-why_load` flag beside them), the session renders
  the answers from its own Pass-2 product (the index builds once per link, the queries read
  it), and the reply's IMAGE tail carries the rendered text verbatim — the M62 convention,
  the wire never re-shapes the face the client prints — so the driver prints the served
  answers beside the resident link exactly as the cold lane prints its own. The lane contract
  stays honest at the edges: a query beside the `record` (the §7.3 ladder's replay) is a
  malformed request at the wire — the replay's Pass-2 product is the record's, not the
  walk's, so the fusion lane keeps refusing; a vacuous query refuses the session's link (the
  cold lane's own refusal), the `ERROR` reply is the client's one-shot fallback cue, and the
  misspelling is named either lane. The `wire_provenance` bench pins the tail's encode/decode
  price beside the image pages it rides, and the `served_provenance_link` example walks the
  served face beside the vacuous refusal

### Added (M78)

- **M78** — the flush pool's writer lanes: the M64 registry named every worker lane
  `pgr parse pool N` because the parse pool (M63) was the only pool the M63 task seam
  carried — and the §5 flush runs a second pool, four writer threads whose `pwrite` work the
  aggregate `Flushed` phase event hid. The writers carry their own spans now: one
  [`pgr_core::observe::TaskEvent`] per writer (the blocks it carried as its label —
  `blocks 1,5 of 5`, writer *k* takes blocks *k, k+4, …* — its wall time, its thread and its
  own arrival clock), reported through the M63 channel convention (the records cross an mpsc
  channel that opens only when a subscriber rides; the caller forwards them once the pool
  returns; a single-block write reports on the calling thread — the pipeline lane, the M64
  serial rule). The timeline's registry names the second family beside the first
  (`pgr write pool N`, each pool numbered among its own workers, family-aware since the
  first task the lane carried), so the §9.4 toolbox reads the write workers' stragglers and
  idle gaps beside the parse pool's. The observation never moves a byte (the parity gate,
  `m78_write_tasks`), the strict reader restores both families' labels exactly (the round
  trip, gated on the mixed shape in `m78_write_lanes`), the `trace` bench's write-pool
  groups pin the rows' render/parse price, and the `write_lanes` consumer example renders
  the four writers beside the round-trip gate

### Added (M77)

- **M77** — the gate's check selection: `-verify-checks <families>` composes the M12 selector
  into the link's own verify gate — the same `CheckSet` the verifier CLI's `--checks` parses,
  the same subtractive contract (fewer families against the same parsed image; the parse
  pre-pass and the stats ride regardless, the `-no_adhoc` carve-out and the strict contract
  unchanged), so a build gate that prices only one contract runs the families it prices.
  The selection rides beside `-verify` only (a selection without a gate refuses — the families
  narrow the gate, never the link) and crosses the wire (v44) so the resident lane's served
  pass narrows to the same families — one selector, both lanes; a selection the wire parser
  refuses is a malformed request, never a widened gate. `pgr_driver::verify_gate_selected` is
  the public face (`verify_gate` delegates to the full set), the `verify_gate` bench pins the
  narrowed lane beside the full pass, and the `verify_checks_gate` example walks both
  selections beside the corrupted twin

### Added (M76)

- **M76** — the resident lane's verify gate: the M73 cold-path `-verify` gate re-ran the
  strict pass on the client even when the link rode the resident session — and the session
  (M72, wire v43) could already serve its own verdict for the asking, but the driver never
  asked. `-resident -verify` rides the request's `verify` flag now: the session's own strict
  pass gates the write through the served verdict (`pgr_driver::gate_from_served` shapes the
  gate face from the reply's report — O(issues), never the image walk), one verifier pass per
  resident link instead of two, and the summary rides `LinkOutcome::verify` exactly like the
  cold lane's. The fallback story stays honest: a resident attempt that stands down hands over
  to the one-shot link, whose own gate runs the pass locally — either lane, one gate, one
  outcome shape. The `verify_gate` bench pins the served face beside the cold pass, and the
  `verify_gate_resident` example walks the cold link, the warm relink, the corrupted twin's
  rendered refusal and the fallback

### Added (M75)

- **M75** — the CLI's SARIF face: `pgr-verify --sarif` rides the M69 render
  (`pgr_verify::sarif::render`) — one deterministic SARIF 2.1.0 document per verified image
  (one line, fixed key order, `ruleId` the stable code token, `level` the severity, the
  anchor offset as a binary `region.byteOffset`), the exit gate the whole verdict keeps.
  The face refuses where it cannot apply honestly: beside `--json` (two machine faces are
  two writers; one run serves one), beside `--baseline` (the delta has no SARIF shape) and
  on a universal container (the SARIF anchors name file bytes; a slice's issues ride their
  own window — re-anchoring would re-shape, so the face names the slice story)

### Added (M74)

- **M74** — the CLI's universal-container face: `pgr-verify <fat-container>` walks
  `verify_universal_with_checks` — the M71 container face composed with the M12 selector
  surface (the new public seam: the check selection narrows every slice's pass, the
  table-row/header agreement riding as the container's own contract under any selection) —
  instead of running the single-image pass over the container's bytes (the fat magic is no
  Mach-O magic, so the gate refused the *container* and never named the slice). One verdict
  per declared slice, printed slice by slice, the exit gate every slice's; the `--json` face
  serves one M13 document per slice (each line the strict reader's own shape, the `file`
  field naming the slice it rode), `--baseline` refuses a container (the baseline identity
  gates one image's offsets, never a slice table), and a malformed table refuses with the
  format reader's offset-tagged error verbatim. The `universal_checks` bench pins the
  narrowed lane beside the full pass, and the `universal_checks` example walks both
  selections beside the corrupted twin

### Added (M73)

- **M73** — the link's own verify gate: `-verify` runs the strict verifier on the
  produced bytes and refuses to ship a failing verdict — the gate sits before the
  write, so the output file is never created when the image fails it (the audit's
  rule, on the cold path), and a passing verdict rides `LinkOutcome::verify` (the
  embedding caller reads the summary without re-reading the file). The `-no_adhoc`
  carve-out applies the audit's way (the missing-signature shape is the config's own
  choice), the strict contract blocks warnings, and the refusal renders with miette
  help text (`DriverError::Verify` — exit 1, the issues in the verifier's own words).
  The knob is an image-output decision: `-incremental` refuses it (the relink
  ladder's gate is `-incremental-verify` — the §7.3 audit, whose subject is the
  patch) and `-r` refuses it (an object, not an image — `pgr-verify` gates objects
  as a tool). The `verify_gate` bench pins one verifier pass beside the write (the
  clean image, the corrupted twin, the `-no_adhoc` filter), and the `verify_gate`
  example walks the gated link beside its corrupted twin's rendered refusal

### Added (M72)

- **M72** — the resident lane's served verify verdict (wire v43): the request's
  `verify` flag asks the session to run the strict verifier on the final bytes, and
  the reply's IMAGE tail carries the effective report — the subject is the image, so
  every outcome serves one (the full link's, the patched relink's, the untouched
  relink's; the audit's subject is the patch — complementary, not duplicate). The
  document rides verbatim in the M13 interchange form, the strict reader
  (`pgr_verify::report_json::parse_report_json`) its own face — a lying document
  refuses the reply — and the `-no_adhoc` carve-out applies the audit's way (the
  stats ride unfiltered). The client gates nothing on the verdict (the audit remains
  the write gate); the `wire_verify` bench pins the tail's codec price beside the
  image pages it rides, and the `verify_session` example walks the cold link, the
  patched relink, the untouched relink and the unasked relink that rides no tail

### Added (M71)

- **M71** — the verifier's universal-container face: the driver links a fat container
  through its arm64 slice (M70), so the verifier owes the same container a read-side
  story — `pgr_verify::verify_universal` runs the strict pass per declared slice (one
  `SliceVerdict` per table row: the row beside its own `Report`), and the table's row
  must agree with the slice's own header about the arch it names (the driver links by
  the row; a lying row rides `Code::HeaderInvalid` anchored at the slice's offset). A
  malformed table stays the format reader's offset-tagged refusal — there is nothing
  to slice — and the face rides the tracing seam inert-until-subscriber like every
  check family. The `universal` bench pins the per-slice price beside the single-image
  pass (linear in the slices, nothing per byte), and the `universal_verify` example
  walks the clean container and its corrupted twin

### Added (M70)

- **M70** — the universal-binary read seam: ld64 links against universal ("fat")
  containers daily — every SDK dylib and static archive ships one — and Peregrine
  refused them ("not a .tbd stub, Mach-O dylib or static archive") because the
  container's magic is `FAT_MAGIC`, not a Mach-O magic. The format layer gains the
  container's codec (`pgr_format::universal`): the big-endian `fat_header` and slice
  table decode at both widths (`FAT_MAGIC`, `FAT_MAGIC_64`), every structural refusal
  is the offset-tagged `FormatError` the other parsers carry (a truncated header, a
  lying count, an out-of-bounds or overlapping window, a sub-header slice), and
  `Universal::arm64` names the cputypes it carries when the arm64 slice is missing —
  the fix, not just the verdict. The driver's input dispatch (the positional/filelist
  `map_input` chain, the `-l` and `-framework` scans, the `-bundle_loader` host)
  unwraps the arm64 slice before the per-kind dispatch, so every input class links the
  slice it already linked — a non-universal input costs one four-byte probe, and the
  parity gate pins the container adding nothing the pipeline sees (byte-identical
  images beside the bare slice). The `universal` bench pins the decode/selection price
  over 2/5/9-slice containers, and the `universal_input_link` consumer example walks
  the container end to end

### Added (M69)

- **M69** — the verifier's SARIF interchange: `pgr_verify::sarif::render` carries the
  M13 report into SARIF 2.1.0 — the shape GitHub Code Scanning, IDE problem panels and
  CI triage read natively (`ruleId` the stable code token, `level` the severity — the
  verifier's only two, the message verbatim under the M13 escape rules, the anchor
  offset as a binary `region.byteOffset`; an unanchored issue rides no location). The
  face is a one-way writer — the reader is the consumer's tooling, not ours — and the
  document keeps the house interchange conventions: deterministic (two renders of one
  report are byte-identical, gated), one line, fixed key order. The rule table rides
  one rule per distinct code in the report — the built-ins in `Code::ALL`'s canonical
  order, the M67 custom tokens after them in lexicographic order — so the document's
  key set is the report's own, never the arrival order. The `sarif` bench pins the
  O(issues) render price beside the M13 JSON writer's, and the `sarif_report` consumer
  example walks the valid image and its corrupted twin

### Added (M68)

- **M68** — the emit half joins the observation seam: Passes 4–5 stop being the caller's
  opaque band and ride the M54 seam as typed phases — `Emit` (the fused tile emit's
  completion: the 16 KiB tiles and the image bytes the plan already knew, reported by
  `pgr_emit::build_image_fused_observed`) and `Flush` (the pooled atomic write's: the
  8 MiB blocks and the writer threads that carried them, the single-writer path included,
  reported by `pgr_emit::write_image_observed`) — the TDD §9.3 instrumentation spec's
  named rows beside the pipeline's passes. The parity gate is the seam's own contract
  (the observed emit plans the identical image, the observed flush ships the identical
  bytes — `emit_observed.rs` gates both); the driver's `--time`/`--time-json`/`--trace`
  faces collect the rows beside the Passes 1–3 rows through one subscription (the
  `FaceSlot`, the `None`-forwarding twin of `ObserverPair`), the total band measuring the
  wall through the flush, and the band face stays the library caller's
  (`TimeReport::emit`/`total` remain `Option`s). The time-report tail's vocabulary gains
  the two tokens without a version bump (no served content changes — the session's warm
  run has no fused emit and the client does the writing). The `time_report` bench's
  `render_9_rows`/`render_json_9_rows` groups and the `trace` bench's
  `render_9_rows_image`/`parse_9_rows_image` groups pin the rows' price, and the
  `emit_flush_observed` consumer example walks the whole pipeline beside the report
  (the `ObserverPair` composition face riding along)

### Added (M67)

- **M67** — the verifier's check registry opens to consumer-side checks: the `ImageCheck`
  doc promised "a future consumer-side check can slot into the same shape", and the slot
  now exists. A project policy implements `CustomCheck` (`pgr_verify::checks`) — the
  family contract without the family key (total like every family, self-gating on the
  image type, declaring its codes; names are metadata, not selector keys, and two
  same-named checks both run in caller order) — its own tokens ride the new
  `Code::Custom(&'static str)` outside the canonical table, and `verify_with_extra_checks`
  drives the selected built-in families first and the custom units after them into the
  same sorted report (the stats contract is the whole-report one: an error zeroes the
  fixup-slot count, a family's or the policy's alike). The M13 interchange keeps its
  one-writer/one-reader shape: a well-formed snake_case token outside the table restores
  as a custom code (interned once per distinct token), anything else is refused with the
  fix named — the round-trip gate covers the extension. The `verify_extra` bench groups
  pin the ride's price beside the full pass (~21 µs vs ~20.9 µs on the checks-bench
  fixture — the extension is a `&dyn` call, not a re-verify), the `custom_check` example
  walks the policy (the m51 stack-exec decision read from the consumer side), and
  `m67_custom_checks.rs` pins the gate matrix. The driver's `-sectcreate` name refusal
  rides its typed `SynthError` (`DriverError::SectionCreate`) instead of a fabricated
  `.tbd` parse failure

### Added (M66)

- **M66** — the fusion lane's ladder joins the seam (wire v42 in service): the session's
  ladder reports its rungs beside the warm pipeline it already observes (`serve_relink`
  reports the integrity gate over the transferred bytes, the patch plan, the in-memory
  patch and the audit through the same collectors), so `-resident -incremental
  --time/--trace` stops refusing — the client prints the served table and writes the
  served timeline verbatim (either lane, one observed run; an untouched relink's served
  report ends at the plan, no patch row riding a relink that patched nothing). The
  vocabulary crossed no new wire: v42 registered the rung tokens at M65; the session
  reports them now. The `served_timing_session` example walks the ladder face beside the
  round-trip gate, and the driver's fusion cycle gates it end to end
  (`m65_relink_timeline.rs::the_fusion_lane_serves_the_ladder_faces`).

### Added (M65)

- **M65** — the relink ladder rides the observation seam (`--time`/`--trace` beside
  `-incremental`): the §7.3 ladder's engine rungs — the integrity gate (`RelinkGate`, the
  record's page-hash sample hashed against the previous output), the patch plan
  (`RelinkPlan`, the total and dirty tiles), the clone-and-patch (`RelinkPatch`, the bytes
  and tiles actually written) and the `-incremental-verify` audit (`RelinkAudit`, the heal
  and the blocking-issue count) — join the M54 seam's phase vocabulary beside the
  pipeline's passes, and the ladder's fallback rungs join the note vocabulary
  (`LinkNote::RelinkFallback` — the full link the ladder handed over to names itself on
  the report and the timeline; one report per run: a successful ladder prints the rungs it
  ran — the warm pipeline's Passes 1–3 riding through the same `link_observed` entry the
  one-shot path uses — and a handover prints the full link's phases with the note
  leading). The M58/M61 lane refusals flip to service beside `-incremental` (the fusion
  lane `-resident -incremental` still refuses until the session's ladder joins the seam),
  and wire v42 registers the rung vocabulary in the time-report tail (the decode side
  restores a captured tail carrying the rungs; the session reports them at the next
  rung). The observation is read-only — the parity gate re-gated through the ladder (the
  observed relink patches the full link's bytes); the `trace` bench's relink groups pin
  the rung rows' render/parse price, and the `relink_timeline` consumer example walks the
  cycle (record, untouched relink, edit, patched relink) beside the round-trip gate.

### Added (M64)

- **M64** — the lane registry's names: the M63 worker lanes made the timeline
  multi-lane, and every `thread_name` metadata row still carried the one hard-coded
  `pgr link` label — a viewer could not tell the pipeline's lane from the pool's
  workers, and the §9.4 toolbox reads the timeline by its lane names.
  `TraceReport::lanes` becomes the named registry (`pgr_core::trace::TraceLane { id,
  name }`): the collector names the pipeline's thread (the first phase/note arrival)
  `pgr link` and the pool's workers `pgr parse pool N` (1-based, registration order
  among the workers — a serial-path task on the calling thread is the pipeline lane,
  not a worker; a feed with no phase or note events names every lane a worker), the
  render writes each lane's own label in its `thread_name` row, and the strict reader
  restores the labels exactly (the round-trip convention, gated on a multi-lane
  report; a foreign writer names its lanes its own way — the reader restores the
  document's labels, and the registry's own gates stay: one row per lane, ascending
  tids, non-empty labels). The `m64_named_lanes.rs` gate matrix pins the naming, the
  serial-task and pure-task-feed shapes, the render/round-trip and the refusals; the
  `trace_tasks` consumer example prints the lanes with their names.

### Added (M63)

- **M63** — the parse pool's worker-lane task spans: the M61 module doc named the future
  seam ("a worker-span seam rides the same shape with more lanes") and the §9.4 toolbox's
  per-thread goal names the reader — the parse pool's per-input parses (the M4 LPT
  schedule) ride the M54 observation seam as `pgr_core::observe::TaskEvent`s (a new
  default-no-op `LinkObserver::on_task`, the same inert-until-subscriber convention; a
  cache hit included — the load is the work the consumer waited on), each carrying the
  phase it rode in, the input's command-line name as its label, its wall time, and the
  two facts the phase event cannot carry: the thread that ran it (the timeline's lane
  registry keys on it) and the task's own arrival clock (the span's start is that clock
  minus the wall — a drain-time re-stamp would end every worker's span at the drain). The
  pool threads cannot borrow the caller's observer slot, so the parallel parse reports
  through an mpsc channel opened only when a subscriber rides (the unsubscribed link
  allocates nothing) and the caller forwards the records once the pool returns; the
  serial path reports on its own thread, and the `-r` shape rides the same `parse_inputs`
  wire-up. `TraceCollector` keeps the records as `TraceTask` spans on the workers' own
  lanes (today's `pgr link` lane beside the pool's worker lanes — the stragglers and
  idle gaps the toolbox reads), `TraceReport::finish` presents them in the timeline's
  canonical `ts` order (the drain interleaves the workers — the render's document and
  the strict reader's restore must agree; the round-trip convention, caught by the
  example's own gate and pinned in `tests/m63_task_spans.rs`), the render writes the
  task rows beside the phase spans (`ph: "X"`, the phase token, `args: {"kind":"task",
  "name":…}`) and `parse_trace_json`'s args union grows the task member beside the phase
  detail, the metadata name and the instant's reason (a mix refuses, the field named).
  The seam stays read-only: an observed-with-tasks link plans the identical image the
  unobserved one does (the parity gate, re-gated in the m63 matrix). The `trace` bench's
  collector variant carries the one-record-per-input price and the 64-task report joins
  as `render_8_rows_64_tasks`/`parse_8_rows_64_tasks`; the `trace_tasks` consumer example
  walks the worker lanes beside a twelve-object link, round-trip gate included.

### Added (M62)

- **M62** — the resident lane's served timeline (wire v41): a trace-asking request
  (`--trace` beside `-resident`) subscribes the same `TraceCollector` to the session's own
  warm run — paired with the time collector when both faces ask — and the reply's IMAGE
  tail carries the rendered document verbatim (the same one-line Trace Event Format file
  the one-shot `--trace` writes; the strict reader is the document's own face, the wire
  never re-shapes it): the served timeline names the phases the session's run actually
  executed (no `Parse` row — the POIs are resident, the parse was paid when the blobs
  arrived; the relink's Pass-4 half is the in-memory patch), and an unasked timeline never
  crosses (the tail is one byte). The client writes the served document to `--trace`'s
  path — either lane writes the same face, so the driver's resident refusal flips to
  service. The `wire_trace` bench pins the tail's encode/decode price (one length prefix,
  one string push).

### Added (M61)

- **M61** — the Chrome-trace timeline (`pgr_core::trace`, the `--trace <path>` driver
  flag): the roadmap §9.4 profiling toolbox ("`--trace` — Chrome-trace-format timeline
  per thread, so stragglers and idle gaps are visible") names the measurement surface the
  M54 observation seam already serves the raw material for — the collector
  (`TraceCollector`, an `impl LinkObserver`) subscribes to the observed pipelines
  (`link_observed` / `link_reloc_observed` / the session's warm run) and keeps every phase
  event as a span and every ladder note as an instant; `TraceReport::render` writes the
  Chrome Trace Event Format's object form (`{"traceEvents":[…]}`, one line, deterministic —
  the `process_name`/`thread_name` metadata rows lead, the spans and instants ride `ts`
  order with the arrival order stable on the ties, integer-microsecond bounds, the
  report-JSON escape rules) and `parse_trace_json` is the strict reader: it restores the
  writer's data exactly (the round-trip convention, gated) or refuses the broken shapes —
  an unknown `ph`, an unknown phase or detail token, a float timestamp, a missing or
  duplicate key, a lane no `thread_name` declared — with the byte position named. A span's
  start is the arrival clock minus the event's own wall (one emit-call behind the clock;
  saturating, never negative); the collector's lane registry keeps one lane per distinct
  arrival thread (today's pipeline renders one `pgr link` lane — a worker-span seam rides
  the same shape with more lanes). The timeline is a measurement, not a layout product: a
  traced link plans the identical image the plain link does (the parity gate), the `-r`
  shape traces its own five-phase run, and the incremental lane refuses the flag (the
  engine's ladder runs where the observer does not). The `ObserverPair` seam serves the
  time and trace faces behind one subscription when both flags ride (one event stream,
  both faces). The `trace` bench pins the seam's near-parity and the faces' O(rows)
  render/parse prices; the `trace_timeline` consumer example writes the file beside a real
  link and reads it back through the strict reader.

### Added (M60)

- **M60** — the build-system dependency record (`pgr_core::dep_info`, the
  `-dependency_info <path>` driver flag): ld64's sidecar artifact — the binary file Xcode's
  incremental builds read to learn which files a link read and which one it wrote — rides
  Peregrine in ld64's own format (`Options::writeDependencyInfo`, apple-oss-distributions ld64):
  the linker-version row leads (opcode `0x00`, the tool's identity string, NUL-terminated),
  every file the link read rides the `0x10` input family (ld64's
  object/dylib/archive/filelist/section/bundle-loader/misc names are one opcode in the field —
  objects, archives, resolved `-l`/`-framework` libraries, `-sectcreate` payloads, the
  symbol-list files, the bundle loader, the order file), every probed-but-missing search
  candidate rides `0x11` (ld64's `checkFileExists` records each miss — the search's own story,
  even when a later candidate hits), and the output — the `-map` beside it — rides `0x40`. The
  rows sort by `(opcode, path)` for build reproducibility (ld64's rdar://30750137 sort): two
  links of one command line write byte-identical records, the insert path keeps the canonical
  order with one `partition_point` memmove per row, and the strict reader restores the writer's
  data exactly (the round-trip convention, gated) or refuses the broken shapes — a foreign
  opcode, a truncated row, an empty path — with the byte position named. The record is the
  link's read set, never a plan product: it rides every lane that actually reads the input files
  (the resident lane writes it client-side from the request's own list — the daemon never
  touches the filesystem) and refuses the one that does not (`-incremental`: the relink patches
  the recorded plan and re-reads no input file, so a record naming them would misreport the
  run). A recording link plans the identical image the plain link does (the parity gate — the
  sidecar never moves a byte); non-absolute paths resolve through `canonicalize` at record time
  (ld64's `realpath` shape, one helper so every read site records the same view of one file).
  The `dep_info` bench pins the insert/render/decode prices; the `dependency_info_link` consumer
  example walks the record beside a real link, round-trip gate included. Riding the same seam:
  the `-l`/`-framework` not-found refusals name the directories they searched (the weak error
  the record's probes made visible).

### Added (M59)

- **M59** — the resident lane's served time report (wire v40): the session observes its own
  pipeline — a time-asking request (`--time` beside `-resident`) subscribes the same
  `TimeCollector` to the warm run the §7.3 ladder serves (`link_from_objects_observed` on
  both the full link and the relink), and the reply's IMAGE tail carries the collected
  report (count-prefixed phase rows — phase token, detail kind, µs — the notes, the
  present-byte + µs bands). The served table names the phases the session's run actually
  executed (no `Parse` row — the POIs are resident, the parse was paid when the blobs
  arrived); the relink's Pass-4 half is the in-memory patch, so its emit band rides absent;
  an unasked report never crosses (the tail is one byte); a client whose daemon falls back
  prints the one-shot link's own report — either way the run is observed, and the daemon
  still never touches the filesystem. The `wire_time` bench pins the tail's encode/decode
  price; the driver's resident cycle walks the served face end to end.

### Added (M58)

- **M58** — the per-pass time report (`pgr_core::time_report`, the `--time` / `--time-json`
  driver flags): the TDD's instrumentation spec ("`--time` prints a per-pass table: parse,
  intern, resolve, layout, emit/fixups, hashes, flush") and the roadmap §9.3 budgets
  ("enforced from `--time` JSON output") name the measurement surface the M54 observation seam
  serves the raw material for — the collector (`TimeCollector`, an `LinkObserver` impl)
  subscribes to the observed pipeline (`link_observed` / `link_reloc_observed`) and
  `TimeReport::render` renders the deterministic text table (phase token, the phase's own
  shape, the wall time, the permille share — integer math, no float rounding; µs below a
  millisecond, seconds beyond), `render_json` the compact interchange line (fixed key order,
  one line, the report-JSON escape rules, walls in whole microseconds). The emit band and the
  total are the caller's measurement (the driver times the fused tile emit and the pipeline
  wall); the ladder's silent-correct rungs ride the report as notes — a phase table that hid
  the resolve-reuse fallback would misread the resolve row's price. The report is a
  measurement, not a layout product: collecting never moves a byte (the parity gate is the
  seam's own contract, re-gated through the collector), the `-r` shape reports its own five
  phases with no fused-emit row, and the lane contract refuses where the observer does not
  watch (`-incremental`; the resident lane joins at M59). The `time_report` bench pins the
  collector's near-parity with the unobserved link (one push per phase — seven per segmented
  link) and the faces' O(rows) render price; the `time_report` consumer example renders the
  driver faces beside the library face.

### Added (M57)

- **M57** — the load-provenance report (`pgr_core::provenance::LoadReport`, the
  `-why_load` driver flag): the S7 archive pull's per-member decision made nameable — every
  member the fixpoint admitted names why it rode: the reference whose round reached it (the
  seed named), the `-all_load`/`-force_load` eager family, the `-ObjC` metadata pull —
  beside the member's own symbol surface (its definitions and the undefineds its pull
  opened, the next fixpoint round's food), in pull order; a member nothing reached rides
  nowhere (the "why not" half of the question). Under `-dead_strip_dylibs` every input
  dylib carries its carriage (kept binds, dropped doesn't); without the knob the dylib rows
  ride empty — every dylib rides because the command line names it. The pull records from
  data it already had (one entry per pulled member — the pass re-derives nothing), the
  report and the bytes cannot disagree, the record never changes the plan (the parity gate
  is the seam's own contract), and the same lane contract as `-why_export` holds (the wire
  stays v39). The `why_load` bench pins the pull-record and render prices (17.6 µs at 64
  members); the `why_load_link` consumer example walks the lazy pull, the eager pull and
  both faces.

### Fixed

- **fix(layout)** — the dead head-def resolution: `atom_or_section_addr`'s
  containment walked `partition_point(...).saturating_sub(1)` and subtracted
  the matched atom's start from a value that could sit *before every live
  atom's start* — a definition the dead-strip mark dropped (the section's
  head atom stripped, live atoms after it). Under overflow checks the
  subtraction panicked ("dead atoms carry no entry — nothing live references
  them" is the parse's own contract, and the containment must refuse the
  delta it cannot vouch for, not wrap); under release arithmetic it silently
  wrapped into a garbage address. The `M52 dead_strip_inits` bench's rooted
  variant was the field reproduction (CI compiles benches — `cargo bench
  --no-run` — the `cargo test --benches` gate *runs* them). The fix returns
  `None` for the unvouched delta (the caller's existing contract), the
  regression gate rides `tests/m52_no_dead_strip_inits.rs`
  (`the_dead_head_def_resolves_without_overflow`), and every pre-fix link
  that planned is byte-identical under the fix (live definitions always
  match an atom at or before their value — the `idx == 0` arm is dead-def
  only, and dead defs never reached the output).

### Added (M56)

- **M56** — the symbol-reference provenance query (`pgr_core::provenance`, the
  `-why_export <symbol>` driver flag): the M8-a reverse reference index the propagation
  planner keeps private becomes a nameable, typed answer a library consumer and the driver
  can read. A query names the definition the Pass-2 resolution installed — the input file
  and section it came from (direct object or pulled archive member, the rank and weak mark
  riding), the dylib export whose two-level bind serves it (the provider named through the
  resolution's ordinal map), or the loader's dynamic lookup — and every reference site the
  link saw: `(file, section, offset)` in the index's own ascending order, one record per
  site. `RefExplanation::render` is the diffable text face, `render_json` the deterministic
  interchange (fixed key order, one line, the report-JSON escape rules, shared with the M55
  map writer), a vacuous query refuses with the misspelling named (the C-underscore hint is
  the fix). The seam is read-only — the query consumes the link's own Pass-2 product
  (`LinkResult` carries the resolution since M56) and re-derives nothing; a queried link
  plans the identical layout (the parity gate is the seam's own contract); the resident and
  incremental lanes refuse the flag (the product never crosses the wire — the daemon wire
  stays v39). The `provenance` bench pins the index build (16.0 µs at 64 objects) and the
  query price (234 ns); the `why_export_link` consumer example renders both faces beside
  the vacuous refusal.

### Added (M55)

- **M55** — the link-map JSON interchange (`pgr_core::map`): the build-system-facing
  report ld64's `-map` serves — already a pure function of the plan (the report and the
  bytes cannot disagree) — gains the machine face: `LinkMap::render_json` renders the
  deterministic compact interchange (fixed key order, one line, the report-JSON escape
  rules — the house writer `pgr-verify`'s `report_json` rides) and `parse_link_map_json`
  is the strict reader: a rigid schema (unknown or duplicate keys refuse,
  integer-only numbers, no trailing commas, byte-positioned `MapJsonError`s) with the
  data model's own structural gate (a section's `seg_name` must name the segment it
  rode in on — `build_link_map` groups sections by their owning segment, so a foreign
  document that misfiles one refuses typed). The reader restores the writer's data
  exactly — the `to_json`/`parse_report_json` round-trip convention, gated in
  `tests/m55_map_json.rs` and the module's own tests — so a build system ships the map
  to any JSON tooling (a size dashboard, a diff gate) without a custom parser. The
  `link_map_json` bench group (write / write-read round trip) rides the map bench; the
  `map_json` consumer example renders both faces beside each other.

### Added (M54)

- **M54** — the link-pipeline observation seam (`pgr_core::observe`): the pass structure
  Passes 1–3 already name on the tracing span seam becomes a typed surface a library
  consumer subscribes to — `pgr_core::link_observed`, `link_from_objects_observed` and
  `link_reloc_observed` run the exact pipeline `link_cached`/`link_from_objects`/
  `link_reloc` run (an observed link plans the identical layout — the parity gate is the
  seam's own contract in `tests/m54_observer.rs`) with each phase's completion arriving
  in link order (`Parse → ArchivePull → Intern → Resolve → Liveness → Fold → Layout`,
  the `-r` object shape its own run) as a `PhaseEvent`: the phase's own `PhaseDetail`
  (the parse's input count, the pulled archive members, the interned names, the
  resolve's reuse split, the dead-strip engagement, the fold count, the planned
  segment/section shape — the counts the pass already had in hand, never re-derived)
  plus its wall time. The §7.3 ladder's silent-correct rungs arrive as notes
  (`LinkNote::ResolveReuseFallback` names the resolve-reuse plan/install refusal with
  its own wording — the same message the tracing seam's debug events carry). Both trait
  methods default to subscribing to nothing (the pipeline pays nothing for the silence),
  `TracingObserver` bridges every event onto the house tracing convention (inert until a
  subscriber installs), the `observer` bench pins the shape (one event per phase — seven
  per segmented link — regardless of corpus size), and the `phase_observer` consumer
  example ships the recorder face.

### Added (M53)

- **M53** — the section renames (`-rename_section <fromSeg> <fromSect> <toSeg> <toSect>`): ld64's
  flag ("Renames section orgSegment/orgSection to newSegment/newSection") joins the surface as the
  Pass-3 decision the section classification reads (`pgr_core::rename`): the first entry naming an
  input section's `(segment, name)` pair renames it before grouping — the section groups with its
  new name and lands in the new segment, the protections following the segment the way ld64's
  reader-level rename does, and two sections renamed onto one pair coalesce (the grouping is by
  name). The default (the empty map) keeps every pre-M53 link byte-identical — the classification
  pair rides every link it always did. The decision is validated, not defaulted: every name within
  the Mach-O 16-byte field width (ld64's own "segment name max 16 chars" check), a source named
  once, and a source or target the house synthesizes (`__unwind_info`, `__chain_starts`,
  `__init_offsets`, the type-merged `__common`) refuses — a renamed input joining a synthetic
  bucket would corrupt the section the synthesis speaks for; the zero-fill type rule outranks the
  map (S_ZEROFILL bytes always bucket `__common`), and a rename outside the M1 bucket trio refuses
  at layout with the segment named. There is no output-kind conflict: every linked output's
  sections ride the same buckets, and the relocatable output never reads the table (its section
  table is the input's, verbatim — the M41/M43/M47 inert-for-relocatable shape). The daemon wire
  v39 carries the map (a count-prefixed table, four names per entry, re-validated on decode); the
  `rename_sections` bench and the `rename_sections_link` consumer example ride along.

### Added (M52)

- **M52** — the dead-strip init/term roots (`-no_dead_strip_inits_and_terms`): ld64's flag ("The
  linker never dead strips initialization and termination routines") joins the surface as the
  Pass-2 decision the dead-strip root set reads: the termination-pointer sections
  (`S_MOD_TERM_FUNC_POINTERS`) join the initialization-pointer sections' whole-section root
  treatment, so a term routine nothing references survives `-dead_strip`. The default (`false`)
  keeps every pre-M52 link byte-identical — the init half has been the house default since M5
  (the flag never changes it), and an unreferenced term routine strips exactly as it did. There
  is no output-kind conflict: without `-dead_strip` the decision never fires, and the relocatable
  output strips nothing (its symbol table is the input's, verbatim — the M41/M43/M47
  inert-for-relocatable shape). The daemon wire v38 carries the decision; the `dead_strip_inits`
  bench and the `no_dead_strip_inits_link` consumer example ride along.

### Added (M51)

- **M51** — the stack-execution decision (`-allow_stack_execute`): ld64's flag ("Marks executable
  so that all stacks in the task will be given stack execution privilege", the pthread stacks
  included) joins the surface as the header decision the flag-word assembly reads: the named
  decision ORs `MH_ALLOW_STACK_EXECUTION` into the executable's header flags — the kernel maps
  the main thread's and every pthread's stack executable. The default (`false`) keeps every
  pre-M51 link byte-identical — the bit rides no image. The knob is an executable decision (the
  kernel loads a dylib or a bundle itself, the relocatable output carries no loader semantics),
  so the non-executable outputs refuse it with the fix — the layout's re-check backs the driver
  surface's refusal (the M27 `-no_pie` shape, one flag word over), and the verifier's structural
  contract names the broken shape (the bit on a non-executable image — a hostile third-party
  fixture the knob cannot plan). The daemon wire v37 carries the decision; the `stack_exec` bench
  and the `allow_stack_execute_link` consumer example ride along.

### Added (M50)

- **M50** — the weak-import refusal (`-no_weak_imports`): ld64's flag joins the surface as the
  Pass-2 decision the resolve's undefined walk reads: a weak reference (`N_WEAK_REF`) that no
  input, no dylib and no loader resolves — a bind dyld must look up at runtime — refuses the link
  with the symbol named, under the `-undefined error` lane (where weak imports used to fall to the
  lookup silently) and under `-undefined dynamic_lookup` alike. The default (`false`) keeps every
  pre-M50 link byte-identical — an unresolvable weak reference rides dyld's runtime lookup exactly
  as it did. A weak reference that *resolves at link time* — against an input definition or a dylib
  export, weak-loaded or not — is not a runtime lookup and never refuses: the knob prices the
  runtime lookup, not the weakness. The relocatable output never reads the decision (its
  undefineds stay open — the M41/M43/M47 inert-for-relocatable shape). The daemon wire v36 carries
  the decision; the `no_weak_imports` bench and the `no_weak_imports_link` consumer example ride
  along.

### Added (M49)

- **M49** — the GCC-era ObjC symbols join the `-ObjC` pull: the ledger M43's module doc drew
  closes at ld64's own matcher — the archive pull matches ranlib-index entries on the `.objc_c`
  prefix (the ObjC1/GCC-era C symbols: `.objc_class_name_<Class>` classes and
  `.objc_category_name_<Class>_<Category>` categories) beside `_OBJC_CLASS_$_` (ld64-609
  `archive_file.cpp`), so `pgr_core::objc` widens: `classify_objc_metadata` names the family
  (`ObjcFamily` — the modern class/metaclass/category forms beside the ObjC1/GCC-era pair), the
  pull admits both families, and the exclusions stay named — the protocol list
  (`_OBJC_PROTOCOL_$_` — a protocol is neither a class nor a category, and ld64's matcher reads
  neither) and the pre-2.0 method-symbol form (a method rides its class or category's metadata
  symbols). The default stays reference-driven — an unreferenced GCC-era member stays unparsed,
  every pre-M49 link byte-identical; the `objc_pre2` bench and the `objc_pre2_link` consumer
  example ride along.

### Added (M48)

- **M48** — the dylib initializer (`-init <symbol>`): ld64's flag — *"Specifies the name of an
  initializer to be called by dyld when the image is loaded"* — joins the surface as the identity
  decision the header assembly reads: the resolved initializer's image-space vaddr rides
  `LC_ROUTINES_64` (the 72-byte `routines_command_64` `pgr-format` classifies beside the 32-bit
  family; dyld's `hasInitializer` walk reads the command before the `__mod_init_func` sections),
  and the name resolves like the entry seam's — an unresolved one refuses with the `Symbol`
  error. The verifier's new routines contract gates the shapes the knob can break (a command off
  a dylib, the 32-bit opcode in a 64-bit image, an undersized command, a duplicate, an
  `init_address` naming no executable mapping). The default (`None`) keeps every pre-M48 link
  byte-identical. The knob is a dylib decision — ld64: "-init can only be used with
  -dynamiclib" — so an executable, a bundle and `-r` refuse it with the fix (the layout's
  re-check and `link_reloc` back the driver surface's refusal). The daemon wire v35 carries the
  name; the `dylib_init` bench and the `dylib_init_link` consumer example ride along.

### Added (M47)

- **M47** — the branch-island suppression (`-no_branch_islands`): ld64's knob
  (`fAllowBranchIslands`, on by default) joins the surface as the Pass-3 decision the M6 veneer
  fixed point reads: under the named suppression the layout stops planning a veneer for an
  out-of-range `B`/`BL`, and a branch the ±128 MiB `imm26` window cannot reach refuses the link
  with the site named — ld64 reports the same condition when islands are disabled. The default
  (`true`) keeps every pre-M47 link byte-identical — the veneer set stays a pure function of the
  placed addresses, and an in-range corpus plans identical bytes under both decisions. There is
  no output-kind conflict: the relocatable output resolves no branches, so `-r` never reads the
  decision (the M41/M43 inert-for-relocatable shape). The daemon wire v34 carries the decision;
  the `branch_islands` bench and the `branch_islands_link` consumer example ride along.

### Added (M46)

- **M46** — the export-dynamic roots (`-export_dynamic`): ld64's liveness rule — *"Preserves all
  global symbols in main executables during dead stripping"* (the `ld` man page) — is the decision
  the dead-strip root set reads: every global definition in the image (an `N_SECT` def or a
  common) roots the mark phase, so a plugin-style main executable keeps its unreferenced entry
  points (the `dlsym` surface is a runtime contract the static fixpoint cannot see). The default
  (`false`) keeps every pre-M46 link byte-identical. The knob is an executable decision — a
  dylib's and a bundle's strip already roots every definition (the export surface is the
  contract), and the relocatable output strips nothing (its symbol table is the input's,
  verbatim) — so all three refuse the knob with the fix (the layout's re-check and `link_reloc`
  back the driver surface's refusal). The daemon wire v33 carries the decision; the
  `export_dynamic` bench and the `export_dynamic_link` consumer example ride along.

### Added (M45)

- **M45** — the upward-dylib load (`-upward_library <path>` / `-upward_framework <name>`): ld64's
  umbrella-relationship mark — the opcode `pgr-format` has decoded since M0
  (`LC_LOAD_UPWARD_DYLIB`, the weak/upward/lazy family in the load-command reader) but no
  producer could name — joins the surface as the fourth load-command kind
  (`pgr_core::resolve::Dylib::upward`). The command rides the two-level ordinal space exactly
  like a plain load (dyld's own rule — the verifier's walk and pair gate count it), the mark
  names the family of a plain load only (a lazy, weak or re-export load keeps its command — the
  obligations outrank the mark), and the driver's flags name one kind per path. The framework
  form resolves through the `-F` search after the lazy frameworks (the LC order — and with it
  the two-level ordinals — is plain, re-export, weak, lazy, then upward); an empty list leaves
  every pre-M45 link byte-identical. The daemon wire v32 carries the kind (one byte per dylib
  beside weak/re-export/lazy — the M14 lazy-byte convention); the `upward` bench and the
  `upward_library_link` consumer example ride along.

### Added (M44)

- **M44** — the dylib-identity default (`-final_output`): ld64's flag — previously unknown on
  the surface — supplies the install name a dylib link derives when `-install_name` is absent
  (the `ld` man page: "Specifies the install name of a dylib if -install_name is not used" —
  the multi-arch driver names the universal path so every arch slice records it instead of
  its own `-o` path). An explicit `-install_name` wins (the man-page rule). The default (flag
  absent) keeps every pre-M44 link byte-identical: the derived install name stays the `-o`
  path. Executables, bundles and the relocatable output refuse the knob with the fix (the
  identity rides `LC_MAIN`, a bundle dlopens without a region, the object carries no identity
  commands). The `final_output` bench and the `final_output_link` consumer example ride along.

### Added (M43)

- **M43** — the ObjC archive pull (`-ObjC`): the flag the surface carried as a later item
  since M6 is the Pass-0 liveness decision the archive pull reads — archive members
  implementing an Objective-C class or category ride the pull without a reference (the
  modern clang emitter names a class with `_OBJC_CLASS_$_`/`_OBJC_METACLASS_$_` and a
  category with `_OBJC_CATEGORY_$_`; the ObjC runtime registers the metadata by section
  address at load time, so no static reference exists to seed the S7 fixpoint — the decision
  rides the ranlib index every link already parses, a member whose index entry names the
  metadata family joins the pull in member file order, and its own undefineds continue the
  fixpoint). The default (`false`) keeps every pre-M43 link byte-identical: the pull stays
  reference-driven and the unreferenced member stays unparsed. A member defining none of the
  metadata names is not pulled by the knob (the rule is class-or-category, not `-all_load`).
  There is no output-kind conflict — the relocatable output consumes pulled members exactly
  like a segmented one, so `-r` rides the same pull. The daemon wire v31 carries the
  decision; the `objc` bench and the `objc_link` consumer example ride along. The dead
  `LATER_FLAGS` entry that outlived `-dylinker`'s M26 release left with the promotion (the
  explicit arm won the match first — the entry shadowed nothing), and the M34 `unwind` bench
  gained the `[[bench]]` entry its file always implied (auto-discovery compiled it under the
  libtest harness, whose generated main shadowed the criterion one).

### Added (M42)

- **M42** — the unused-dylib drop (`-dead_strip_dylibs`): ld64's flag — previously unknown on
  the surface — is the Pass-2 decision the resolve reads: every input dylib no referenced name
  binds against *as it is linked* leaves the header (the two-level bind names its provider — a
  dylib whose exports nothing references cannot serve a bind), and the kept list compacts the
  two-level ordinals onto it (symtab `n_desc` rows, the chained-fixups import table and the
  classic opcode binds all read the compacted table). The default (`false`) keeps every
  pre-M42 link byte-identical: every input dylib rides its `LC_LOAD_DYLIB` command regardless
  of use. The re-export dylibs always ride (their `LC_REEXPORT_DYLIB` command is an identity
  obligation and their REEXPORT nodes join the export trie), and every dylib a dynamic-lookup
  reference could reach rides (the flat bind names no provider — the loader may reach any
  loaded image's exports). The knob is a Pass-2-to-3 decision — the relocatable output refuses
  it (the object carries no load commands), `-flat_namespace` refuses it (the flat bind names
  no provider), and `link_reloc` re-checks so no library caller can plan the shape either.
  The daemon wire v30 carries the decision; the `dead_strip_dylibs` bench and the
  `dead_strip_dylibs_link` consumer example ride along.

### Added (M41)

- **M41** — the dedup toggle (`-no_deduplicate`): the flag the surface carried as an accepted
  no-op since M7 is the Pass-3 decision the D4 piece builder reads — identical literals stop
  merging, every input `S_CSTRING_LITERALS` section rides the output verbatim (one
  whole-section piece per input, every symbol on its own instance — the pre-D4 shape). The
  default (`true`) keeps every pre-M41 link byte-identical (the M5/D4 merge and its remap
  unchanged). The knob is a Pass-3 decision — never a parse blindfold: the parse still splits
  cstring sections into atoms (liveness and the POI cache are flag-independent), dead-strip
  still drops dead literals under either decision, and there is no output-kind conflict (the
  relocatable output never engaged the merge). Riding the same seam, the symtab's
  output-section lookup now resolves a definition whose input section merged away *entirely*
  (every atom a duplicate — no piece of its own remains) through its remapped address
  instead of shipping the `n_sect 0` row the symtab contract refuses. The daemon wire v29
  carries the decision; the `no_deduplicate` bench and the `no_deduplicate_link` consumer
  example ride along.

### Added (M40)

- **M40** — the export-trie suppression (`-no_exported_symbols`): the last always-carried
  `__LINKEDIT` command the surface could not name (`LC_DYLD_EXPORTS_TRIE`, hard-wired since
  M2) drops on the named decision — no `__LINKEDIT` slot, no trie bytes, `sizeofcmds` 16
  bytes narrower — and the image verifies strict (absence is the decision, never a defect;
  the M31/M32/M36 always-carried-family shape). The default (`true`) keeps every pre-M40
  link byte-identical. The knob is an executable decision: a main executable's trie is the
  `dlsym`/debugger surface, a dylib's trie *is* the two-level contract its clients bind
  through and a bundle's the dlopen surface — a dylib, a bundle and `-r` refuse the knob
  with the fix, and a link carrying re-export dylibs refuses (the REEXPORT nodes ride the
  trie). The classic `-no_fixup_chains` path plans the same suppression; the verifier's
  dylib contract gates the trie-less foreign shape; the daemon wire v28 carries the
  decision; the `exported_symbols` bench and the `no_exported_symbols_link` consumer
  example ride along.

### Added (M39)

- **M39** — the make-undefined mark (`-U <symbol>`): the flag the surface carried as a later
  item since M2 is the Pass-2 decision the definition install reads — the named symbol's
  definition (`N_SECT` or common) never installs *as it is linked*, so the symtab row, the
  export-trie node and the `__common` slot drop and the defining atom loses its liveness root
  (`-dead_strip` drops the body nothing references anymore), and the stripped references follow
  the `-undefined` policy like any unresolved name (a dynamic lookup under `-undefined
  dynamic_lookup`; the vacuous refusal names the misspelling under the default). The empty table
  keeps every pre-M39 link byte-identical; the marks ride the resolve-reuse replay (a relink
  strips like the full walk); the relocatable output refuses the knob; the daemon wire v27
  carries the names; the `make_undefined` bench and the `make_undefined_link` consumer example
  ride along.

### Added (M38)

- **M38** — the install-name auto-floor (`-headerpad_max_install_names`): the flag the
  surface carried as a later item since M29 is the decision the packing loop reads — the
  reserved header region grows past its natural size by every load-dylib command's room to
  grow its install name to the longest install name in the image (+1 NUL, 8-byte aligned;
  `pgr_core::header_pad::install_names_growth` is the public seam), the space
  `install_name_tool` needs to rewrite any install name in place. The default (`false`)
  keeps every pre-M38 link byte-identical; a single-name surface plans zero growth; the
  floor composes with `-headerpad` (both are minimums — the bigger wins); the relocatable
  output refuses the knob; the daemon wire v26 carries the decision; the `headerpad_max`
  bench and the `headerpad_max_install_names_link` consumer example ride along.

### Added (M37)

- **M37** — thread-local variables (TLV): the input `S_THREAD_LOCAL_*` sections the
  pipeline rejected since M5 ride the atom map onto the output `__DATA` segment — the
  `__thread_vars` descriptors (16-byte thunk/initializer pairs; a section off the stride
  refuses at parse with the fix), the `__thread_data` initializers, the `__thread_bss`
  zero-fills (VM-only, their own section — never merged into `__common`). The
  `ARM64_RELOC_TLVP_LOAD_PAGE21`/`PAGEOFF12` descriptor loads decode
  (`RelocKind::TlvpLoadPage21`/`TlvpLoadPageOff12`) and patch ADRP/scaled-LDR-imm12
  directly against the descriptor's vaddr — no GOT slot, the descriptor is always a local
  definition; a descriptor load past this image's definitions refuses with the fix
  (thread-local variables cannot bind across a dylib boundary). The descriptor slots ride
  chained fixups (the thunk's bind, the initializer's rebase) and the header declares
  `MH_HAS_TLV_DESCRIPTORS` exactly when the image carries a thread-local section. The
  verifier's `tlv` family joins the `--checks` registry (`Check::Tlv`, code `tlv` — the
  marker/section parity, the descriptor stride, the descriptors' thread-local data); the
  relocatable output round-trips the surface (`-r` keeps the sections and re-encodes the
  TLVP pair, the object links again); the POI cache parser revision bumps to v2 (the
  zero-fill reclassification self-heals stale entries); the `tlv` bench and the `tlv_link`
  consumer example ride along.

### Added (M36)

- **M36** — the compact-unwind suppression (`-no_compact_unwind`): the output
  `__TEXT,__unwind_info` section drops on the named decision (`LinkConfig::compact_unwind`,
  the default `true` keeping every pre-M36 link byte-identical) — no synthetic piece, no
  section slot, the pre-M34 bytes exactly and byte-identical to the entry-free link (the
  file-size delta rides the 16 KiB segment congruence). The suppression is a Pass-3
  decision — never a parse blindfold: the parse still validates the table, and a broken
  table refuses with the knob set; the relocatable path never engages the carriage (no
  output-kind conflict); an incremental knob flip lands on the relayout rung's correct
  image and the record renews so the cycle never stalls; the daemon wire v25 carries the
  decision; the `no_compact_unwind` bench and the `no_compact_unwind_link` consumer example
  ride along.

### Added (M35)

- **M35** — compact-unwind compressed second-level pages: the density rung past the M34
  regular pages. A translated row rides the compressed second-level family
  (`UNWIND_SECOND_LEVEL_COMPRESSED`) exactly when it qualifies — its output offset fits the
  compressed entry's 24-bit field and its final encoding word (the personality index folded
  in) sits in the section-level common encodings array — and consecutive same-family rows
  share a page (a page never mixes families). The common array gathers the distinct final
  words in first-use order over the offset-qualifying stream, capped at the compressed
  entry's 8-bit index space (`pgr_core::unwind::MAX_COMMON_ENCODINGS` = 256); the
  compressed page's own page-local encodings array rides empty (the two-tier decode
  libunwind runs answers at tier one, and the verifier walks both tiers). The planning seam
  grows with the rung: `pgr_core::unwind::plan_shape` names the shape a table plans into
  (array counts, page count, compressed pages) and `synthesized_size_shape` sizes it with
  the builder's one formula; `synthesized_size` stays exact for the tables that plan the
  pre-M35 shape (no row qualifies). A 4096-row table over one encoding plans half the M34
  bytes. The verifier's `unwind` family walks the compressed pages (bounds behind the
  12-byte page header, the two-tier index resolution, sorted offsets, `__TEXT` bounds, the
  common rows' own mode/personality contract) and the `unwind_compressed` bench plus the
  `compact_unwind_compressed_link` consumer example ride along.

### Changed (M35)

- The `__unwind_info` section shape for tables whose rows qualify: qualifying rows ride
  compressed second-level pages through the common encodings array (the header's
  `commonEncodingsArrayCount` is nonzero now), shrinking the section up to 50 % for
  single-encoding tables; tables whose rows all sit past the 16 MiB `__TEXT` mark or past
  the encoding cap plan the pre-M35 bytes verbatim. `UnwindInfo` gained
  `compressed_page_count`. The M34 regular-page shape remains the fallback family the
  verifier walks beside the compressed one.

### Added (M34)

- **M34** — compact-unwind synthesis: the input `__LD,__compact_unwind` tables the Pass-1
  sweep kept dropping (the `S_ATTR_DEBUG` section the `__LD` skip hid) now ride the atom map
  onto the output `__TEXT,__unwind_info` — the section dyld's unwinder and every backtrace
  reader walks. The format reader (`pgr_format::read_compact_unwind`) decodes the table with
  typed refusals; the parse validates it against the object's sections (a range the object
  cannot vouch for, a dangling personality/LSDA reference, a zero-length or duplicate range
  refuse with the fix); the carriage translates through the placed piece list (dead-stripped
  functions drop their rows, ICF-folded duplicates land once on the canonical copy, the
  personality/LSDA references root their targets under `-dead_strip`); `pgr_core::unwind::synthesize`
  builds the section (personality rows in first-use order, the sorted index with its terminator,
  regular second-level pages under the 4096-entry cap, the LSDA rows sorted) — the public seam a
  build system plans with before any link runs. An entry-free corpus plans the pre-M34 bytes (no
  section at all); the relocatable output never engages the carriage; the POI cache codec carries
  the parsed rows (v5; stale entries self-heal); the verifier's `unwind` family joins the
  `--checks` registry (`Check::Unwind`, code `unwind_info`) and gates the broken shapes; the
  `compact_unwind` bench and the `compact_unwind_link` consumer example ride along.

### Added (M32–M33)

- **M32** — the UUID suppression (`-no_uuid`): the third advisory no-op promoted — the output's `LC_UUID` command drops on the named decision (24 bytes narrower, no uuid field for the emit two-pass derivation to patch); the emit patch paths consult the plan offset's absent sentinel (`0`, the `__LINKEDIT` offset convention); the verifier's absence warning names the decision, never a defect; daemon wire v23 carries the decision; the `uuid` bench and the `no_uuid_link` consumer example ride along.
- **M33** — the private-extern decision (`-keep_private_externs`): the input `N_PEXT` bit the tree dropped at parse is carried now — the default converts a private-extern definition into the locals range (`N_SECT | N_PEXT`, the filter-hidden shape, absent from the trie) and the named keep holds it external (`N_EXT | N_SECT | N_PEXT`, exported); the POI cache codec carries the bit (v4; stale entries self-heal); the verifier's symtab contract gates the extdef-range agreement; daemon wire v24 carries the decision; the `keep_pext` bench and the `keep_private_externs_link` consumer example ride along.

### Documentation
- The M20 umbrella rows the 0.23.0 sweep missed (the region's README, TDD,
  compat and bench commits postdate that section)
- The M26–M29 rows backfilled from their milestone commits (the README's
  status and examples carry M26 through M29, the compat table's
  driver-flag rows, the TDD trailer's design entries, the bench
  inventory's recording pass)

### Features
- **driver:** The -sectalign and -headerpad flags shape the config (M28, M29)
- **driver:** The -dylinker and -no_pie flags shape the config (M26, M27)
- **core:** The packing loop plans the named decisions (M28)
- **core:** The header-pad decision joins the core surface (M29)
- **core:** The layout plans the loader path and the PIE decision (M26, M27)
- **core:** The sect-align and header-pad surfaces re-export their decisions (M28, M29)
- **daemon:** Wire v17 carries the loader and v18 the PIE byte (M26, M27)
- **daemon:** Wire v19 carries the floors and v20 the floor (M28, M29)
- **verify:** The loader-path and congruence/header-region contracts land (M26–M29)
- **fixtures:** The builder names the loader, the PIE bit and the header reservation (M26–M29)
- **format:** The data-in-code stream reader joins the commands (M30)
- **fixtures:** The object builder names the data-in-code entries (M30)
- **fixtures:** The image builder emits the data-in-code payload (M30)
- **core:** The parse carries the input data-in-code streams (M30)
- **core:** The layout plans the data-in-code carriage (M30)
- **driver:** The -no_data_in_code flag names the suppression (M30)
- **daemon:** Wire v21 carries the data-in-code suppression (M30)
- **verify:** The data-in-code contract gates the broken shapes (M30)
- **core:** The function-starts suppression joins the crate surface (M31)
- **driver:** The -no_function_starts flag names the suppression (M31)
- **daemon:** Wire v22 carries the function-starts suppression (M31)
- **format:** The sub-client opcode joins the constants (M21)
- **core:** The sub-client seam joins the crate surface (M21)
- **core:** The layout plans the client list and refuses the rest (M21)
- **driver:** The -sub_client flag names the clients and refuses the rest (M21)
- **daemon:** Wire v14 carries the named clients (M21)
- **daemon:** The version gate reads wire v14 (M21)
- **verify:** The identity-block contract checks the client namespace (M21)
- **fixtures:** The builder names the sub clients (M21)
- **driver:** The sub-client consumer example walks both images (M21)
- The M20 umbrella work rides unreleased too (wire v13, the region seam,
  the verifier's region contract, the `umbrella_link` example)
- **format:** The dyld-environment opcode joins the constants and the
  crosscheck (M22)
- **format:** The load-command walk classifies the environment command (M22)
- **core:** The dyld-environment seam joins the crate surface (M22)
- **core:** The layout plans the pair list and refuses the rest (M22)
- **driver:** The -dyld_env flag names the pairs and refuses the rest (M22)
- **daemon:** Wire v15 carries the named pairs (M22)
- **daemon:** The version gate reads wire v15 (M22)
- **verify:** The environment contract gates the broken shapes (M22)
- **fixtures:** The builder exports the dyld pairs (M22)
- **driver:** The dyld-env consumer example walks both images (M22)
- **driver:** The -reexport_framework flag names the re-exports (M23)
- **driver:** The re-export frameworks resolve through the -F search (M23)
- **driver:** The reexport-framework consumer example walks the story (M23)
- **core:** The symbol-alias seam joins the crate surface (M24)
- **core:** The layout plans the alias table and refuses the rest (M24)
- **driver:** The -alias flag names the aliases and refuses the rest (M24)
- **daemon:** Wire v16 carries the named pairs (M24)
- **verify:** The symtab contract gates the duplicate external name (M24)
- **driver:** The alias consumer example walks the story (M24)
- **format:** The loader export surface is one shared reader (M25)
- **core:** The bundle-loader seam joins the crate surface (M25)
- **core:** Pass 2 installs the loader surface and the binds ride 0xFF (M25)
- **driver:** The -bundle_loader flag names the host and refuses the rest (M25)
- **verify:** The bundle-loader pair gate replays the 0xFF binds (M25)
- **fixtures:** The builder builds bundle images (M25)
- **driver:** The bundle-loader consumer example walks the story (M25)

### Performance
- **core:** The data-in-code bench joins the bench table (M30)
- **core:** The function-starts bench joins the bench table (M31)
- **core:** Bench the data-in-code carriage's shape parity (M30)
- **core:** Bench the function-starts suppression's shape parity (M31)
- **core:** The dylinker, pie, sect-align and header-pad benches join the bench table (M26–M29)
- **core:** Bench the client list's per-decision parity (M21)
- **core:** The dyld-env bench joins the bench table and records parity (M22)
- **core:** The alias bench joins the bench table and records parity (M24)
- **core:** The bundle-loader bench joins the bench table and records parity (M25)

### Tests
- **core:** The data-in-code gates ride the carriage and the refusals (M30)
- **driver:** The data-in-code surface gates links and the wire (M30)
- **verify:** The data-in-code contract gates the broken shapes (M30)
- **core:** The function-starts gates ride the suppression (M31)
- **driver:** The function-starts surface gates links (M31)
- **core:** The loader and PIE seams gate the plan and the refusals (M26, M27)
- **core:** The sect-align floors gate the plan and the refusals (M28)
- **core:** The header pad gates the reservation and the refusals (M29)
- **core:** The client seam gates the plan and the refusals (M21)
- **driver:** The client surface gates links and the wire (M21)
- **verify:** The client contract gates the broken shapes (M21)
- **core:** The env seam gates the plan and the refusals (M22)
- **driver:** The env surface gates links and the wire (M22)
- **verify:** The env contract gates the broken shapes (M22)
- **driver:** The reexport-framework gates ride the search and the trie (M23)

## [0.23.0] - 2026-11-11
### Build
- **core:** The image-base bench joins the bench table (1270de5)

### Documentation
- Record the M19 image-base bench numbers (65496b2)
- The TDD trailer points at M19 (e85b5f7)
- The compat table carries the -image_base row (d3cfda2)
- The README carries M19 and the 0.22.0 badge (5d8346f)

### Features
- **core:** The image base is a nameable dylib decision (17f19da)
- **core:** The constant-delta resolver reads the named base (a8f3bbc)
- **core:** The layout plans the named dylib base and refuses the rest (c5b88cc)
- **core:** The image-base seam joins the crate surface (6641954)
- **driver:** The -image_base flag names the base and refuses the rest (b126b4c)
- **daemon:** Wire v12 carries the named image base (280626a)
- **daemon:** The version gate reads wire v12 (9559482)
- **verify:** The base contract checks the invariant, not the constant (507a091)
- **fixtures:** The builder names the dylib image base (27dbda3)
- **driver:** The image-base consumer example walks both images (c894073)

### Performance
- **core:** Bench the image base's per-decision parity (3d4a35b)

### Refactor
- **core:** The relocatable gate reads the one base resolver (9306576)
- **core:** The pagezero gates ride the extended resolver (3fb774d)

### Tests
- **core:** The image-base seam gates the plan and the refusals (2c05d21)
- **driver:** The image-base surface gates links and the wire (b6c2af7)
- **verify:** The base contract gates the broken shapes (458d854)

## [0.19.0] - 2026-11-10
### Build
- **core:** The filter and dylib benches join the manifest (1955c34)

### Documentation
- Record the M14 filter and dylib-surface numbers (625fa64)
- The TDD trailer points at the M14 surfaces (b401987)
- Migration's released flags leave the rejected list (782b069)
- The README carries the M14 rows and the 0.18.0 badge (bdc5da0)
- The compat table carries the M14 rows (df71f66)
- **verify:** The dylib walk names the lazy command (21375e2)
- **format:** The lazy constant notes its absent REQ bit (b540a28)

### Features
- **driver:** The lazy link's consumer example rides (078f6b7)
- **driver:** The glob filter's consumer example rides (fd09fa2)
- **format:** The lazy-load command decodes as a dylib command (c3e0049)
- **daemon:** Protocol v7 carries filter patterns and lazy kinds (5d490b0)
- **driver:** The weak and lazy dylib flags parse repeatable (0554cac)
- **driver:** The driver parses filter patterns and lazy flags (1135f4b)
- **core:** The layout reads pattern filters and lazy loads (6383b94)
- **core:** The dylib input names its lazy-load kind (d3be52c)
- **core:** The export filter seam joins the crate root (190ee00)
- **core:** The export filter names its symbol patterns (f484c93)

### Performance
- **core:** Bench the dylib surface's kind parity (aa55d4b)
- **core:** Bench the export filter's per-family match cost (6cbb789)

### Refactor
- **core:** The fold caller drops the interner argument (455929d)
- **core:** Icf folds without the unused interner parameter (4064fcd)

### Tests
- **driver:** The lazy and weak flags gate their commands (f138449)
- **driver:** The glob filter gates the surface and the wire (0bc36aa)
- **core:** The glob seam gates parse, match and visibility (39cdf34)
- **driver:** The m3 filter gates construct pattern lists (fb64937)
- **emit:** The fused filter gates construct pattern lists (43a2ec3)
- **emit:** The relink gates carry the lazy field (3932c4e)
- **core:** The reuse gates carry the lazy field (2d7ab62)
- **core:** The cache gates carry the lazy field (57a98a8)
- **daemon:** The version gate asserts the v7 wire shape (f57d2ee)


## [0.18.0] - 2026-11-10
### Build
- **deps:** The lock carries the dev-surface additions (ea5798f)
- **emit:** The record bench joins the crate manifest (4c7b609)
- **verify:** The baseline bench joins the crate manifest (28ab642)

### Documentation
- Record the M13 baseline and record-inspector numbers (a68f1d8)
- The TDD trailer points at the M13 report surfaces (ca5c34f)
- The README carries the M13 rows and the 0.17.0 badge (602671e)
- **core:** The chain-format field's doc link resolves by path (971c006)

### Features
- **driver:** The CLI answers --print-record before the link (d78eec4)
- **driver:** The record query joins the driver surface (f2bcdc5)
- **emit:** The record summary opens the crate's example surface (a18e9a5)
- **emit:** The record read surface joins the emit root (d1c3890)
- **emit:** The record inspector wires into the incremental engine (c726dd0)
- **emit:** The link record reads back as a typed summary (2e92b39)
- **verify:** The baseline gate gets its consumer example (0f3eaae)
- **verify:** The verifier CLI gates on a baseline (cdab2b8)
- **verify:** The report surfaces wire into the library root (e987b2a)
- **verify:** The baseline delta classifies a relink's findings (30325db)
- **verify:** The report JSON learns its library reader (2b7f159)

### Performance
- **emit:** Bench the record inspector's read cost (28b518e)
- **verify:** Bench the baseline gate's per-policy cost (c9f71d0)

### Tests
- **driver:** The --print-record surface gates its exit codes (b2631fa)
- **emit:** The record inspector gates the frame layers (2edb141)
- **verify:** The baseline gate gates round-trips, deltas, policies (32c9d03)


## [0.17.0] - 2026-11-10
### Build
- **verify:** The checks bench joins the crate manifest (2abde88)

### Documentation
- Record the M12 selective-surface baselines (42eaf8c)
- The TDD trailer points at the real frontier (0544c62)
- Migration's rejected list releases -order_file (3b3a452)
- The README carries the M12 rows (12217b7)

### Features
- **verify:** The selective surface gets its consumer example (5b4d701)
- **verify:** The verifier CLI selects its families (1b60840)
- **verify:** The selective surface wires into the library root (09018b9)
- **verify:** The ImageCheck registry names the check families (c95ce74)
- **verify:** The parsed image joins the public seam (bd48119)

### Performance
- **verify:** Bench the selective surface's per-family cost (fc8ed18)

### Tests
- **verify:** The selection surface gates parity and isolation (9a771c9)


## [0.16.0] - 2026-11-10
### Bug Fixes
- **verify:** The pair replay matches ordinals through lib_ordinal (4ff3dd4)
- **verify:** The chain-starts mirror reads the right section table (7bd8337)
- **fixtures:** The minimal trie exports every defined symbol (c2cac09)
- **format:** The arm64e family honors dyld's bit layout (29ddc5d)

### Build
- **core:** Register the order and map benches (631160b)

### Documentation
- Record the M11 bench baselines (a4fc81c)
- The README carries the M11 rows (7547b36)
- The not-milestones line names what M11 shipped (61dd84f)
- The compat table carries the M11 flag rows (50f0e89)

### Features
- **driver:** The link map gets its consumer example (238f26c)
- **driver:** The order file gets its consumer example (a78bfc3)
- **driver:** The driver ranks, warns and writes the map (88366cf)
- **driver:** -order_file and -map join the flag surface (5c03334)
- **core:** An order file rides the atom split like dead-strip (8f17e16)
- **core:** The layout ranks ordered pieces as a stable sort (7f456f0)
- **core:** Wire the order and map modules into the library root (2bab54d)
- **core:** Render the placed image's link map (fd948e8)
- **core:** Parse the order file into a rank table (adcc5c3)

### Performance
- **core:** Bench the link-map report (d97685f)
- **core:** Bench the order-file rank seam (8f4c426)

### Refactor
- **core:** The packer drops its redundant casts (27a2b13)
- **daemon:** The v6 wire decodes an order-free config (d6598d6)

### Tests
- **verify:** The advisory vehicle carries no fixup slots (8611be6)
- **driver:** The -map surface gates its report and its refusals (a2e25af)
- **driver:** The order-file surface gates its ranks and refusals (d8d67ce)
- **core:** The link map gates its rows and its determinism (8fd67f2)
- **core:** The order file gates its parse and its ranks (bf1d12f)

### Style
- **core:** The producer example rides the fmt pass (b763575)
- **driver:** The platform-floor example rides the fmt pass (6478e4c)
- **driver:** The fixup-chains-auth example rides the fmt pass (88f3b64)
- **driver:** The encoding-query example rides the fmt pass (566396e)
- **driver:** The chain-format-floor example rides the fmt pass (e8f2be9)
- **driver:** The arm64e pair example rides the fmt pass (95f0ef0)
- **verify:** The walk example rides the fmt pass (3c96895)
- **verify:** The platform bench rides the fmt pass (7361206)
- **verify:** The arm64e bench rides the fmt pass (83506ce)
- **driver:** The encoding-query test rides the fmt pass (a2ee058)
- **driver:** The arm64e surface tests ride the fmt pass (97f397b)
- **verify:** The pair test rides the fmt pass (7fa1a1e)
- **verify:** The family read-side tests ride the fmt pass (dad2b71)
- **core:** The producer test rides the fmt pass (ac7d16d)
- **core:** The family tests ride the fmt pass (59d4f2e)
- **fixtures:** The auth-slot tests ride the fmt pass (6c7040b)
- **verify:** The structural gate rides the fmt pass (212572b)
- **verify:** The dyld walk rides the fmt pass (b80be9f)


## [0.15.0] - 2026-11-10
### Documentation
- Record the rung 4 slice 4 and heal the drift (9673372)

### Features
- **driver:** The arm64e pair gets its consumer example (2473ccd)
- **verify:** The pair gate walks the arm64e family (d9ebbf4)

### Performance
- **verify:** Bench the arm64e pair replay (3711fe8)

### Refactor
- **verify:** The mirror gate drops its dead word (377082e)

### Tests
- **verify:** The arm64e pair gates its binds (f2e4eed)


## [0.14.0] - 2026-11-10
### Bug Fixes
- **driver:** The resident refusal names the v6 wire (8c3170a)

### Documentation
- Record the rung 4 slice 3 and heal the drift (edb927b)

### Features
- **driver:** The auth producer gets its consumer example (e93ec5e)
- **core:** The arm64e producer plans auth words (c7b7814)

### Miscellaneous Tasks
- **deps:** Pgr-emit rides the workspace table (b729598)

### Performance
- **core:** Bench the auth word family (8107113)

### Refactor
- **driver:** The daemon fallbacks speak spans (1528c4a)

### Tests
- **core:** The auth producer gates their shapes (c86df11)


## [0.13.0] - 2026-11-10
### Bug Fixes
- **fixtures:** The chain build names its empty-slot refusal (29d96dc)

### Documentation
- Heal the v0.12.0 drift and record the rung 4 slice 2 (f23744e)

### Features
- **core:** The arm64e producer gets its consumer example (a873f09)
- **daemon:** The wire carries the chain word family (c9116fd)
- **driver:** The fixup-chains-format flag and its honest refusals (6d5c90f)
- **core:** The chain planner speaks the arm64e word family (b8c3158)

### Performance
- **core:** Bench the arm64e word-family planner (4e374af)

### Tests
- **driver:** The arm64e flag gates its links (d19a10d)
- **core:** The arm64e producer plans gate their shapes (ff3de8b)


## [0.12.0] - 2026-11-10
### Bug Fixes
- **emit:** The writer thread names its panic payload (2b4006c)

### Documentation
- The surface records rung 4 slice 1 and heals the changelog (2b0a2d9)

### Features
- **verify:** The arm64e walk gets its consumer example (b1a12f8)
- **verify:** The chain walk strides the arm64e family (c1d527a)
- **fixtures:** The builder speaks the arm64e pointer format (f0a8ed9)
- **format:** The arm64e chain words decode and encode (d7aa5d2)

### Performance
- **verify:** Bench the arm64e strict pass (c660a3f)

### Tests
- **verify:** The arm64e read side gates its shapes (f8ed42d)


## [0.11.0] - 2026-11-10
### Bug Fixes
- **core:** The resolve-reuse fallback names its refusal cause (364ef9e)

### Documentation
- Record the rung 3 slice 2 across the surface (8c5c018)

### Features
- **driver:** The encoding query gets its consumer example (b4109c0)
- **driver:** The encoding query and the honest refusal hints (2b63b4a)
- **fixtures:** The image builder takes its build version (2a22a5c)
- **verify:** The build-version gate checks the chained-fixups floor (ecdf3e6)

### Performance
- **verify:** Bench the platform floor gate (cd0792c)

### Refactor
- Drop the dead public seams (fab339c)
- The floor table moves beside the platform constants (ec18b8a)

### Tests
- **verify:** The floor gate matrix rides the builder knob (5a48cb6)
- **driver:** The encoding query answers before the link (20f8c5c)



> **Release-ladder reconciliation (2026-11-09).** The headings below used to
> follow the design-doc milestone stream (0.7.0 → 1.2.0 for M6 → M9 v1), but
> the published tags compressed that stream: everything through the M9 v1
> engine shipped squashed in **v0.2.0**; the M9 GA tiers then shipped as
> **v0.3.0** (the per-symbol propagation planner), **v0.4.0** (the
> segment-relayout tier), **v0.5.0** (the GA hardening pass) and **v0.6.0**
> (tier 2c, the resolve's record-side wiring, the resident fusion wire rung
> and the audited fusion rung). The prose is unchanged; only the section
> structure now matches the published tags (v0.2.0–v0.10.0; Cargo.toml
> carries 0.10.0).

## [0.10.1] - unreleased slot (retitled: this section sat stray between [0.11.0] and [0.10.0], a generation artifact — its position's own version)

### Features

- **driver:** the chain format refuses the below-floor target — an
  explicitly named `-fixup_chains_format` (either spelling) refuses when
  the `-platform_version` target sits below the platform's chained-fixups
  floor: the layout would plan the classic opcode streams and the named
  family would never reach the image (a refusal, never a silently dropped
  knob, M10 rung 4 slice 5). The decision reads the same consumer seam
  the encoding query answers from, the refusal renders its fix as miette
  help text, the flag's other refusals (classic path, resident session,
  `-r`) ride the same typed variant with fitting help, and the
  `chain_format_floor` consumer example walks the whole story — the
  pre-link advisory, the refusal, the silent fallback, the above-floor
  link, every image strict-verified.

### Bug Fixes

- **fixtures:** the auth slots ride the import table — the arm64e builder
  registered only plain binds in the fixup import table, so any
  auth-bind slot refused with "bind name missing from import table";
  auth binds register their import (table addend 0 — the word has no
  addend field), and the indirect symbol table covers all four slot
  kinds (auth binds carry their symbol's output index, auth rebases ride
  `INDIRECT_SYMBOL_LOCAL`, mirroring their plain twins).
- **daemon:** the wire-version gate names v6 — the unit gate still
  asserted the v5 protocol constant after the v6 chain-word-family byte
  shipped.
- **driver:** the usage line names the real spelling — `--help`
  advertised `-print-fixup-encoding` while the binary intercepts
  `--print-fixup-encoding`, and the `-incremental-verify` help line
  re-gains its word order.

### Refactor

- the sweep drops the dead weight — the emit relocation test's orphaned
  `EmitError::Internal` construction, the daemon reply's duplicated
  error arms (and the `SessionError` import they alone kept alive), the
  session's duplicated untouched-branch comment and the `( surfaced`
  typo.

### Tests

- **fixtures:** the auth slots gate their table — an auth-bind-only
  arm64e image builds, its import table carries the bind, the payload
  re-parses through the format layer with the ordinal and the
  `DYLD_CHAINED_IMPORT` format in place, the words decode back through
  the arm64e codec, the mixed auth-rebase/auth-bind shape keeps both,
  and a plain-bind control pins the M2 behavior.
- **driver:** the floor gate refuses the explicit family — both
  spellings, both families, all five linked platforms one row below
  their floors, the target and floor displayed, the miette help naming
  the flag; the flag-less below-floor link keeps the silent
  classic-stream fallback (strict-verified), the above-floor arm64e link
  stays chained (strict-verified), and `-r` keeps its own refusal
  wording below the floor.

### Documentation

- record the rung 4 slice 5 and heal the drift: the README badge and
  status catch up to v0.15.0 and the status paragraph records the slice,
  the benchmarks page's title/status stop lagging at M5, COMPAT's two
  stale ❌ rows retire (archive members and full export tries were
  shipped), the migration guide stops bucketing implemented flags as
  no-ops and maps the fixup-chain flags, and the rustdocs the sweep
  found refresh — the arm64e constants' "schema only at M0" tags, the
  format crate's scope and summary-walk docs (the walk names its
  64-family scope instead of implying generic strides), the two
  copy-pasted `# Errors` blocks and the signed-addend contradiction, the
  mangled trie-walk comment, the verifier's export-trie and structural
  module docs, the arm64e walk example's forward-looking prose, the
  daemon `IMAGE` tag row (the v5 tile-stream tail) and the duplicated
  auth-bind paragraph in the core fixup module.

## [0.10.0] - 2026-11-09

### Features

- **format/core/driver/verify:** M10 rung 2 — the platform plumbing rung
  (roadmap §10.4 row M10). `-platform_version` accepts the five linked
  platforms — `macos`, `ios`, `tvos`, `watchos`, `visionos` — and the
  refusal for anything else names the surface (miette help text, the
  fix, not just the verdict); an SDK older than the deployment target
  refuses at parse time (`OptsError::VersionOrder`). The layout's
  chained-fixups gate is per-platform: `pgr_core::layout::
  chained_fixups_min_minos` names the dyld availability floors
  (macOS 12.0, iOS 15.0, tvOS 15.0, watchOS 8.0, visionOS 1.0) — below
  the floor the M6 classic `LC_DYLD_INFO_ONLY` opcode streams encode
  the same fixups (the encoding flips, the pipeline does not), and the
  fixup-shape span now carries the platform and its floor.
  `pgr_format::PLATFORM_VISIONOS` (11) crosschecks against the vendored
  headers' `PLATFORM_XROS`. The verifier's build-version gate checks
  the *declared* platform — the five platforms verify strict-clean, an
  unknown platform constant is an error, and `sdk < minos` is an error
  (before the rung every non-macos image warned, so a legitimately
  plumbed iOS image could not pass `--strict`). The `platform_matrix`
  consumer example and the `platform` bench ride along.

### Bug Fixes

- **driver:** an unreadable input names itself — `DriverError::Io`
  used to be routed through the option-error reporter, printing
  "option handling failed" for what is a file-system refusal; the Io
  arm now reports its own message ("reading {path}: {source}").

### Refactor

- **verify:** the export-trie walk loses its two logically-infallible
  `unwrap()`s — the checked terminal bound is the value, so a hostile
  payload can never turn "the verifier" into a panic (TDD §2: typed
  errors, never panic); the re-export test uses the named
  `EXPORT_SYMBOL_FLAGS_REEXPORT` constant instead of the magic `0x8`,
  and the import-keeping `let _ =` suppression is gone.

### Documentation

- the `pgr-core`, `pgr-verify` crate docs carry their M10 rungs
  (the relocatable stop-short and the platform-aware fixup floor; the
  platform gate), and `LinkConfig::platform`'s rustdoc matches the
  driver-selected surface instead of "macOS at M1".
- **changelog:** cut the missing v0.9.1 section (the M10 rung 1 work
  below shipped as 0.9.1 without its section) and fix the release
  ladder note's carried version.

## [0.9.1] - 2026-11-09

### Features

- **emit/core/driver/verify:** M10 rung 1 — the `-r` relocatable output
  (roadmap §10.4 row M10). `pgr_core::link_reloc` runs Passes 1–2 and
  stops short of the segment layout (undefined externals stay open — the
  object is itself a link input; duplicate strongs still refuse);
  `pgr_emit::build_object_image` assembles the `MH_OBJECT`: sections
  merged by `(segment, name)` in first-seen order, each contribution
  re-aligned inside its section, symbol `n_value`s mapped through the
  placement, the symtab grouped locals / winner-backed globals / open
  undefineds with the `LC_DYSYMTAB` subranges following, commons kept
  tentative, and every relocation entry **preserved, not applied** —
  `r_extern` entries re-pointed at the output symbol table, section
  targets re-ordinaled, `ADDEND`/`SUBTRACTOR` leaders re-emitted first,
  site bytes verbatim. The driver parses `-r`, refuses the conflicting
  knobs (`-dead_strip`, `-icf`, `-incremental`, `-resident`, the other
  output kinds) with messages that name the conflict, and routes
  `run()` through the new path; the verifier gains the object contract
  (`check_object_contract`: no fixups/dyld-info/signature on
  `MH_OBJECT`, every relocation entry bounds-checked against its
  section, the symbol table and the pair shape) plus the image-shaped
  carve-outs the convention needs. The two-step self-consumption link
  (`pgr -r a.o b.o -o out.o`, then `pgr out.o -o exe`) is a test gate,
  double `-r` is byte-identical, and the emitted object is
  verifier-clean under `--strict`.
- **emit:** the relocatable emit rides the workspace conventions —
  tracing spans on `link_reloc`, `object_layout`, `reloc_encode` and
  `object_emit` (inert until a subscriber installs), and the miette
  help-text refusal `ObjectRelocRefusal` for a relocation the output
  symbol table cannot represent (a malformed input's `r_extern` entry
  naming a local), rendered with the fix, not just the verdict.
- **emit:** the object emit gets its bench (`cargo bench -p pgr-emit --
  bench object`: the same corpus shape the fused-emit bench uses) and
  **driver** its consumer example (`cargo run -p pgr-driver --example
  relocatable_link`: the two-step cycle at the API level, verifier
  gated, spans watchable under `PGR_TRACING=1`).

### Bug Fixes

- **driver:** a repeated `-dylib`/`-bundle` is idempotent — it used to
  be reported as "-dylib and -bundle are mutually exclusive", a
  diagnosis about a conflict that never happened. The real kind switch
  still refuses, naming both flags.

### Refactor

- **emit:** drop the dead public re-exports — `blob_size` and the
  record-twin types (`SpanTable`, `RecordedSpan`, `RecordedSection`)
  nothing in the workspace consumed are gone; the items stay reachable
  through their own modules.

### Documentation

- reconcile the v0.9.0 release drift: the README badge and status line
  ride 0.9.0, the release ladder note matches, and the missing 0.9.0
  section is backfilled below.
- **driver:** the `--help` text and the `opts` module docs carry their
  current surface instead of the M2/M3 ones they stopped matching; the
  emit/verify crate docs name their current rungs.
- **migration:** the environment-variable table lists the full surface
  (`PGR_DAEMON_SOCK`, `PGR_RESIDENT_DEBUG`, `PGR_INCREMENTAL_RECORD`,
  `PGR_INCREMENTAL_DEBUG`, `PGR_RANDOMIZED_STEPS`, `PGR_TRACING`) and
  the output-kind table carries `-r`.

## [0.9.0] - 2026-11-09

### Features

- **core:** the incremental resolve gets its consumer example —
  `cargo run -p pgr-core --example incremental_resolve` walks the reuse
  shape (`plan_reuse` → `install_reused` vs the full resolve) on a
  two-file corpus, printing the split counts (the tracing spans stay
  inert until a subscriber installs).
- **core:** the resolve-reuse seams ride tracing spans —
  `resolve_reuse_plan`/`resolve_reuse_install` carry the refusal
  reasons and the split counts as fields, inert until a subscriber
  installs (the workspace convention).

### Bug Fixes

- **format:** the tbd utf-8 refusal names the offset — the error no
  longer flattens the malformed byte position away.

### Refactor

- **emit:** drop the dead `apply_patch_reloc` re-export — nothing in
  the workspace consumed it; the item stays reachable through its own
  module.

### Documentation

- **fixtures:** the crate docs carry the workspace consumers.

### Build

- the lint-policy comment matches the CI gate.

## [0.8.0] - 2026-11-09

### Features

- **emit:** the engine gets its consumer example —
  `cargo run -p pgr-emit --example record_patch_tiles` walks the whole
  §7.3 tier-1 loop at the engine's own API level (record → plan → patch →
  re-record) plus the bytes-level tile twin the §7.2 resident transport
  ships, printing the report either way (the tracing spans stay inert
  until a subscriber installs).
- **driver:** the driver library gets its consumer example —
  `cargo run -p pgr-driver --example library_link` drives the same
  two-step cycle the CLI drives (`-o` then `-incremental`) at the
  [`pgr_driver::run`] API level, checking the patched output two ways
  (byte-identity against the full link, then a `pgr-verify` pass).

### Bug Fixes

- **driver:** the resident stand-down carries its io cause — the
  fallback-to-one-shot path no longer flattens the underlying io error
  into a bare message.
- the lockfile carries the 0.7.0 members — `Cargo.lock` was left listing
  the previous member set after the release bump.

### Documentation

- reconcile the v0.7.0 release drift (README status, the release ladder
  in the docs).
- **core:** the crate docs carry the m8/m9 machinery — the crate-level
  rustdoc now names the reverse reference index, the insertion-stable
  import table, the slack policy and the M9 `propagate`/`resolve_reuse`
  scoping instead of stopping at M4.

### Refactor

- drop the dead public seams — public re-exports nothing in the workspace
  consumed are gone; the underlying items stay reachable through their
  own modules.

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

#### Build

- **build:** restore criterion's `cargo_bench_support` to the workspace
  feature set — criterion 0.7 split the measuring harness out of the
  default features, and with `default-features = false, features =
  ["html_reports"]` every bench compiled, "passed" and measured nothing
  (the CI `bench --no-run` gate could not see it); the harness runs again



