//! The sweep lanes' shared machinery — the flag surface and the corpus
//! projection both lane binaries read, so one shape names two ledgers.
//!
//! The lanes are two processes by design: the allocation lane's seat is
//! a process-global counting allocator (`dhat::Alloc` — the valgrind-class
//! tooling §9.3 names), and the wall lane's baselines must ride the plain
//! allocator (a counting seat's per-allocation bookkeeping would ride the
//! stored walls). One crate, two binaries: the wall lane's `xtask` and
//! the allocation lane's `xtask-alloc`, both speaking this module's flag
//! surface — the shape axes, the run count, the ledger path — and both
//! projecting the same generated corpus the same way, the labels the
//! two ledgers carry identical.

use std::path::PathBuf;

use pgr_core::layout::{LinkConfig, OutputType};
use pgr_core::link::{LinkArchive, LinkInput, Parallelism};
use pgr_fixtures::corpus::{CorpusPreset, CorpusSpec};

/// One parsed flag: its name and the value token that followed it.
pub struct Flag<'a> {
    /// The flag's name (the leading `--` stripped).
    pub name: &'a str,
    /// The value token that followed it.
    pub value: &'a str,
}

/// Parses `--flag value` pairs out of the argument list — the value rides
/// the next token (the driver's two-token flag shape). An odd trailing
/// flag or an unknown name refuses with the fix named.
///
/// # Errors
/// A descriptive message for an unexpected positional or a flag missing
/// its value.
pub fn parse_flags(args: &[String]) -> Result<Vec<Flag<'_>>, String> {
    let mut flags = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        if !arg.starts_with("--") {
            return Err(format!(
                "unexpected argument {arg:?} (the lane commands read --flags only)"
            ));
        }
        let Some(value) = args.get(i + 1) else {
            return Err(format!(
                "{arg} needs a value (the flags are two-token: --flag value)"
            ));
        };
        flags.push(Flag {
            name: &arg[2..],
            value,
        });
        i += 2;
    }
    Ok(flags)
}

/// Parses an unsigned count for the flags that take one.
///
/// # Errors
/// A descriptive message when the value is not a non-negative integer.
pub fn parse_count(flag: &str, value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .map_err(|_| format!("--{flag} {value:?} is not a non-negative integer"))
}

/// The preset names the shape flags accept (the refusal's fix names
/// them).
pub const PRESET_NAMES: [&str; 5] = [
    "many-tiny",
    "large-debug",
    "archive-heavy",
    "single-giant",
    "byte-touching",
];

/// The sweep lanes' parsed arguments: the corpus shape (the corpus
/// command's axes), the run count and the ledger file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SweepArgs {
    /// The ledger file to write (required — never a repo-tree default).
    pub out: Option<PathBuf>,
    /// The preset shape (kebab-case; the default is `many-tiny`).
    pub preset: Option<CorpusPreset>,
    /// Direct objects (overrides the preset's count).
    pub objects: Option<usize>,
    /// `__text` payload per object, in KiB.
    pub text_kib: Option<usize>,
    /// Extra defined symbols per object.
    pub symbols_per_object: Option<usize>,
    /// Archive members (0 = no archive).
    pub archive_members: Option<usize>,
    /// `__text` payload per archive member, in KiB.
    pub member_text_kib: Option<usize>,
    /// Recorded runs (the §9.3 contract names 10; the default rides it).
    pub runs: Option<usize>,
    /// `auto` (the M4 parallel pipeline, the default) or `serial` (the
    /// determinism lane).
    pub parallel: Option<String>,
    /// The §9.3 budget gate's mode (`off`, `report` — the default — or
    /// `enforce`; the calibrated rig job's face). The wall lane's flag —
    /// the alloc lane's binary refuses it.
    pub budgets: Option<String>,
    /// Where the gate's run-0 image writes (`--determinism <path>`):
    /// the separate-process artifact the CI determinism job
    /// byte-compares — TDD §11's "link the same corpus twice in
    /// separate processes → byte-identical (CI-level, every PR)". The
    /// wall lane's flag — the alloc lane's binary refuses it.
    pub determinism: Option<PathBuf>,
}

impl SweepArgs {
    /// The spec the arguments name: the preset's shape with the parsed
    /// overrides applied (the corpus command's own projection).
    #[must_use]
    pub fn spec(&self) -> CorpusSpec {
        let base = CorpusSpec::new(self.preset.unwrap_or(CorpusPreset::ManyTiny));
        CorpusSpec {
            preset: base.preset,
            objects: self.objects,
            text_kib: self.text_kib,
            symbols_per_object: self.symbols_per_object,
            archive_members: self.archive_members,
            member_text_kib: self.member_text_kib,
        }
    }

    /// The recorded-run count (the §9.3 nightly contract's ten).
    #[must_use]
    pub fn runs(&self) -> usize {
        self.runs.unwrap_or(10)
    }

    /// The lane the sweep rides: the M4 parallel pipeline by default, the
    /// serial determinism lane under `--parallel serial`.
    #[must_use]
    pub fn parallel(&self) -> Parallelism {
        match self.parallel.as_deref() {
            Some("serial") => Parallelism::Serial,
            _ => Parallelism::Auto,
        }
    }

    /// The budget gate's mode (`report` the default).
    #[must_use]
    pub fn budgets_mode(&self) -> BudgetsMode {
        match self.budgets.as_deref() {
            Some("off") => BudgetsMode::Off,
            Some("enforce") => BudgetsMode::Enforce,
            _ => BudgetsMode::Report,
        }
    }

    /// The ledgers' shape label: the preset and the effective axes, in a
    /// stable order — the string the next nightly's baseline names, and
    /// the string that keeps the wall and allocation ledgers of one
    /// shape comparable.
    #[must_use]
    pub fn label(&self) -> String {
        let shape = self.spec().resolved();
        format!(
            "{} objects={} text_kib={} syms_per_obj={} archive_members={}",
            self.spec().preset.name(),
            shape.objects,
            shape.text_kib,
            shape.symbols_per_object,
            shape.archive_members,
        )
    }
}

/// The `--budgets` flag's parsed mode (the §9.3 gate's three faces).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BudgetsMode {
    /// Skip the gate entirely (the walls-only ledger face).
    Off,
    /// Price the budgets and render the verdict; never fail the build
    /// (the dev-class runner's honest face — the thresholds are the
    /// §9.1 rig job's calibration).
    #[default]
    Report,
    /// Price the budgets and fail the build on a breach (the rig job's
    /// face — §9.3's "fail the build if").
    Enforce,
}

/// Applies one sweep flag to the args, refusing unknown names (the
/// surface's own vocabulary is the fix). The shape axes ride the corpus
/// command's projection; `--runs` and `--parallel` are the sweep's own.
///
/// # Errors
/// A descriptive message for an unknown flag or a bad value.
pub fn apply_sweep_flag(args: &mut SweepArgs, flag: &str, value: &str) -> Result<(), String> {
    match flag {
        "out" => {
            args.out = Some(PathBuf::from(value));
            Ok(())
        }
        "preset" => {
            let preset = CorpusPreset::from_name(value).ok_or_else(|| {
                format!(
                    "--preset {value:?} is not a preset name (the presets are {})",
                    PRESET_NAMES.join(", ")
                )
            })?;
            args.preset = Some(preset);
            Ok(())
        }
        "objects" => {
            args.objects = Some(parse_count(flag, value)?);
            Ok(())
        }
        "text-kib" => {
            args.text_kib = Some(parse_count(flag, value)?);
            Ok(())
        }
        "symbols-per-object" => {
            args.symbols_per_object = Some(parse_count(flag, value)?);
            Ok(())
        }
        "archive-members" => {
            args.archive_members = Some(parse_count(flag, value)?);
            Ok(())
        }
        "member-text-kib" => {
            args.member_text_kib = Some(parse_count(flag, value)?);
            Ok(())
        }
        "runs" => {
            args.runs = Some(parse_count(flag, value)?);
            Ok(())
        }
        "parallel" => {
            if value != "auto" && value != "serial" {
                return Err(format!(
                    "--parallel {value:?} is not a lane (the lanes are auto and serial)"
                ));
            }
            args.parallel = Some(value.to_string());
            Ok(())
        }
        "budgets" => {
            if value != "off" && value != "report" && value != "enforce" {
                return Err(format!(
                    "--budgets {value:?} is not a mode (the modes are off, report and enforce)"
                ));
            }
            args.budgets = Some(value.to_string());
            Ok(())
        }
        "determinism" => {
            args.determinism = Some(PathBuf::from(value));
            Ok(())
        }
        other => Err(format!(
            "--{other} is not a sweep flag (the flags are --out --preset --objects --text-kib \
             --symbols-per-object --archive-members --member-text-kib --runs --parallel \
             --budgets --determinism)"
        )),
    }
}

/// Parses the sweep lanes' argument list.
///
/// # Errors
/// A descriptive message for a malformed command line — an unexpected
/// positional, a flag missing its value, an unknown flag, a bad count or
/// a missing `--out`.
pub fn parse_sweep_args(args: &[String]) -> Result<SweepArgs, String> {
    let mut parsed = SweepArgs::default();
    for flag in parse_flags(args)? {
        apply_sweep_flag(&mut parsed, flag.name, flag.value)?;
    }
    if parsed.runs() == 0 {
        return Err("--runs 0 records nothing — plan at least one run".to_string());
    }
    if parsed.out.is_none() {
        return Err(
            "the sweep command needs --out <ledger.json> (the file the nightly keeps)".to_string(),
        );
    }
    Ok(parsed)
}

/// The link configuration both lanes plan with: the executable output —
/// the nightly's shape links a whole image (the §9.2 corpus's own
/// product).
#[must_use]
pub fn sweep_config() -> LinkConfig {
    LinkConfig {
        filetype: OutputType::Execute,
        ..LinkConfig::default()
    }
}

/// Projects one generated corpus onto the lanes' inputs: the direct
/// objects ride the inputs, the one `libcorpus.a` (when the shape
/// carries one) projects onto the archives — the S7 pull's own input,
/// never a direct parse.
///
/// # Errors
/// The archive projection's refusal (the format reader's, the archive
/// named), already worded.
pub fn split_corpus(
    files: &[(String, Vec<u8>)],
) -> Result<(Vec<LinkInput>, Vec<LinkArchive>), String> {
    let mut inputs = Vec::new();
    let mut archives = Vec::new();
    for (name, bytes) in files {
        if name
            .rsplit_once('.')
            .is_some_and(|(_, ext)| ext.eq_ignore_ascii_case("a"))
        {
            archives.push(
                pgr_core::sweep::archive_input(name, bytes.clone()).map_err(|e| e.to_string())?,
            );
        } else {
            inputs.push(LinkInput {
                name: name.clone(),
                bytes: bytes.clone(),
            });
        }
    }
    Ok((inputs, archives))
}
