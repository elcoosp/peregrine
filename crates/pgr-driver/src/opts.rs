//! ld64-compatible option surface (TDD §5 Pass 0, M2 subset).
//!
//! M2 links direct `.o` inputs against `.tbd` dylib stubs: `-l`/`-L`
//! library search, `-rpath`, `-flat_namespace`, `-undefined`,
//! `-weak_library`, `-u` and `-source_version` join the surface. Flags real
//! builds use that arrive at later milestones (`-dylib`, `-dead_strip`,
//! `-framework`, `-filelist`, `-order_file`, TLV, bitcode) are rejected with
//! actionable messages rather than silently ignored — a linker that pretends
//! to understand a flag it drops is worse than one that says "not yet".

use pgr_core::layout::LinkConfig;

/// Parsed driver options (M2 surface).
#[derive(Debug, Clone)]
pub struct Options {
    /// Output path (`-o`).
    pub output: String,
    /// Input object paths, in command-line order (the resolution tie-break).
    pub inputs: Vec<String>,
    /// The link configuration handed to Pass 3.
    pub config: LinkConfig,
    /// Minimum page size accepted for `-segalign` on arm64 (16 KiB default).
    pub segalign: u64,
    /// `-headerpad` (advisory at M1: commands never grow after the link).
    pub headerpad: u64,
    /// `-L` library search directories, in command-line order.
    pub lib_dirs: Vec<String>,
    /// `-l` requested library basenames (`-lfoo` / `-l foo`), in order.
    pub libs: Vec<String>,
    /// `-u <symbol>`: force the symbol to be treated as defined (must
    /// resolve; a plain liveness marker at M2).
    pub force_load: Vec<String>,
    /// Indices into `inputs` loaded weakly (`-weak_library`).
    pub weak_library_inputs: Vec<usize>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            output: String::new(),
            inputs: Vec::new(),
            config: LinkConfig::default(),
            segalign: pgr_format::consts::PAGE_SIZE_16K,
            headerpad: 0,
            lib_dirs: Vec::new(),
            libs: Vec::new(),
            force_load: Vec::new(),
            weak_library_inputs: Vec::new(),
        }
    }
}

/// A command-line problem (exit code 2).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum OptsError {
    /// A required flag or value is missing.
    #[error("missing value for {flag}")]
    MissingValue {
        /// The flag that wanted a value.
        flag: String,
    },
    /// The flag is not part of the M1 surface.
    #[error("unsupported flag {flag} (M1 links direct .o inputs only; {hint})")]
    Unsupported {
        /// The offending flag.
        flag: String,
        /// What to do instead / when it lands.
        hint: String,
    },
    /// A flag value is malformed.
    #[error("invalid value for {flag}: {value}")]
    InvalidValue {
        /// The flag.
        flag: String,
        /// The bad value.
        value: String,
    },
    /// No output path or no inputs.
    #[error("{message}")]
    Missing {
        /// What is missing.
        message: String,
    },
    /// Duplicate `-o` or a repeated flag that must be unique.
    #[error("{message}")]
    Repeated {
        /// What was repeated.
        message: String,
    },
}

/// Flags accepted with no effect at M1 (their features do not exist yet).
const NOOP_FLAGS: [&str; 5] = [
    "-no_adhoc_extensions",
    "-keep_private_externs",
    "-no_uuid",
    "-no_function_starts",
    "-no_data_in_code",
];

/// Flags that arrive at a later milestone (rejected with the roadmap entry).
const LATER_FLAGS: [(&str, &str); 20] = [
    ("-dylib", "M3 scope (dylibs and bundles)"),
    ("-bundle", "M3 scope (dylibs and bundles)"),
    ("-dylinker", "M3 scope (dylibs and bundles)"),
    ("-dead_strip", "M5 scope"),
    ("-framework", "M3 scope (framework bundles)"),
    ("-weak_framework", "M3 scope (framework bundles)"),
    ("-lazy_framework", "M3 scope (framework bundles)"),
    ("-lazy_library", "M3 scope"),
    ("-filelist", "M3 scope"),
    ("-order_file", "M5 scope"),
    ("-install_name", "M3 scope"),
    ("-U", "M3 scope (make-undefined)"),
    ("-pagezero_size", "later milestone"),
    ("-sub_library", "M3 scope"),
    ("-sub_umbrella", "M3 scope"),
    ("-reexport_library", "M3 scope"),
    ("-compatibility_version", "M3 scope"),
    ("-current_version", "M3 scope"),
    ("-mark_dead_strippable_dylib", "M3 scope"),
    ("-cache_path_limiter", "later milestone"),
];

/// Parses argv (without the program name).
///
/// # Errors
/// [`OptsError`] on any malformed or unsupported flag.
pub fn parse(args: &[std::ffi::OsString]) -> Result<Options, OptsError> {
    let mut opts = Options::default();
    let mut output_seen = false;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].to_str().ok_or_else(|| OptsError::InvalidValue {
            flag: "<arg>".into(),
            value: args[i].to_string_lossy().into_owned(),
        })?;
        if arg == "-o" {
            if output_seen {
                return Err(OptsError::Repeated {
                    message: "-o given more than once".into(),
                });
            }
            opts.output = next_value(args, &mut i, arg)?;
            output_seen = true;
        } else if arg.starts_with('-') {
            apply_flag(&mut opts, arg, args, &mut i)?;
        } else {
            opts.inputs.push(arg.to_string());
        }
        i += 1;
    }
    finish(&opts)
}

/// The next argv element as a flag value.
fn next_value(args: &[std::ffi::OsString], i: &mut usize, flag: &str) -> Result<String, OptsError> {
    *i += 1;
    args.get(*i)
        .and_then(|v| v.to_str())
        .map(str::to_string)
        .ok_or_else(|| OptsError::MissingValue {
            flag: flag.to_string(),
        })
}

/// Applies one option flag to the configuration.
fn apply_flag(
    opts: &mut Options,
    arg: &str,
    args: &[std::ffi::OsString],
    i: &mut usize,
) -> Result<(), OptsError> {
    match arg {
        "-arch" => {
            let v = next_value(args, i, arg)?;
            if v != "arm64" {
                return Err(OptsError::Unsupported {
                    flag: arg.into(),
                    hint: "M1 targets arm64-apple-darwin exclusively".into(),
                });
            }
        }
        "-platform_version" => {
            let platform = next_value(args, i, arg)?;
            let minos = next_value(args, i, arg)?;
            let sdk = next_value(args, i, arg)?;
            if platform != "macos" {
                return Err(OptsError::Unsupported {
                    flag: arg.into(),
                    hint: format!("platform {platform:?} (M1 supports macos only)"),
                });
            }
            opts.config.minos = parse_version(&minos).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: minos,
            })?;
            opts.config.sdk = parse_version(&sdk).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: sdk,
            })?;
        }
        "-e" | "-entry" => {
            opts.config.entry_symbol = next_value(args, i, arg)?;
        }
        "-headerpad" => {
            let v = next_value(args, i, arg)?;
            opts.headerpad = parse_number(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: v,
            })?;
        }
        "-segalign" => {
            let v = next_value(args, i, arg)?;
            let n = parse_number(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: v.clone(),
            })?;
            if n != 0x1000 && n != 0x4000 {
                return Err(OptsError::InvalidValue {
                    flag: arg.into(),
                    value: format!("{v} (chained fixups need a -segalign of 0x1000 or 0x4000)"),
                });
            }
            opts.segalign = n;
        }
        "-static" => {
            // The M1 default; accepted for ld64 compatibility.
        }
        "-fixup_chains" => opts.config.fixup_chains = true,
        "-no_fixup_chains" => opts.config.fixup_chains = false,
        "-adhoc" => opts.config.adhoc = true,
        "-no_adhoc" => opts.config.adhoc = false,
        "-flat_namespace" => opts.config.flat_namespace = true,
        "-no_flat_namespace" | "-twolevel_namespace" => {
            opts.config.flat_namespace = false;
        }
        "-undefined" => {
            let v = next_value(args, i, arg)?;
            opts.config.undefined_policy = match v.as_str() {
                "error" => pgr_core::resolve::UndefinedPolicy::Error,
                "dynamic_lookup" => pgr_core::resolve::UndefinedPolicy::DynamicLookup,
                other => {
                    return Err(OptsError::InvalidValue {
                        flag: arg.into(),
                        value: format!("{other} (error | dynamic_lookup)"),
                    });
                }
            };
        }
        "-rpath" => {
            let v = next_value(args, i, arg)?;
            opts.config.rpaths.push(v);
        }
        "-source_version" => {
            let v = next_value(args, i, arg)?;
            let sv = parse_source_version(&v).ok_or_else(|| OptsError::InvalidValue {
                flag: arg.into(),
                value: format!("{v} (A24.B10.C10.D10.E10, e.g. 1.2.3.4.5)"),
            })?;
            opts.config.source_version = Some(sv);
        }
        "-weak_library" => {
            // The whole dylib loads weakly (LC_LOAD_WEAK_DYLIB + weak binds).
            let v = next_value(args, i, arg)?;
            opts.inputs.push(v);
            opts.weak_library_inputs.push(opts.inputs.len() - 1);
        }
        "-l" | "-L" | "-u" => {
            let v = next_value(args, i, arg)?;
            match arg {
                "-l" => opts.libs.push(v),
                "-L" => opts.lib_dirs.push(v),
                _ => opts.force_load.push(v),
            }
        }
        "-help" | "--help" | "-h" => Err(OptsError::Unsupported {
            flag: arg.into(),
            hint: "handled by the CLI shell before parsing".into(),
        })?,
        _ if arg.starts_with("-l") && arg.len() > 2 && !arg.starts_with("-lazy") => {
            // Attached library form: -lSystem, -lfoo.
            opts.libs.push(arg[2..].to_string());
        }
        _ if NOOP_FLAGS.contains(&arg) => {
            // Accepted no-ops at M1 (the features they toggle do not exist
            // yet; emitting nothing matches the requested state).
        }
        _ if LATER_FLAGS.iter().any(|(f, _)| *f == arg) => {
            let hint = LATER_FLAGS
                .iter()
                .find(|(f, _)| *f == arg)
                .map(|(_, h)| (*h).to_string())
                .unwrap_or_default();
            return Err(OptsError::Unsupported {
                flag: arg.into(),
                hint,
            });
        }
        _ => {
            return Err(OptsError::Unsupported {
                flag: arg.into(),
                hint: "unknown flag (see --help for the M1 surface)".into(),
            });
        }
    }
    Ok(())
}

/// Post-conditions: an output path and at least one input.
fn finish(opts: &Options) -> Result<Options, OptsError> {
    if opts.output.is_empty() {
        return Err(OptsError::Missing {
            message: "no output path (use -o <path>)".into(),
        });
    }
    if opts.inputs.is_empty() {
        return Err(OptsError::Missing {
            message: "no input object files".into(),
        });
    }
    Ok(opts.clone())
}

/// Parses `X.Y.Z` into the packed `(X<<16)|(Y<<8)|Z` version.
#[must_use]
pub fn parse_version(v: &str) -> Option<u32> {
    let parts: Vec<&str> = v.split('.').collect();
    if parts.is_empty() || parts.len() > 3 {
        return None;
    }
    let mut out = 0u32;
    for (k, p) in parts.iter().enumerate() {
        let n: u32 = p.parse().ok()?;
        if n > 0xFF {
            return None;
        }
        out |= n << (16 - 8 * k);
    }
    Some(out)
}

/// Parses `A.B.C.D.E` into the packed `A24.B10.C10.D10.E10` source version.
#[must_use]
pub fn parse_source_version(v: &str) -> Option<u64> {
    let mut out = 0u64;
    let bits = [24u32, 10, 10, 10, 10];
    for (seen, part) in v.split('.').enumerate() {
        if part.is_empty() {
            return None;
        }
        let n: u64 = part.parse().ok()?;
        if seen >= 5 || n >= (1 << bits[seen]) {
            return None;
        }
        let shift = bits[seen..].iter().sum::<u32>() - bits[seen];
        out |= n << shift;
    }
    Some(out)
}

/// Parses a number in decimal or 0x-hex form.
#[must_use]
pub fn parse_number(v: &str) -> Option<u64> {
    if let Some(hex) = v.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        v.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{OptsError, parse, parse_number, parse_version};
    use std::ffi::OsString;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn minimal_invocation_parses() {
        let o = parse(&args(&["-o", "out", "a.o", "b.o"])).unwrap();
        assert_eq!(o.output, "out");
        assert_eq!(o.inputs, ["a.o", "b.o"]);
        assert_eq!(o.config.entry_symbol, "_main");
        assert!(o.config.fixup_chains);
        assert!(o.config.adhoc);
    }

    #[test]
    fn flags_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-arch",
            "arm64",
            "-platform_version",
            "macos",
            "13.0",
            "15.1",
            "-e",
            "_start",
            "-no_fixup_chains",
            "-no_adhoc",
            "-headerpad",
            "0x800",
            "-segalign",
            "0x1000",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.config.minos, (13 << 16));
        assert_eq!(o.config.sdk, (15 << 16) | (1 << 8));
        assert_eq!(o.config.entry_symbol, "_start");
        assert!(!o.config.fixup_chains);
        assert!(!o.config.adhoc);
        assert_eq!(o.headerpad, 0x800);
        assert_eq!(o.segalign, 0x1000);
    }

    #[test]
    fn missing_output_or_inputs_error() {
        assert!(matches!(
            parse(&args(&["a.o"])),
            Err(OptsError::Missing { .. })
        ));
        assert!(matches!(
            parse(&args(&["-o", "out"])),
            Err(OptsError::Missing { .. })
        ));
    }

    #[test]
    fn later_milestone_flags_are_rejected_actionably() {
        let err = parse(&args(&["-o", "out", "-dead_strip", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("M5"), "{err}");
        let err = parse(&args(&["-o", "out", "-framework", "Foo", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("M3"), "{err}");
        let err = parse(&args(&["-o", "out", "--wat", "a.o"])).unwrap_err();
        assert!(err.to_string().contains("unknown flag"), "{err}");
    }

    #[test]
    fn m2_flags_shape_the_config() {
        let o = parse(&args(&[
            "-o",
            "out",
            "-l",
            "System",
            "-lfoo",
            "-L",
            "/opt/libs",
            "-rpath",
            "/opt/r",
            "-flat_namespace",
            "-undefined",
            "dynamic_lookup",
            "-u",
            "_force_me",
            "-weak_library",
            "/opt/weak.tbd",
            "-source_version",
            "1.2.3.4.5",
            "a.o",
        ]))
        .unwrap();
        assert_eq!(o.libs, ["System", "foo"]);
        assert_eq!(o.lib_dirs, ["/opt/libs"]);
        assert_eq!(o.config.rpaths, ["/opt/r"]);
        assert!(o.config.flat_namespace);
        assert_eq!(
            o.config.undefined_policy,
            pgr_core::resolve::UndefinedPolicy::DynamicLookup
        );
        assert_eq!(o.force_load, ["_force_me"]);
        assert_eq!(o.weak_library_inputs, [0]);
        assert_eq!(
            o.config.source_version,
            Some(1u64 << 40 | 2 << 30 | 3 << 20 | 4 << 10 | 5)
        );
    }

    #[test]
    fn m2_flag_values_are_validated() {
        assert!(parse(&args(&["-o", "out", "-undefined", "wat", "a.o"])).is_err());
        assert!(
            parse(&args(&[
                "-o",
                "out",
                "-source_version",
                "1.2.3.4.5.6",
                "a.o"
            ]))
            .is_err()
        );
        assert!(parse(&args(&["-o", "out", "-source_version", "1.2000.0", "a.o"])).is_err());
        assert!(parse(&args(&["-o", "out", "-twolevel_namespace", "a.o"])).is_ok());
    }

    #[test]
    fn bad_values_error() {
        assert!(parse(&args(&["-o"])).is_err());
        assert!(parse(&args(&["-o", "out", "-segalign", "0x2000", "a.o"])).is_err());
        assert!(
            parse(&args(&[
                "-o",
                "out",
                "-platform_version",
                "macos",
                "x",
                "1",
                "a.o"
            ]))
            .is_err()
        );
    }

    #[test]
    fn version_and_number_parsers() {
        assert_eq!(parse_version("12.0.0"), Some(0x000c_0000));
        assert_eq!(parse_version("14.4"), Some(0x000e_0400));
        assert_eq!(parse_version("15"), Some(0x000f_0000));
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_number("0x4000"), Some(0x4000));
        assert_eq!(parse_number("16384"), Some(16384));
        assert_eq!(parse_number("nope"), None);
    }
}
