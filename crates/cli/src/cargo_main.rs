//! Entry point for `cargo soroban-guard`.
//!
//! When invoked as a Cargo subcommand (`cargo soroban-guard scan …`), Cargo
//! prepends the subcommand name so argv looks like:
//!
//!   `[cargo-soroban-guard, soroban-guard, scan, …]`
//!
//! This wrapper strips the injected `soroban-guard` token (argv[1]) and
//! re-executes the `soroban-guard` binary found on `PATH` — or, if the two
//! binaries share a directory (the common case after `cargo install`), uses
//! the sibling binary directly.  If no path argument is given, the current
//! directory is tried first so that `cargo soroban-guard scan` works from the
//! crate root exactly like `soroban-guard scan`.

use std::env;
use std::os::unix::process::CommandExt;
use std::process;

fn main() {
    // argv: [cargo-soroban-guard, soroban-guard, <subcommand>, ...]
    // Strip the first real argument when it equals "soroban-guard" (the token
    // Cargo injects to identify the subcommand).
    let mut args: Vec<String> = env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("soroban-guard") {
        args.remove(1);
    }

    // args[0] is the path to this binary. Replace it with soroban-guard.
    // Prefer a sibling binary in the same directory (e.g. ~/.cargo/bin/).
    let self_path = std::path::PathBuf::from(&args[0]);
    let sibling = self_path
        .parent()
        .map(|p| p.join("soroban-guard"))
        .filter(|p| p.exists());

    let binary = sibling
        .as_deref()
        .unwrap_or_else(|| std::path::Path::new("soroban-guard"));

    // exec() replaces the current process on Unix; on other platforms fall back
    // to spawn-and-wait.
    #[cfg(unix)]
    {
        let err = process::Command::new(binary).args(&args[1..]).exec();
        // exec() only returns on error.
        eprintln!("cargo-soroban-guard: failed to exec soroban-guard: {err}");
        process::exit(2);
    }

    #[cfg(not(unix))]
    {
        let status = process::Command::new(binary)
            .args(&args[1..])
            .status()
            .unwrap_or_else(|e| {
                eprintln!("cargo-soroban-guard: failed to run soroban-guard: {e}");
                process::exit(2);
            });
        process::exit(status.code().unwrap_or(1));
    }
}
