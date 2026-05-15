//! `xtask` — workspace automation entry point.
//!
//! Invoked as `cargo xtask <command>` (via the alias in `.cargo/config.toml`).
//! Real subcommands are added milestone by milestone:
//!
//! - `capture-tlv`  — drive `matter.js` to capture TLV vectors (Milestone 1).
//! - `codegen`      — generate cluster definitions from the Matter spec
//!   (Milestone 7).
//! - `release`      — workspace release helper (post-Milestone 1).

fn main() {
    let mut args = std::env::args().skip(1);
    let cmd = args.next();
    match cmd.as_deref() {
        None | Some("help" | "--help" | "-h") => print_help(),
        Some(other) => {
            eprintln!("xtask: unknown subcommand `{other}`");
            print_help();
            std::process::exit(2);
        }
    }
}

fn print_help() {
    println!(
        "xtask — matter-rust workspace automation\n\
         \n\
         USAGE:\n  \
             cargo xtask <subcommand>\n\
         \n\
         SUBCOMMANDS:\n  \
             help     Show this message.\n\
         \n\
         No real subcommands exist yet. They arrive with their owning milestone.\n"
    );
}
