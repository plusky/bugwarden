//! Dev/packaging tool: regenerate the committed man page and shell
//! completions from the `bugwarden` CLI definition. CI runs this and diffs
//! the output so the assets never drift. Built only with `--features gen`.

#![forbid(unsafe_code)]

use std::io::Write as _;
use std::path::{Path, PathBuf};

fn main() -> std::process::ExitCode {
    // args_os: the argument is a path, which need not be UTF-8. The default
    // is the crate directory baked in at compile time, so the tool writes
    // the committed asset dirs no matter which cwd it runs from.
    let out = std::env::args_os()
        .nth(1)
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from);
    match generate(&out) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::ExitCode::from(2)
        }
    }
}

fn generate(out: &Path) -> std::io::Result<()> {
    let man_dir = out.join("man");
    let comp_dir = out.join("completions");
    std::fs::create_dir_all(&man_dir)?;
    std::fs::create_dir_all(&comp_dir)?;

    let mut cmd = bugwarden::config::command();
    cmd.build();
    std::fs::write(man_dir.join("bugwarden.1"), render_man(&cmd)?)?;
    for shell in [
        clap_complete::Shell::Bash,
        clap_complete::Shell::Zsh,
        clap_complete::Shell::Fish,
    ] {
        clap_complete::generate_to(shell, &mut cmd, "bugwarden", &comp_dir)?;
    }
    Ok(())
}

/// The clap_mangen render of the derive, with the sections the derive cannot
/// express interleaved at their man-pages(7) positions. SYNOPSIS and
/// ENVIRONMENT are derived from the same command so they cannot drift from
/// `config.rs`; the hand-authored sections state only facts the derive has
/// no field for.
fn render_man(cmd: &clap::Command) -> std::io::Result<Vec<u8>> {
    let man = clap_mangen::Man::new(cmd.clone());
    let mut buf = Vec::new();
    // Hand-written .TH: clap_mangen leaves an empty date argument unquoted,
    // shifting source and manual one slot left. The date stays empty on
    // purpose — a generation date would make every CI regeneration differ
    // from the committed page and trip the drift gate — and the version
    // lives in the source field, so no separate VERSION section is rendered.
    writeln!(
        buf,
        ".TH bugwarden 1 \"\" \"bugwarden {}\" \"General Commands Manual\"",
        cmd.get_version().unwrap_or_default()
    )?;
    man.render_name_section(&mut buf)?;
    render_synopsis(cmd, &mut buf)?;
    man.render_description_section(&mut buf)?;
    man.render_options_section(&mut buf)?;
    buf.write_all(EXIT_STATUS.as_bytes())?;
    render_environment(cmd, &mut buf)?;
    buf.write_all(FILES.as_bytes())?;
    buf.write_all(EXAMPLES.as_bytes())?;
    Ok(buf)
}

/// Derived synopsis with the value placeholders clap_mangen's own synopsis
/// omits (it prints a bare `[--transport]`, hiding which options take a
/// value, and renders the required option as `<--bugzilla-server>`).
fn render_synopsis(cmd: &clap::Command, buf: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(buf, ".SH SYNOPSIS")?;
    writeln!(buf, "\\fBbugwarden\\fR")?;
    for arg in cmd.get_arguments() {
        if arg.get_id() == "help" || arg.get_id() == "version" {
            continue;
        }
        let long = arg
            .get_long()
            .expect("every bugwarden option is a long option")
            .replace('-', "\\-");
        let mut piece = format!("\\fB\\-\\-{long}\\fR");
        if arg.get_num_args().is_some_and(|n| n.takes_values()) {
            let metavar = arg
                .get_value_names()
                .and_then(|names| names.first().map(ToString::to_string))
                .unwrap_or_else(|| arg.get_id().as_str().to_uppercase());
            piece.push_str(&format!(" <{metavar}>"));
        }
        if arg.is_required_set() {
            writeln!(buf, "{piece}")?;
        } else {
            writeln!(buf, "[{piece}]")?;
        }
    }
    writeln!(buf, "[\\fB\\-h\\fR|\\fB\\-\\-help\\fR]")?;
    writeln!(buf, "[\\fB\\-V\\fR|\\fB\\-\\-version\\fR]")?;
    Ok(())
}

/// One entry per option that has an environment fallback, straight off the
/// clap command.
fn render_environment(cmd: &clap::Command, buf: &mut Vec<u8>) -> std::io::Result<()> {
    writeln!(buf, ".SH ENVIRONMENT")?;
    writeln!(
        buf,
        "Each variable is the fallback for one option; a command\\-line argument"
    )?;
    writeln!(
        buf,
        "always wins over the environment, and the built\\-in default applies when"
    )?;
    writeln!(buf, "neither is given.")?;
    for arg in cmd.get_arguments() {
        let Some(env) = arg.get_env() else { continue };
        let long = arg
            .get_long()
            .expect("every bugwarden option is a long option");
        writeln!(buf, ".TP")?;
        writeln!(buf, ".B {}", env.to_string_lossy())?;
        writeln!(
            buf,
            "Fallback for \\fB\\-\\-{}\\fR.",
            long.replace('-', "\\-")
        )?;
    }
    Ok(())
}

const EXIT_STATUS: &str = r".SH EXIT STATUS
.TP
.B 0
Clean shutdown.
.TP
.B 1
Startup or runtime failure: an unreadable policy or audit configuration, a
key misconfiguration, a Bugzilla client or transport error.
.TP
.B 2
Command\-line usage error.
";

const FILES: &str = r".SH FILES
.TP
.I /etc/bugwarden/policy.toml
Worked example guard policy as installed by distribution packages; the
source tree and release archives ship it as
.IR examples/policy.toml .
The server reads a policy only when one is named with
.B \-\-policy
or
.BR BUGWARDEN_POLICY ;
without one the built\-in allow\-all default policy applies.
.TP
.I /etc/bugwarden/audit.toml
Worked example audit configuration; the source tree ships it as
.IR examples/audit.toml .
Without
.B \-\-audit\-config
or
.B BUGWARDEN_AUDIT_CONFIG
no audit stream is written.
";

const EXAMPLES: &str = r".SH EXAMPLES
Serve a local MCP client over stdio, the server reading the Bugzilla API
key from a file:
.PP
.RS 4
.nf
bugwarden \-\-transport stdio \e
    \-\-bugzilla\-server https://bugzilla.example.com \e
    \-\-api\-key\-file ~/.config/bugwarden/api\-key \e
    \-\-policy /etc/bugwarden/policy.toml
.fi
.RE
.PP
Listen on HTTP (the default transport, 127.0.0.1:8000), each client
presenting its own key in the API key header:
.PP
.RS 4
.nf
bugwarden \-\-bugzilla\-server https://bugzilla.example.com \e
    \-\-policy /etc/bugwarden/policy.toml
.fi
.RE
.PP
Listen on HTTP with a server\-held key (container secret, systemd
LoadCredential): every request is served with this key and the per\-request
key header is not consulted:
.PP
.RS 4
.nf
bugwarden \-\-bugzilla\-server https://bugzilla.example.com \e
    \-\-api\-key\-file /run/secrets/bugzilla\-api\-key \e
    \-\-policy /etc/bugwarden/policy.toml
.fi
.RE
";
