//! A ~20-line ANSI colorizer — deliberately no external crate.
//!
//! `render::render()` stays a pure function of `Report` (needed so a future
//! snapshot test can compare its output to a fixed string, and because the
//! same text is what gets written to a `-o` file, uncolored). Color is
//! therefore applied as a separate post-process over the already-rendered
//! text, and only by the caller (`diag_main`) — and only when stdout is a
//! TTY and output isn't being redirected to a file or suppressed.

const RESET: &str = "\x1b[0m";

fn wrap(code: &str, s: &str) -> String {
    format!("{code}{s}{RESET}")
}

/// Wraps each fixed-width `[ OK  ]`-style tag in `text` with its color,
/// leaving everything else untouched.
pub fn apply(text: &str) -> String {
    text.replace("[ OK  ]", &wrap("\x1b[32m", "[ OK  ]"))
        .replace("[FAIL ]", &wrap("\x1b[31m", "[FAIL ]"))
        .replace("[QUIRK]", &wrap("\x1b[33m", "[QUIRK]"))
        .replace("[SKIP ]", &wrap("\x1b[2m", "[SKIP ]"))
        .replace("[ERROR]", &wrap("\x1b[31m", "[ERROR]"))
        .replace("[INFO ]", &wrap("\x1b[36m", "[INFO ]"))
}

/// Whether `diag_main` should call [`apply`]: stdout is a TTY, and output
/// isn't being suppressed or redirected to a file.
pub fn enabled(quiet: bool, output_to_file: bool) -> bool {
    use std::io::IsTerminal;
    !quiet && !output_to_file && std::io::stdout().is_terminal()
}
