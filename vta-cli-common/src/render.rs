use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::{Color, Modifier},
    widgets::Widget,
};

// ── ANSI constants ──────────────────────────────────────────────────

pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const GREEN: &str = "\x1b[32m";
pub const RED: &str = "\x1b[31m";
pub const CYAN: &str = "\x1b[36m";
pub const YELLOW: &str = "\x1b[33m";
pub const RESET: &str = "\x1b[0m";

// ── Error reporting ─────────────────────────────────────────────────

/// Print a CLI error to stderr in a form an operator can act on.
///
/// Downcasts to [`vta_sdk::error::VtaError`] when possible and emits a
/// tailored remediation hint for the common failure modes (auth, network,
/// forbidden, validation). Falls back to the raw error message + source
/// chain for anything else, so unknown failures still get their underlying
/// cause surfaced.
///
/// Call this from the top-level CLI match instead of `eprintln!("Error:
/// {e}")` — the raw form loses auth/network context that operators need
/// to fix things themselves.
pub fn print_cli_error(err: &(dyn std::error::Error + 'static)) {
    use vta_sdk::error::VtaError;
    if let Some(vta_err) = err.downcast_ref::<VtaError>() {
        match vta_err {
            VtaError::Auth(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Authentication failed: {msg}");
                eprintln!(
                    "  {DIM}Token may be expired. Try `pnm setup` to re-authenticate, or check \
                     that the VTA's `/auth` endpoint is reachable.{RESET}"
                );
            }
            VtaError::Forbidden(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Forbidden: {msg}");
                eprintln!(
                    "  {DIM}Your role or context access doesn't permit this operation. \
                     Inspect with `pnm acl get <your-did>`.{RESET}"
                );
            }
            VtaError::NotFound(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Not found: {msg}");
            }
            VtaError::Conflict(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Conflict: {msg}");
            }
            VtaError::Validation(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Invalid request: {msg}");
            }
            VtaError::Network(e) => {
                eprintln!("{RED}\u{2717}{RESET} Network error: {e}");
                eprintln!("  {DIM}Is the VTA reachable? Check its URL with `pnm vta info`.{RESET}");
            }
            VtaError::Server { status, body } => {
                eprintln!("{RED}\u{2717}{RESET} Server error (HTTP {status}): {body}");
                eprintln!(
                    "  {DIM}This is a VTA-side failure. Check server logs or contact the operator.{RESET}"
                );
            }
            VtaError::Protocol(msg) => {
                eprintln!("{RED}\u{2717}{RESET} Protocol error: {msg}");
            }
            other => eprintln!("{RED}\u{2717}{RESET} Error: {other}"),
        }
        return;
    }
    eprintln!("{RED}\u{2717}{RESET} Error: {err}");
    let mut source = err.source();
    while let Some(s) = source {
        eprintln!("  {DIM}caused by: {s}{RESET}");
        source = s.source();
    }
}

// ── Ratatui rendering helpers ───────────────────────────────────────

pub fn print_widget(widget: impl Widget, height: u16) {
    let width = ratatui::crossterm::terminal::size().map_or(120, |(w, _)| w);
    let area = Rect::new(0, 0, width, height);
    let mut buf = Buffer::empty(area);
    widget.render(area, &mut buf);

    let mut out = String::new();
    for y in 0..height {
        let mut cur_fg = Color::Reset;
        let mut cur_bg = Color::Reset;
        let mut cur_mod = Modifier::empty();

        for x in 0..width {
            let cell = &buf[(x, y)];
            if cell.skip {
                continue;
            }

            if cell.fg != cur_fg || cell.bg != cur_bg || cell.modifier != cur_mod {
                out.push_str("\x1b[0m");
                push_ansi_fg(&mut out, cell.fg);
                push_ansi_bg(&mut out, cell.bg);
                push_ansi_mod(&mut out, cell.modifier);
                cur_fg = cell.fg;
                cur_bg = cell.bg;
                cur_mod = cell.modifier;
            }

            out.push_str(cell.symbol());
        }
        out.push_str("\x1b[0m\n");
    }

    print!("{out}");
}

pub fn push_ansi_fg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[30m"),
        Color::Red => out.push_str("\x1b[31m"),
        Color::Green => out.push_str("\x1b[32m"),
        Color::Yellow => out.push_str("\x1b[33m"),
        Color::Blue => out.push_str("\x1b[34m"),
        Color::Magenta => out.push_str("\x1b[35m"),
        Color::Cyan => out.push_str("\x1b[36m"),
        Color::Gray => out.push_str("\x1b[37m"),
        Color::DarkGray => out.push_str("\x1b[90m"),
        Color::LightRed => out.push_str("\x1b[91m"),
        Color::LightGreen => out.push_str("\x1b[92m"),
        Color::LightYellow => out.push_str("\x1b[93m"),
        Color::LightBlue => out.push_str("\x1b[94m"),
        Color::LightMagenta => out.push_str("\x1b[95m"),
        Color::LightCyan => out.push_str("\x1b[96m"),
        Color::White => out.push_str("\x1b[97m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[38;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[38;5;{i}m");
        }
    }
}

pub fn push_ansi_bg(out: &mut String, color: Color) {
    use std::fmt::Write as _;
    match color {
        Color::Reset => {}
        Color::Black => out.push_str("\x1b[40m"),
        Color::Red => out.push_str("\x1b[41m"),
        Color::Green => out.push_str("\x1b[42m"),
        Color::Yellow => out.push_str("\x1b[43m"),
        Color::Blue => out.push_str("\x1b[44m"),
        Color::Magenta => out.push_str("\x1b[45m"),
        Color::Cyan => out.push_str("\x1b[46m"),
        Color::Gray => out.push_str("\x1b[47m"),
        Color::DarkGray => out.push_str("\x1b[100m"),
        Color::LightRed => out.push_str("\x1b[101m"),
        Color::LightGreen => out.push_str("\x1b[102m"),
        Color::LightYellow => out.push_str("\x1b[103m"),
        Color::LightBlue => out.push_str("\x1b[104m"),
        Color::LightMagenta => out.push_str("\x1b[105m"),
        Color::LightCyan => out.push_str("\x1b[106m"),
        Color::White => out.push_str("\x1b[107m"),
        Color::Rgb(r, g, b) => {
            let _ = write!(out, "\x1b[48;2;{r};{g};{b}m");
        }
        Color::Indexed(i) => {
            let _ = write!(out, "\x1b[48;5;{i}m");
        }
    }
}

pub fn push_ansi_mod(out: &mut String, modifier: Modifier) {
    if modifier.contains(Modifier::BOLD) {
        out.push_str("\x1b[1m");
    }
    if modifier.contains(Modifier::DIM) {
        out.push_str("\x1b[2m");
    }
    if modifier.contains(Modifier::ITALIC) {
        out.push_str("\x1b[3m");
    }
    if modifier.contains(Modifier::UNDERLINED) {
        out.push_str("\x1b[4m");
    }
    if modifier.contains(Modifier::REVERSED) {
        out.push_str("\x1b[7m");
    }
    if modifier.contains(Modifier::CROSSED_OUT) {
        out.push_str("\x1b[9m");
    }
}

pub fn print_section(title: &str) {
    let pad = 46usize.saturating_sub(title.len());
    println!(
        "\n{DIM}──{RESET} {BOLD}{title}{RESET} {DIM}{}{RESET}",
        "─".repeat(pad)
    );
}
