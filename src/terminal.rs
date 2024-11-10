//! Terminal rendering functionality, currently just coloring.

use nu_ansi_term::Color;

pub fn render_syscall(
    colored_output: bool,
    syscall: &str,
    syscall_num: u64,
) -> String {
    // TODO: CoW to avoid alloc
    if !colored_output {
        return syscall.to_string();
    }
    match syscall_num {
        0..=10 | 257 => Color::Blue.bold().paint(syscall).to_string(),
        _ => Color::White.bold().paint(syscall).to_string(),
    }
}
