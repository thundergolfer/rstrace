//! Terminal rendering functionality, currently just coloring.

use nix::errno::Errno;
use nu_ansi_term::Color;

const NVIDIA_COLOR: Color = Color::Rgb(118, 185, 0);

pub fn render_cuda(colored_output: bool, ioctl: String) -> String {
    let s = format!("CUDA {}", ioctl);
    if !colored_output {
        return s;
    }
    NVIDIA_COLOR.bold().paint(s).to_string()
}

pub fn render_syscall(colored_output: bool, syscall: &str, syscall_num: u64) -> String {
    // TODO: CoW to avoid alloc
    if !colored_output {
        return syscall.to_string();
    }
    match syscall_num {
        0..=10 | 257 => Color::Blue.bold().paint(syscall).to_string(),
        _ => Color::White.bold().paint(syscall).to_string(),
    }
}

pub fn render_syscall_return_success(colored_output: bool, num: i32) -> String {
    // TODO: CoW to avoid alloc
    if !colored_output {
        return num.to_string();
    }
    Color::Green.bold().paint(num.to_string()).to_string()
}

pub fn render_syscall_return_err(colored_output: bool, errno: i32, err_name: Errno) -> String {
    // TODO: CoW to avoid alloc
    let s = format!("{} ({})", errno, err_name.desc());
    if !colored_output {
        return s;
    }
    Color::Red.bold().paint(s).to_string()
}

pub fn render_syscall_return_addr(colored_output: bool, addr: usize) -> String {
    let s = format!("{:#X}", addr);
    if !colored_output {
        return s;
    }
    Color::Yellow.bold().paint(s).to_string()
}
