//! An implementation of https://github.com/geohot/cuda_ioctl_sniffer in Rust.
//! The original implementation used library interposition. This does not
//! provide interposition functionality, and instead is intended to be called by
//! a syscall tracer.
use anyhow::Result;
use libc::{c_int, c_ulong, c_void};

#[allow(dead_code, non_camel_case_types, non_snake_case)]
mod common_inc {
    include!(concat!(
        env!("OUT_DIR"),
        "/open-gpu-kernel-modules.kernel-open.common.inc.rs"
    ));
}

#[allow(dead_code, non_camel_case_types, non_snake_case)]
mod common_sdk_nvidia {
    include!(concat!(
        env!("OUT_DIR"),
        "/open-gpu-kernel-modules.src.common.sdk.nvidia.inc.rs"
    ));
}

use common_inc::*;

/// Sniffs an ioctl syscall and if it determines that the ioctl is NVIDIA
/// related returns trace log output. Otherwise, returns None.
pub fn sniff_ioctl(fd: c_int, request: c_ulong, argp: *mut c_void) -> Result<Option<String>> {
    let _ = fd;
    let _ = argp;

    let type_: u8 = (request >> 8) as u8;
    let nr: u32 = (request & 0xFF) as u32;
    let _size: u16 = (request >> 16) as u16;

    if type_ != NV_IOCTL_MAGIC {
        return Ok(None);
    }

    let output = match nr {
        0x00 => {
            format!("WOW! An NVIDIA ioctl. {:#x} {:#x}", request, type_)
        }
        NV_ESC_CARD_INFO => format!("NV_ESC_CARD_INFO"),
        NV_ESC_REGISTER_FD => {
            let params = argp as *const nv_ioctl_register_fd_t;
            format!("NV_ESC_REGISTER_FD fd: {}", unsafe {
                (*params).ctl_fd as i32
            })
        }
        _ => format!("UNKNOWN: {:#x} {:#x} {:#x}", nr, request, type_),
    };

    Ok(Some(output))
}
