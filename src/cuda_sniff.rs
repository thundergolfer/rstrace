//! An implementation of https://github.com/geohot/cuda_ioctl_sniffer in Rust.
//! The original implementation used library interposition. This does not
//! provide interposition functionality, and instead is intended to be called by
//! a syscall tracer.
use anyhow::Result;
use libc::{c_int, c_ulong, c_void};

include!(concat!(
    env!("OUT_DIR"),
    "/open-gpu-kernel-modules.kernel-open.common.inc.rs"
));
include!(concat!(
    env!("OUT_DIR"),
    "/open-gpu-kernel-modules.src.common.sdk.nvidia.inc.rs"
));

/// Sniffs an ioctl syscall and if it determines that the ioctl is NVIDIA
/// related returns trace log output. Otherwise, returns None.
pub fn sniff_ioctl(fd: c_int, request: c_ulong, argp: *mut c_void) -> Result<Option<String>> {
    let _ = fd;
    let _ = argp;

    let type_: u8 = (request >> 8) as u8;
    let _nr: u8 = (request >> 0) as u8;
    let _size: u16 = (request >> 16) as u16;

    if type_ == NV_IOCTL_MAGIC {
        let output = format!("WOW! An NVIDIA ioctl. {:#x} {:#x}", request, type_);
        Ok(Some(output))
    } else {
        Ok(None)
    }
}
