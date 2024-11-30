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

#[allow(dead_code, non_camel_case_types, non_snake_case)]
mod nvalloc_unix_include {
    include!(concat!(
        env!("OUT_DIR"),
        "/open-gpu-kernel-modules.src.nvidia.arch.nvalloc.unix.include.rs"
    ));
}

use common_inc::*;
#[allow(unused_imports)]
use common_sdk_nvidia::*;
use nvalloc_unix_include::*;

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
        // From kernel-open/common/inc/nv-ioctl-numbers.h:
        NV_ESC_CARD_INFO => format!("NV_ESC_CARD_INFO"),
        NV_ESC_REGISTER_FD => {
            let params = argp as *const nv_ioctl_register_fd_t;
            format!("NV_ESC_REGISTER_FD fd: {}", unsafe { (*params).ctl_fd })
        }
        NV_ESC_ALLOC_OS_EVENT => format!("NV_ESC_ALLOC_OS_EVENT"),
        NV_ESC_FREE_OS_EVENT => format!("NV_ESC_FREE_OS_EVENT"),
        NV_ESC_CHECK_VERSION_STR => format!("NV_ESC_CHECK_VERSION_STR"),
        NV_ESC_ATTACH_GPUS_TO_FD => format!("NV_ESC_ATTACH_GPUS_TO_FD"),
        NV_ESC_SYS_PARAMS => format!("NV_ESC_SYS_PARAMS"),
        NV_ESC_WAIT_OPEN_COMPLETE => format!("NV_ESC_WAIT_OPEN_COMPLETE"),

        // From kernel-open/common/inc/nv-ioctl-numa.h:
        NV_ESC_NUMA_INFO => format!("NV_ESC_NUMA_INFO"),

        // From src/nvidia/arch/nvalloc/unix/include/nv_escape.h:
        NV_ESC_RM_ALLOC_MEMORY => {
            let params = argp as *const nv_ioctl_nvos02_parameters_with_fd;
            format!("NV_ESC_RM_ALLOC_MEMORY: {:?}", unsafe { (*params).params })
        }
        NV_ESC_RM_FREE => format!("NV_ESC_RM_FREE"),
        NV_ESC_RM_CONTROL => format!("NV_ESC_RM_CONTROL"),
        NV_ESC_RM_ALLOC => format!("NV_ESC_RM_ALLOC"),
        NV_ESC_RM_VID_HEAP_CONTROL => {
            let params = argp as *const common_sdk_nvidia::NVOS32_PARAMETERS;
            unsafe {
                if (*params).function == nvalloc_unix_include::NVOS32_FUNCTION_ALLOC_SIZE {
                    let alloc_size_params = &(*params).data.AllocSize;
                    format!(
                        "NV_ESC_RM_VID_HEAP_CONTROL alloc_size: {:?}",
                        *alloc_size_params
                    )
                } else {
                    format!("NV_ESC_RM_VID_HEAP_CONTROL")
                }
            }
        }
        NV_ESC_RM_MAP_MEMORY => format!("NV_ESC_RM_MAP_MEMORY"),
        NV_ESC_RM_UNMAP_MEMORY => format!("NV_ESC_RM_UNMAP_MEMORY"),
        NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO => format!("NV_ESC_RM_UPDATE_DEVICE_MAPPING_INFO"),

        _ => format!("UNKNOWN: {:#x} {:#x} {:#x}", nr, request, type_),
    };

    Ok(Some(output))
}
