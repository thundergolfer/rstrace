#[cfg(target_os = "linux")]
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

extern crate bindgen;

macro_rules! get(($name:expr) => (ok!(env::var($name))));
macro_rules! ok(($expression:expr) => ($expression.unwrap()));
macro_rules! log {
    ($fmt:expr) => (println!(concat!("open-gpu-kernel-modules/build.rs:{}: ", $fmt), line!()));
    ($fmt:expr, $($arg:tt)*) => (println!(concat!("open-gpu-kernel-modules/build.rs:{}: ", $fmt),
    line!(), $($arg)*));
}
macro_rules! log_var(($var:ident) => (log!(concat!(stringify!($var), " = {:?}"), $var)));

const REPOSITORY: &str = "https://github.com/NVIDIA/open-gpu-kernel-modules";
const TAG: &str = "550";

fn run<F>(name: &str, mut configure: F)
where
    F: FnMut(&mut Command) -> &mut Command,
{
    let mut command = Command::new(name);
    let configured = configure(&mut command);
    log!("Executing {:?}", configured);
    if !ok!(configured.status()).success() {
        panic!("failed to execute {:?}", configured);
    }
    log!("Command {:?} finished successfully", configured);
}

fn fetch_open_gpu_kernel_modules_headers() {
    let output = PathBuf::from(&get!("OUT_DIR"));
    log_var!(output);
    let source = PathBuf::from(&get!("CARGO_MANIFEST_DIR")).join(format!("target/source-{}", TAG));
    log_var!(source);
    let lib_dir = output.join(format!("lib-{}", TAG));
    log_var!(lib_dir);
    if lib_dir.exists() {
        log!("Directory {:?} already exists", lib_dir);
    } else {
        log!("Creating directory {:?}", lib_dir);
        fs::create_dir(lib_dir.clone()).unwrap();
    }

    if !Path::new(&source.join(".git")).exists() {
        run("git", |command| {
            command
                .arg("clone")
                .arg(format!("--branch={}", TAG))
                .arg("--recursive")
                .arg(REPOSITORY)
                .arg(&source)
        });
    }

    // TODO: do all files in folder not just one.
    let common_inc_headers_path = source.join("kernel-open/common/inc/");
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", common_inc_headers_path.to_str().unwrap()))
        .header(
            common_inc_headers_path
                .join("nv-ioctl-numbers.h")
                .to_str()
                .unwrap(),
        )
        .header(common_inc_headers_path.join("nvlimits.h").to_str().unwrap())
        .header(common_inc_headers_path.join("nv-ioctl.h").to_str().unwrap())
        .header(common_inc_headers_path.join("nv-ioctl-numa.h").to_str().unwrap())
        .generate()
        .expect("Unable to generate kernel-open/common/inc bindings");

    bindings
        .write_to_file(output.join("open-gpu-kernel-modules.kernel-open.common.inc.rs"))
        .expect("Couldn't write kernel-open/common/inc bindings!");

    let nvidia_inc_headers_path = source.join("src/common/sdk/nvidia/inc/");
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", nvidia_inc_headers_path.to_str().unwrap()))
        .header(nvidia_inc_headers_path.join("nvtypes.h").to_str().unwrap())
        .header(nvidia_inc_headers_path.join("nvos.h").to_str().unwrap())
        .generate()
        .expect("Unable to generate src/common/sdk/nvidia/inc/ bindings");
    bindings
        .write_to_file(output.join("open-gpu-kernel-modules.src.common.sdk.nvidia.inc.rs"))
        .expect("Couldn't write src/common/sdk/nvidia/inc bindings!");

    let nvalloc_headers_path = source.join("src/nvidia/arch/nvalloc/unix/include/");
    let bindings = bindgen::Builder::default()
        .clang_arg(format!("-I{}", nvidia_inc_headers_path.to_str().unwrap()))
        .header(nvalloc_headers_path.join("nv_escape.h").to_str().unwrap())
        .header(
            nvalloc_headers_path
                .join("nv-unix-nvos-params-wrappers.h")
                .to_str()
                .unwrap(),
        )
        .generate()
        .expect("Unable to generate src/nvidia/arch/nvalloc/unix/include/ bindings");
    bindings
        .write_to_file(
            output.join("open-gpu-kernel-modules.src.nvidia.arch.nvalloc.unix.include.rs"),
        )
        .expect("Couldn't write src/nvidia/arch/nvalloc/unix/include bindings!");
}

#[cfg(target_os = "linux")]
fn main() {
    let cuda_sniff_enabled = env::var("CARGO_FEATURE_CUDA_SNIFF").is_ok();
    if cuda_sniff_enabled {
        fetch_open_gpu_kernel_modules_headers();
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {}
