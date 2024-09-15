use std::process;

use anyhow::Result;
use strace_rs::trace_command;
use tracing::level_filters::LevelFilter;
use tracing_subscriber;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let mut args = std::env::args();
    if args.len() < 2 {
        eprintln!(
            "USAGE: {} PROG ARGS",
            args.next().expect("argv[0] always exists")
        );
        process::exit(2);
    } else {
        let _ = args.next().expect("always exists");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    unsafe { trace_command(args.into_iter()) }
}
