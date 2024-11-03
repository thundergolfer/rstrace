use anyhow::Result;
use rstrace::trace_command;
use std::{collections::HashMap, process::Command};

fn count_syscalls(output: &str) -> HashMap<&str, u32> {
    let mut call_counts_by_syscall: HashMap<&str, u32> = HashMap::new();
    // The first two lines are the header; skip those.
    for line in output.lines().skip(2) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() == 0 {
            break; // end of table
        } else if parts[0].starts_with("---") {
            break; // strace's totals divider. totals currently unimplemented in rstrace.
        }
        // 6 if non-zero errors, else 5.
        let (calls, syscall) = if parts.len() == 6 {
            (parts[3].parse().unwrap(), parts[5])
        } else if parts.len() == 5 {
            (parts[3].parse().unwrap(), parts[4])
        } else {
            panic!("Unexpected number of parts: {:?}", parts);
        };
        call_counts_by_syscall.insert(syscall, calls);
    }
    call_counts_by_syscall
}

#[test]
fn test_trace_echo() -> Result<()> {
    let mut f = std::io::BufWriter::new(Vec::new());
    let options = rstrace::TraceOptions {
        stats: rstrace::StatisticsOptions {
            summary: rstrace::SummaryOption::SummaryOnly,
        },
        ..Default::default()
    };
    let program = vec!["echo".to_string(), "hello".into()];
    unsafe { trace_command(&program, &mut f, options).unwrap() };
    let r_strace_output = String::from_utf8(f.into_inner().unwrap())?;
    println!("{}", r_strace_output);

    let output = Command::new("strace")
        .arg("-c")
        .args(&program)
        .output()
        .expect("failed to execute process");

    let strace_output = String::from_utf8_lossy(&output.stderr);
    println!("{}", strace_output);

    let r_counts = count_syscalls(&r_strace_output);
    let s_counts = count_syscalls(&strace_output);

    for (syscall, count) in r_counts {
        if syscall == "rt_sigprocmask" {
            // TODO(Jonathon): figure out why this shows up in rstrace but not strace.
            continue;
        } else if syscall == "execve" {
            // TODO(Jonathon): figure out why this shows up 17 times in rstrace when it should be 1!
            continue;
        }
        let strace_count = s_counts.get(syscall).unwrap_or(&0);
        assert_eq!(
            count, *strace_count,
            "mismatch on {syscall}: rstrace has {count} but strace has {strace_count}"
        );
    }

    Ok(())
}
