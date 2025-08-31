use std::io::Write;

use anyhow::Result;
use rstrace::trace_command;
use std::{collections::HashMap, process::Command};

const IGNORED_SYSCALLS: [&str; 2] = [
    // TODO(Jonathon): figure out why this shows up in rstrace but not strace.
    "rt_sigprocmask",
    // TODO(Jonathon): figure out why this shows up 17 times in rstrace when it should be 1!
    "execve",
];

fn count_syscalls(output: &str) -> HashMap<&str, u32> {
    let mut call_counts_by_syscall: HashMap<&str, u32> = HashMap::new();
    // The first two lines are the header; skip those.
    for line in output
        .lines()
        .filter(|line| !line.starts_with("strace: "))
        .skip(2)
    {
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
            panic!("Unexpected number of parts ({}): {:?}", parts.len(), parts);
        };
        call_counts_by_syscall.insert(syscall, calls);
    }
    call_counts_by_syscall
}

fn run_strace(program: &[String]) -> String {
    let output = Command::new("strace")
        .arg("-c")
        .args(program)
        .output()
        .expect("failed to execute process");

    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
#[serial_test::serial]
fn test_trace_echo() -> Result<()> {
    let mut f = std::io::BufWriter::new(Vec::new());
    let options = rstrace::TraceOptions {
        stats: rstrace::StatisticsOptions {
            summary: rstrace::SummaryOption::SummaryOnly,
        },
        cuda_verbose: false,
        ..Default::default()
    };
    let program = vec!["echo".to_string(), "hello".into()];
    trace_command(&program, &mut f, options).unwrap();
    let r_strace_output = String::from_utf8(f.into_inner().unwrap())?;
    println!("{}", r_strace_output);

    let strace_output = run_strace(&program);
    println!("{}", strace_output);

    let r_counts = count_syscalls(&r_strace_output);
    let s_counts = count_syscalls(&strace_output);

    for (syscall, count) in r_counts {
        if IGNORED_SYSCALLS.contains(&syscall) {
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

#[test]
#[serial_test::serial]
fn test_trace_tef_output() -> Result<()> {
    let mut f = std::io::BufWriter::new(Vec::new());
    let options = rstrace::TraceOptions {
        tef: true,
        cuda_verbose: false,
        ..Default::default()
    };
    // Run 'echo hello' under rstrace with TEF output enabled.
    let program = vec!["echo".to_string(), "hello".into()];
    trace_command(&program, &mut f, options).unwrap();
    let r_strace_output = String::from_utf8(f.into_inner().unwrap())?;
    // Parse the output as JSON to validate.
    let parsed: serde_json::Value = serde_json::from_str(&r_strace_output).unwrap();
    assert!(parsed.is_array(), "TEF output should be a JSON array");
    // Validate TEF correctness by counting syscalls.
    let mut tef_syscall_counts: HashMap<String, u32> = HashMap::new();
    if let serde_json::Value::Array(events) = parsed {
        for event in events {
            if let Some(name) = event.get("name").and_then(|n| n.as_str()) {
                *tef_syscall_counts.entry(name.to_string()).or_insert(0) += 1;
            }
        }
    }
    for count in tef_syscall_counts.values_mut() {
        *count /= 2; // Divide all counts by 2 since each syscall has start and end events.
    }
    // Compare TEF syscall counts to strace output on same program.
    let strace_output = run_strace(&program);
    let strace_counts = count_syscalls(&strace_output);
    for (syscall, count) in tef_syscall_counts {
        if IGNORED_SYSCALLS.contains(&syscall.as_str()) {
            continue;
        }
        if syscall == "exit_group" {
            continue; // strace summary ignores this.
        }
        let strace_count = strace_counts.get(syscall.as_str()).unwrap_or(&0);
        assert_eq!(
            count, *strace_count,
            "mismatch on {syscall}: rstrace has {count} but strace has {strace_count}"
        );
    }

    Ok(())
}

#[ignore]
#[test]
fn test_follow_forks() -> Result<()> {
    let mut f = std::io::BufWriter::new(Vec::new());
    let options = rstrace::TraceOptions {
        stats: rstrace::StatisticsOptions {
            summary: rstrace::SummaryOption::SummaryOnly,
        },
        follow_forks: true,
        cuda_verbose: false,
        ..Default::default()
    };

    let dir = tempdir::TempDir::new("test_follow_forks")?;
    let file_path = dir.path().join("script.sh");
    let mut file = std::fs::File::create(&file_path)?;
    writeln!(
        file,
        r#"#!/bin/bash
temp_file=$(mktemp)

write_to_file() {{
    echo "Child process $$ writing to the file." >> "$temp_file"
    sleep 1
}}
echo "Parent process $$ starts."

# Spawn the first child process in the background
(write_to_file) &
# Spawn the second child process using bash -c
bash -c "echo 'Child process $$ writing via bash -c.' >> $temp_file"

wait

echo "Contents of the file:"
cat "$temp_file"
rm -f "$temp_file"
"#
    )?;
    std::fs::set_permissions(
        &file_path,
        std::os::unix::fs::PermissionsExt::from_mode(0o755),
    )?;

    let script_path = file_path.to_str().unwrap().to_string();

    // rstrace
    let program: Vec<String> = vec!["bash".to_string(), script_path.clone()];
    trace_command(&program, &mut f, options).unwrap();
    let r_strace_output = String::from_utf8(f.into_inner().unwrap())?;
    println!("{}", r_strace_output);

    // strace
    let output = Command::new("strace")
        .args(&["-c", "-f", "bash", &script_path])
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
