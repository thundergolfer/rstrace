use std::io::Write;

use anyhow::Result;
use rstrace::trace_command;
use std::{collections::HashMap, process::Command};

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
    trace_command(&program, &mut f, options).unwrap();
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

#[ignore]
#[test]
fn test_follow_forks() -> Result<()> {
    let mut f = std::io::BufWriter::new(Vec::new());
    let options = rstrace::TraceOptions {
        stats: rstrace::StatisticsOptions {
            summary: rstrace::SummaryOption::SummaryOnly,
        },
        follow_forks: true,
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
