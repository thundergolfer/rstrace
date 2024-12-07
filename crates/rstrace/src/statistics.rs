//! Implements the functionality corresponding to the 'Statistics' section of strace's
//! option configuration.
use std::collections::HashMap;

use prettytable::{
    format::{FormatBuilder, LinePosition, LineSeparator},
    Cell, Row, Table,
};

use crate::info::EXIT_GROUP_N;
use crate::info::SYSCALL_MAP;

/// Struct to hold statistics for a single syscall.
#[derive(Debug, Default, Clone)]
pub struct SyscallStat {
    /// The number of times the syscall was called.
    pub calls: u64,
    /// The total time spent in the syscall.
    pub latency: std::time::Duration,
    /// The number of errors encountered during the syscall.
    pub errors: u64,
}

/// Convert the summary statistics to a table in the same format as strace's tables.
pub fn summary_to_table(
    summary_stats: HashMap<u64, SyscallStat>,
    trace_duration: std::time::Duration,
) -> String {
    let mut table = Table::new();
    let format = FormatBuilder::new()
        .column_separator(' ')
        .separator(LinePosition::Title, LineSeparator::new('-', ' ', ' ', ' '))
        .padding(1, 1)
        .build();
    table.set_format(format);
    // % time     seconds  usecs/call     calls    errors syscall
    // ------ ----------- ----------- --------- --------- ----------------
    table.set_titles(Row::new(vec![
        Cell::new_align("% time", prettytable::format::Alignment::RIGHT),
        Cell::new_align("seconds", prettytable::format::Alignment::RIGHT),
        Cell::new_align("usecs/call", prettytable::format::Alignment::RIGHT),
        Cell::new_align("calls", prettytable::format::Alignment::RIGHT),
        Cell::new_align("errors", prettytable::format::Alignment::RIGHT),
        Cell::new_align("syscall", prettytable::format::Alignment::LEFT),
    ]));

    // Sort by latency
    let mut sorted_stats: Vec<_> = summary_stats.into_iter().collect();
    sorted_stats.sort_by(|a, b| b.1.latency.cmp(&a.1.latency));
    for (syscall_num, stat) in sorted_stats {
        if syscall_num == EXIT_GROUP_N {
            // strace doesn't include this syscall in summaries, presumably because
            // there's always exactly one exit_group call per process.
            continue;
        }
        let name = SYSCALL_MAP
            .get(&syscall_num)
            .map(|s| s.0)
            .unwrap_or("unknown");
        table.add_row(Row::new(vec![
            Cell::new_align(
                &format!(
                    "{:>6.2}",
                    (stat.latency.as_secs_f64() / trace_duration.as_secs_f64()) * 100.0
                ),
                prettytable::format::Alignment::RIGHT,
            ),
            Cell::new_align(
                &format!("{:>6.6}", stat.latency.as_secs_f64()),
                prettytable::format::Alignment::RIGHT,
            ),
            // TODO(Jonathon): add 'usecs/call' value
            Cell::new_align(&format!("{:>9}", 0), prettytable::format::Alignment::RIGHT),
            Cell::new_align(
                &format!("{:>8}", stat.calls),
                prettytable::format::Alignment::RIGHT,
            ),
            if stat.errors > 0 {
                Cell::new_align(
                    &format!("{:>8}", stat.errors),
                    prettytable::format::Alignment::RIGHT,
                )
            } else {
                Cell::new_align(
                    &format!("{:>8}", " "),
                    prettytable::format::Alignment::RIGHT,
                )
            },
            Cell::new_align(
                &format!("{:<18}", name),
                prettytable::format::Alignment::LEFT,
            ),
        ]));
    }

    table.to_string()
}
