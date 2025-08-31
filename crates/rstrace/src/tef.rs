//! Support for emitting Trace Event Format (TEF) trace files.
//! Originally created for Chromium, the TEF format is a JSON-based legacy
//! format that is simple to emit and still widely supported by tools such as Chrome,
//! Perfetto, and Catapult.
//!
//! ref: <https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU>.
use std::io::Write;

pub struct TefWriter {
    started: bool,
}

const CATEGORY: &str = "syscall";

#[derive(Debug)]
pub enum Phase {
    DurationBegin = b'B' as isize,
    DurationEnd = b'E' as isize,
    Complete = b'X' as isize,
}

impl Phase {
    pub fn as_str(&self) -> &'static str {
        match self {
            Phase::DurationBegin => "B",
            Phase::DurationEnd => "E",
            Phase::Complete => "X",
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl TefWriter {
    pub fn new() -> Self {
        TefWriter { started: false }
    }

    /// Write a DurationBegin event directly to the output stream.
    pub fn write_duration_start(
        &mut self,
        output: &mut dyn Write,
        name: &str,
        timestamp: u64,
        pid: u32,
        tid: u32,
    ) -> std::io::Result<()> {
        let phase = Phase::DurationBegin;
        if !self.started {
            self.started = true;
            output.write_all(b"[\n")?; // Begin the JSON array.
        }
        write!(
            output,
            "{{\"name\": \"{}\", \"ts\": {}, \"cat\": \"{}\", \"ph\": \"{}\", \"pid\": {}, \"tid\": {}, \"args\": {{}}}},\n",
            name, timestamp, CATEGORY, phase, pid, tid
        )
    }

    /// Write a DurationEnd event directly to the output stream.
    pub fn write_duration_end(
        &mut self,
        output: &mut dyn Write,
        name: &str,
        timestamp: u64,
        pid: u32,
        tid: u32,
    ) -> std::io::Result<()> {
        let phase = Phase::DurationEnd;
        if !self.started {
            self.started = true;
            output.write_all(b"[\n")?; // Begin the JSON array.
        }
        write!(
            output,
            "{{\"name\": \"{}\", \"ts\": {}, \"cat\": \"{}\", \"ph\": \"{}\", \"pid\": {}, \"tid\": {}, \"args\": {{}}}},\n",
            name, timestamp, CATEGORY, phase, pid, tid
        )
    }

    /// Even though the TEF spec does not require that trace files are valid JSON,
    /// <ui.perfetto.dev> crashes with an assertion error if we do not emit valid JSON.
    pub fn finalize(
        &mut self,
        output: &mut dyn Write,
        timestamp: u64,
        pid: u32,
        tid: u32,
    ) -> std::io::Result<()> {
        // NB: emitting a final event is easier than removing the last comma of the previous event.
        let phase = Phase::Complete;
        if !self.started {
            self.started = true;
            output.write_all(b"[\n")?; // Begin the JSON array if no events were written.
        }
        write!(
            output,
            "{{\"name\": \"END\", \"ts\": {}, \"dur\": 0, \"cat\": \"END\", \"ph\": \"{}\", \"pid\": {}, \"tid\": {}, \"args\": {{}}}}\n",
            timestamp, phase, pid, tid
        )?;
        output.write_all(b"]")?;
        Ok(())
    }
}
