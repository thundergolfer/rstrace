//! Support for emitting Trace Event Format (TEF) trace files.
//! Originally created for Chromium, the TEF format is a JSON-based legacy
//! format that is simple to emit and still widely supported by tools such as Chrome,
//! Perfetto, and Catapult.
//!
//! ref: <https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU>.

use std::io::{self, Write};
use std::time::Duration;

pub struct TefWriter<'a> {
    output: &'a mut dyn Write,
}

impl<'a> TefWriter<'a> {
    pub fn new(output: &'a mut dyn Write) -> io::Result<Self> {
        output.write_all(b"[\n")?;
        Ok(TefWriter { output })
    }

    pub fn emit_event(&mut self, name: &str, timestamp: u64, duration: Duration) -> io::Result<()> {
        let d_secs = duration.as_secs_f64();
        let e = format!(
            "{{\"name\": \"{name}\", \"ts\": {timestamp}, \"dur\": {d_secs}, \"cat\": \"hi\", \"ph\": \"X\", \"pid\": 1, \"tid\": 1, \"args\": {{}}}}\n"
        );

        writeln!(self.output, "{}", e)
    }
}

impl<'a> Drop for TefWriter<'a> {
    fn drop(&mut self) {
        // NB: This closing bracket isn't actually required by the spec.
        if let Err(e) = self.output.write_all(b"\n]") {
            eprintln!("failed to write closing bracket: {}", e);
        }
        if let Err(e) = self.output.flush() {
            eprintln!("failed to flush output: {}", e);
        }
    }
}
