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

impl TefWriter {
    pub fn new() -> Self {
        TefWriter { started: false }
    }

    // TODO(Jonathon): include args in the event.
    pub fn emit_duration_start(&mut self, name: &str, timestamp: u64) -> String {
        let e = format!(
            "{{\"name\": \"{name}\", \"ts\": {timestamp}, \"cat\": \"hi\", \"ph\": \"B\", \"pid\": 1, \"tid\": 1, \"args\": {{}}}},\n"
        );

        self.emit_event(e)
    }

    // TODO(Jonathon): include args and exit code (+ errno) in the event.
    pub fn emit_duration_end(&mut self, name: &str, timestamp: u64) -> String {
        let e = format!(
            "{{\"name\": \"{name}\", \"ts\": {timestamp}, \"cat\": \"hi\", \"ph\": \"E\", \"pid\": 1, \"tid\": 1, \"args\": {{}}}},\n"
        );
        self.emit_event(e)
    }

    fn emit_event(&mut self, e: String) -> String {
        if !self.started {
            self.started = true;
            format!("[\n{e}") // Begin the JSON array.
        } else {
            e
        }
    }

    /// Even though the TEF spec does not require that trace files are valid JSON,
    /// <ui.perfetto.dev> crashes with an assertion error if we do not emit valid JSON.
    pub fn finalize(&mut self, output: &mut dyn Write, timestamp: u64) -> std::io::Result<()> {
        // NB: emitting a final event is easier than removing the last comma of the previous event.
        let final_event = format!("{{\"name\": \"END\", \"ts\": {timestamp}, \"dur\": 0, \"cat\": \"hi\", \"ph\": \"X\", \"pid\": 1, \"tid\": 1, \"args\": {{}}}}\n");
        output.write(&mut self.emit_event(final_event).as_bytes())?;
        output.write_all(b"]")?;
        Ok(())
    }
}
