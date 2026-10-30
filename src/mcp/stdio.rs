use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

use super::PARSE_ERROR;
use super::gateway::Gateway;

/// Runs the gateway over stdin/stdout: one JSON message per line in, one per
/// line out. Returns when stdin closes.
pub fn serve_stdio(gateway: &Gateway, runtime: &tokio::runtime::Runtime) -> io::Result<()> {
    let mut stdout = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(message) => runtime.block_on(gateway.handle(message)),
            Err(err) => Some(json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": PARSE_ERROR, "message": err.to_string() },
            })),
        };
        if let Some(reply) = reply {
            serde_json::to_writer(&mut stdout, &reply)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
    }
    Ok(())
}
