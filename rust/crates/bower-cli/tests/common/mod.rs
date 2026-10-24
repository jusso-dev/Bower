//! Shared helpers: run the built `bower` binary and locate repository assets.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// Bower repository root (resolves symlinked workspaces).
pub fn repo_root() -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = manifest
        .canonicalize()
        .unwrap_or_else(|_| manifest.to_path_buf());
    manifest
        .ancestors()
        .nth(3)
        .expect("repo root above rust/crates/bower-cli")
        .to_path_buf()
}

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl From<Output> for Run {
    fn from(output: Output) -> Self {
        Self {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}

pub fn command(binary: &Path, args: &[&str], cwd: &Path) -> Command {
    let mut command = Command::new(binary);
    command
        .args(args)
        .current_dir(cwd)
        .env_remove("BOWER_INGEST_TOKEN")
        .env("DOTNET_CLI_TELEMETRY_OPTOUT", "1");
    command
}

pub fn bower_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_bower"))
}

/// Runs the Rust `bower` with `cwd`.
pub fn bower_in(cwd: &Path, args: &[&str]) -> Run {
    command(&bower_binary(), args, cwd)
        .output()
        .expect("run bower")
        .into()
}

/// Runs the Rust `bower` from the repository root.
pub fn bower(args: &[&str]) -> Run {
    bower_in(&repo_root(), args)
}

/// Accepts one HTTP request, replies with `status` and `body`, returns the raw request
/// (empty when nothing connects within 30 s).
pub fn one_shot_server(
    status: &'static str,
    body: &'static str,
) -> (String, std::thread::JoinHandle<String>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        // Give up after 30 s so a client that never connects cannot hang the test.
        listener.set_nonblocking(true).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() > deadline {
                        return String::new();
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).unwrap();
            request.extend_from_slice(&buffer[..read]);
            let text = String::from_utf8_lossy(&request).into_owned();
            if let Some(split) = text.find("\r\n\r\n") {
                let length = text[..split]
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|v| v.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if request.len() >= split + 4 + length {
                    break;
                }
            }
            if read == 0 {
                break;
            }
        }
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
        String::from_utf8_lossy(&request).into_owned()
    });
    (address, handle)
}

/// Sample events stamped now (the intake rejects times outside its window).
pub fn policy_samples(dir: &Path) -> (String, String, String) {
    use bower_contracts::time::Clock as _;
    let now = bower_contracts::time::SystemClock.utc_now().to_rfc3339();
    let event = |id: &str, category: &str, kind: &str, extra: &str| {
        format!(
            "{{\"schemaVersion\":\"1.0.0\",\"eventId\":\"{id}\",\"timeGenerated\":\"{now}\",\"eventCategory\":\"{category}\",\"eventType\":\"{kind}\",\"eventAction\":\"authentication.attempt\",\"eventResult\":\"failure\",\"eventOutcomeReason\":\"InvalidPassword\",\"application\":{{\"name\":\"App\",\"environment\":\"test\"}},\"actor\":{{\"username\":\"u\"}},\"source\":{{\"ipAddress\":\"192.0.2.10\"}},\"request\":{{\"correlationId\":\"c-1\"}}{extra}}}"
        )
    };
    let write = |name: &str, content: String| {
        let path = dir.join(name);
        std::fs::write(&path, content).unwrap();
        path.to_str().unwrap().to_owned()
    };
    (
        write(
            "secret.json",
            event(
                "evt-1",
                "authentication",
                "authentication_failure",
                ",\"attributes\":{\"password\":\"never-print\"}",
            ),
        ),
        write("noise.json", event("evt-2", "telemetry", "page_view", "")),
        write("broken.json", "{".into()),
    )
}
