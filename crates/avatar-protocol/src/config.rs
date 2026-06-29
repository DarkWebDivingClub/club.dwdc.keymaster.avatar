use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};

/// Load a TOML config file for a binary.
///
/// Search order:
/// 1. `cli_path` — explicit `--config <path>` from the CLI
/// 2. `~/.config/keymaster-avatar/<binary_name>.toml`
/// 3. `/etc/keymaster-avatar/<binary_name>.toml`
/// 4. None — caller should use defaults
pub fn load_config<T: DeserializeOwned>(binary_name: &str, cli_path: Option<&Path>) -> Option<T> {
    let candidates: Vec<PathBuf> = if let Some(p) = cli_path {
        vec![p.to_path_buf()]
    } else {
        let mut v = Vec::new();
        if let Some(home) = std::env::var_os("HOME") {
            v.push(
                PathBuf::from(home)
                    .join(".config/keymaster-avatar")
                    .join(format!("{}.toml", binary_name)),
            );
        }
        v.push(PathBuf::from(format!(
            "/etc/keymaster-avatar/{}.toml",
            binary_name
        )));
        v
    };

    for path in &candidates {
        if let Ok(contents) = std::fs::read_to_string(path) {
            match toml::from_str::<T>(&contents) {
                Ok(config) => {
                    eprintln!("{}: loaded config from {}", binary_name, path.display());
                    return Some(config);
                }
                Err(e) => {
                    eprintln!(
                        "{}: failed to parse {}: {}",
                        binary_name,
                        path.display(),
                        e
                    );
                }
            }
        }
    }

    None
}
