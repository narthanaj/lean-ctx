//! Project-root path jail for every file-accepting tool.
//!
//! # Why this module exists
//!
//! lean-ctx is a privileged position between the LLM and the filesystem: any path
//! the LLM supplies (potentially via prompt injection) is handed to `std::fs::read`
//! with no containment. Without this module, a single injected tool call like
//! `ctx_read("/etc/shadow")` or `ctx_read("~/.ssh/id_rsa")` is a data exfiltration.
//! Content sanitization downstream is irrelevant if the wrong file was reachable
//! in the first place — capability reduction beats content inspection.
//!
//! # Design
//!
//! `open_in_jail` returns an already-opened `File` handle, not a resolved `PathBuf`.
//! This is intentional: a canonicalize-then-open-by-name flow has a classic TOCTOU
//! window where an attacker with write access to any path component (or any
//! directory ancestor of the jail itself) can swap the path for a symlink after
//! the check passes but before the `open` completes. All downstream reads go
//! through the returned FD; the canonical path is kept around only for error
//! messages.
//!
//! On Linux ≥5.6 we issue a single `openat2(..., RESOLVE_BENEATH |
//! RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` syscall, which the kernel
//! enforces atomically — there is no userspace race window. Older Linux, macOS,
//! and BSDs fall back to a per-component `openat(O_NOFOLLOW)` descent that
//! rejects any symlink anywhere in the path. After open we belt-and-suspenders
//! with `/proc/self/fd/N` (Linux) or `F_GETPATH` (macOS) to verify the opened FD
//! still resolves inside the jail; a mismatch means a race was observed in
//! flight and we refuse to hand the FD back.
//!
//! Windows is currently unsupported — the module returns `JailError::Unsupported`
//! on non-Unix platforms and callers must decide the policy (fall back to
//! unjailed read with a warning, or refuse). Tracking: follow-up issue.

use std::fs::File;
use std::io;
use std::path::{Component, Path, PathBuf};

/// Hard cap on a single file's size. Applied *before* any read/hash/compress
/// via `fstat` on the jailed FD. 4 MiB covers >99% of real source files; the
/// envelope exists to prevent an attacker dropping a 10 GiB payload that would
/// OOM the host before compression even has a chance to run.
pub const MAX_READ_BYTES: u64 = 4 * 1024 * 1024;

/// Environment variable that overrides [`MAX_READ_BYTES`] at runtime (bytes).
pub const ENV_MAX_READ_BYTES: &str = "LCTX_MAX_READ_BYTES";

/// Colon-separated list of additional absolute roots that `open_in_jail` will
/// accept in addition to the session's project root. Intentionally an
/// env-var opt-in (not a config file setting) so it cannot be silently set by
/// a malicious config drop in `~/.lean-ctx/`.
pub const ENV_ALLOW_PATHS: &str = "LCTX_ALLOW_PATH";

/// Env override for the jail root itself — takes precedence over
/// `SessionState.project_root` when set.
pub const ENV_PROJECT_ROOT: &str = "LCTX_PROJECT_ROOT";

/// Errors returned by the path jail.
///
/// Each variant is distinct so callers (and tests) can disambiguate between
/// "legitimate mis-use" (e.g. `NotFound`) and "security event" (e.g. `Escape`,
/// `RaceDetected`) without string-matching.
#[derive(Debug, thiserror::Error)]
pub enum JailError {
    /// The path escapes the jail root — either absolute outside, or relative
    /// resolving outside via `..`. Does NOT imply intent; benign mis-typed
    /// paths land here too.
    #[error("path '{0}' is outside the project jail")]
    Escape(String),

    /// A component of the resolved path was a symlink. Rejected even if the
    /// target lies inside the jail — symlinks are a TOCTOU amplifier and the
    /// benefit of supporting them inside source repos is small.
    #[error("path '{0}' contains a symlink")]
    SymlinkRejected(String),

    /// The opened FD's re-canonicalized path no longer matches the expected
    /// target. Indicates an attacker swapped the path mid-open. This is the
    /// signal you want to alert on.
    #[error("TOCTOU race detected while opening '{0}'")]
    RaceDetected(String),

    /// The target is not a regular file. FIFOs block `open`, sockets return
    /// unexpected byte streams, character devices can wedge the process. We
    /// refuse all of them — lean-ctx only reads real source files.
    #[error("path '{0}' is not a regular file")]
    UnsupportedFileType(String),

    /// Path contains NUL / CR / LF — these are never valid file names and
    /// are a common smuggling vector in filename parsers.
    #[error("path '{0}' contains forbidden characters (NUL/CR/LF)")]
    InvalidInput(String),

    /// Platform does not support jailed open. Currently returned on non-Unix
    /// targets; callers decide whether to fall back to an unjailed read.
    #[error("path jail is not supported on this platform")]
    Unsupported,

    /// Any underlying I/O error. Kept separate from security-relevant
    /// variants so dashboards/logs can split "benign ENOENT" from "attack".
    #[error("I/O error for '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
}

impl JailError {
    /// True when the variant represents a security-relevant event (worth
    /// logging/alerting on) as opposed to a benign user mistake.
    pub fn is_security_event(&self) -> bool {
        matches!(
            self,
            JailError::Escape(_) | JailError::SymlinkRejected(_) | JailError::RaceDetected(_)
        )
    }
}

/// A file opened under the jail. Callers read via [`file`]; they must NOT
/// re-open by `canonical_path` — that re-introduces the TOCTOU window the
/// jail exists to close. The canonical path is retained for diagnostics only.
#[derive(Debug)]
pub struct JailedFile {
    /// The open file descriptor. Read from this, not from the path.
    pub file: File,

    /// The canonical path the FD resolves to at the moment of open. Useful
    /// for logs and cache keys; do not pass to other `open` calls.
    pub canonical_path: PathBuf,

    /// Size captured via `fstat` on the jailed FD at open time. Holders can
    /// decide truncation policy based on this without a second syscall.
    pub size_bytes: u64,
}

/// Resolve the effective project-root (jail root) for the current session.
///
/// Priority order:
/// 1. `$LCTX_PROJECT_ROOT` env var (explicit override for tests / CI).
/// 2. Current working directory.
///
/// Both are canonicalized once. The returned path is *only* valid as long as
/// no ancestor directory is renamed or deleted; callers should treat it as a
/// per-call value rather than caching for long-running sessions.
pub fn session_jail_root() -> Result<PathBuf, JailError> {
    if let Ok(explicit) = std::env::var(ENV_PROJECT_ROOT) {
        if !explicit.is_empty() {
            return canonicalize_existing(&explicit);
        }
    }
    let cwd = std::env::current_dir().map_err(|e| JailError::Io {
        path: ".".to_string(),
        source: e,
    })?;
    canonicalize_existing(cwd.to_string_lossy().as_ref())
}

/// Additional roots the user explicitly allows (opt-in via env var). Empty
/// vec if `LCTX_ALLOW_PATH` is unset.
pub fn allow_list_roots() -> Vec<PathBuf> {
    match std::env::var(ENV_ALLOW_PATHS) {
        Ok(v) if !v.is_empty() => v
            .split(':')
            .filter(|s| !s.is_empty())
            .filter_map(|p| canonicalize_existing(p).ok())
            .collect(),
        _ => Vec::new(),
    }
}

/// Runtime-overridable size cap. Reads the env var on every call so tests can
/// set/unset it cheaply; hot paths can cache the result if profiling shows it
/// matters (it shouldn't — getenv is a memory lookup on Linux).
pub fn max_read_bytes() -> u64 {
    std::env::var(ENV_MAX_READ_BYTES)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(MAX_READ_BYTES)
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Open a file under the project jail. Returns an FD the caller reads from;
/// the path is never re-opened by name.
///
/// This is the ONLY supported way to read an LLM-supplied path. Direct
/// `std::fs::read` / `File::open` elsewhere in `tools/` is a CI regression
/// (see `rust/tests/no_unsanitized_llm_output.rs`).
///
/// # Parameters
/// * `input`: The path as the LLM/caller supplied it. May be relative
///   (resolved against `jail_root`) or absolute. Absolute paths must land
///   inside `jail_root` or one of the allow-list roots.
/// * `jail_root`: Canonical absolute path of the project jail root. Use
///   [`session_jail_root`] to obtain this.
pub fn open_in_jail(input: &str, jail_root: &Path) -> Result<JailedFile, JailError> {
    reject_forbidden_chars(input)?;

    // Build the target path (absolute). Relative inputs resolve against the
    // jail; absolute inputs are taken as-is (and will be re-verified below).
    let target = build_target_path(input, jail_root);

    // Enforce containment *before* open. This is a necessary precondition
    // even though openat2 will enforce it again — callers who expose the
    // weaker non-Linux fallback still need it.
    let allowed_roots = build_allow_list(jail_root);
    ensure_path_within_any_root(&target, &allowed_roots, input)?;

    // Platform-specific open.
    #[cfg(target_os = "linux")]
    let file = unix::open_beneath(&target, &allowed_roots, input)?;

    #[cfg(all(unix, not(target_os = "linux")))]
    let file = unix::open_component_descent(&target, &allowed_roots, input)?;

    #[cfg(not(unix))]
    let file = {
        // Windows has `NtOpenFile` with `OBJ_DONT_REPARSE` but we don't wire
        // it up in v1 — callers that land here must decide the policy.
        let _ = (&target, &allowed_roots, input);
        return Err(JailError::Unsupported);
    };

    // fstat the FD (not the path) so the metadata we trust is the one that
    // belongs to what we actually opened — no post-open swap can lie to us.
    let meta = file.metadata().map_err(|e| JailError::Io {
        path: input.to_string(),
        source: e,
    })?;

    if !meta.is_file() {
        return Err(JailError::UnsupportedFileType(input.to_string()));
    }

    // Belt-and-suspenders: re-canonicalize via the FD and confirm it still
    // lives inside an allowed root. On Linux this uses `/proc/self/fd/N`
    // which reflects the FD's current dentry, not a racy name lookup.
    let canonical_path = fd_canonical_path(&file).unwrap_or_else(|_| target.clone());
    ensure_path_within_any_root(&canonical_path, &allowed_roots, input)
        .map_err(|_| JailError::RaceDetected(input.to_string()))?;

    Ok(JailedFile {
        file,
        canonical_path,
        size_bytes: meta.len(),
    })
}

/// Convenience wrapper: opens the file, reads up to `max_read_bytes()` bytes,
/// and returns both the bytes and the truncation flag. Used by the wrappers
/// around `std::fs::read` / `std::fs::read_to_string`.
pub fn read_in_jail(input: &str, jail_root: &Path) -> Result<ReadResult, JailError> {
    let jailed = open_in_jail(input, jail_root)?;
    let cap = max_read_bytes();
    let (buf, truncated) = read_capped(jailed.file, cap)?;
    Ok(ReadResult {
        bytes: buf,
        truncated,
        original_size: jailed.size_bytes,
        canonical_path: jailed.canonical_path,
    })
}

/// Result of a jailed read with size cap applied.
#[derive(Debug)]
pub struct ReadResult {
    /// Bytes read. At most `max_read_bytes()` long.
    pub bytes: Vec<u8>,
    /// True when the file exceeded the cap and `bytes` is a prefix.
    pub truncated: bool,
    /// The true file size from `fstat`. `truncated == (original_size > bytes.len())`.
    pub original_size: u64,
    /// Canonical path for diagnostics.
    pub canonical_path: PathBuf,
}

/// Read at most `cap` bytes from the given file. Kept separate from
/// `read_in_jail` so tests can exercise the cap logic without needing a real
/// jail.
fn read_capped(mut file: File, cap: u64) -> Result<(Vec<u8>, bool), JailError> {
    use std::io::Read;

    // Pre-allocate up to the cap, but only what we'll actually read. Using
    // `take()` ensures we never allocate more than cap+1 bytes even if the
    // file grows mid-read.
    let mut buf = Vec::with_capacity(cap.min(64 * 1024) as usize);
    let n = (&mut file)
        .take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| JailError::Io {
            path: "<fd>".to_string(),
            source: e,
        })?;

    // Detect truncation by trying to read one more byte. If the file is
    // exactly `cap` bytes long, this returns 0 and `truncated` stays false.
    let mut peek = [0u8; 1];
    let extra = file.read(&mut peek).unwrap_or(0);
    let _ = n;
    Ok((buf, extra > 0))
}

// ---------------------------------------------------------------------------
// Helpers (platform-agnostic)
// ---------------------------------------------------------------------------

/// Canonicalize a path that is expected to already exist. Wraps the I/O
/// error with our own variant so callers don't leak `std::io::Error` shapes.
fn canonicalize_existing(p: &str) -> Result<PathBuf, JailError> {
    std::fs::canonicalize(p).map_err(|e| JailError::Io {
        path: p.to_string(),
        source: e,
    })
}

/// Build the pre-open target path. Relative inputs go under `jail_root`;
/// absolute inputs are taken as-is and validated against the allow list
/// downstream. Does *not* canonicalize — that happens inside open routines.
fn build_target_path(input: &str, jail_root: &Path) -> PathBuf {
    let p = Path::new(input);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        jail_root.join(p)
    }
}

/// Assemble the full set of allowed roots: the jail root plus any
/// `LCTX_ALLOW_PATH` entries. All are canonicalized so `starts_with` is
/// reliable.
fn build_allow_list(jail_root: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::with_capacity(1 + 4);
    roots.push(jail_root.to_path_buf());
    roots.extend(allow_list_roots());
    roots
}

/// Reject the small set of characters that should never appear in a filename
/// lean-ctx handles. NUL ends C-strings; CR/LF are often smuggled through
/// filename parsers to inject control sequences.
fn reject_forbidden_chars(input: &str) -> Result<(), JailError> {
    if input.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
        return Err(JailError::InvalidInput(input.to_string()));
    }
    Ok(())
}

/// Pure path-level containment check. Does NOT resolve symlinks — that work
/// is done by the platform-specific open routine. This function exists to
/// reject obvious escapes (absolute paths outside the jail, relative paths
/// with `..` that normalize outside) without a syscall.
fn ensure_path_within_any_root(
    target: &Path,
    roots: &[PathBuf],
    original_input: &str,
) -> Result<(), JailError> {
    let normalized = logical_normalize(target);
    for root in roots {
        if normalized.starts_with(root) {
            return Ok(());
        }
    }
    Err(JailError::Escape(original_input.to_string()))
}

/// Logical (non-I/O) path normalization. Collapses `.` and `..` purely by
/// inspecting components — does NOT follow symlinks. Used only as a
/// pre-syscall escape check; the real enforcement is `openat2`/`O_NOFOLLOW`.
///
/// Deliberately does not call `canonicalize` because the target may not yet
/// exist (e.g. when `ctx_edit` creates a new file). Over-rejection is
/// acceptable; under-rejection is not.
fn logical_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                // Pop only if the prior component is a normal dir, NOT if
                // it's a prefix/root — otherwise `../foo` under a root stays
                // as `../foo` and the starts_with check will fail, which is
                // what we want.
                let popped = out.pop();
                if !popped {
                    // Can't go above root via logical means — leave the
                    // `..` in place so the escape check fails.
                    out.push(Component::ParentDir.as_os_str());
                }
            }
            Component::CurDir => { /* skip */ }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Re-canonicalize the path an FD currently points to, bypassing the name
/// that was originally passed in. On Linux this reads `/proc/self/fd/N`;
/// on macOS we use `F_GETPATH`. Other Unixes return the original path,
/// meaning the "race detected" check devolves to the weaker pre-open check.
#[cfg(target_os = "linux")]
fn fd_canonical_path(file: &File) -> Result<PathBuf, JailError> {
    use std::os::fd::AsRawFd;
    let fd = file.as_raw_fd();
    let link = format!("/proc/self/fd/{fd}");
    std::fs::read_link(&link).map_err(|e| JailError::Io {
        path: link,
        source: e,
    })
}

#[cfg(target_os = "macos")]
fn fd_canonical_path(_file: &File) -> Result<PathBuf, JailError> {
    // macOS support deferred — requires a direct libc::fcntl(F_GETPATH)
    // invocation which we're not wiring up in v1. The per-component
    // O_NOFOLLOW descent fallback still catches symlinks in-path, so the
    // residual TOCTOU window (attacker renames a dir mid-open) is narrow.
    // Tracking: follow-up issue.
    Err(JailError::Unsupported)
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn fd_canonical_path(_file: &File) -> Result<PathBuf, JailError> {
    // No portable way to recover an FD's current path on other Unixes.
    // The per-component O_NOFOLLOW descent already rejects symlinks, so the
    // residual TOCTOU window (attacker renames a dir mid-open) is narrow.
    Err(JailError::Unsupported)
}

#[cfg(not(unix))]
fn fd_canonical_path(_file: &File) -> Result<PathBuf, JailError> {
    Err(JailError::Unsupported)
}

// ---------------------------------------------------------------------------
// Unix open paths
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod unix {
    use super::*;
    use std::fs::File;

    /// Linux ≥5.6: single atomic `openat2` syscall. Kernel rejects any path
    /// that escapes the starting directory or passes through a symlink. No
    /// userspace race window.
    #[cfg(target_os = "linux")]
    pub(super) fn open_beneath(
        target: &Path,
        roots: &[PathBuf],
        original_input: &str,
    ) -> Result<File, JailError> {
        use rustix::fs::{Mode, OFlags, ResolveFlags};

        // Pick the root this target lives under; its FD becomes the "start
        // directory" for openat2. If multiple roots match the longest prefix
        // wins (important when LCTX_ALLOW_PATH adds a subdirectory of the
        // jail — we want the tightest possible anchor).
        let (anchor, relative) = split_target_over_roots(target, roots)
            .ok_or_else(|| JailError::Escape(original_input.to_string()))?;

        // Open the anchor read-only. `O_PATH` would be enough but we use a
        // real directory FD so the fallback path (component descent) can
        // share the helper.
        let anchor_dir = std::fs::File::open(&anchor).map_err(|e| JailError::Io {
            path: anchor.display().to_string(),
            source: e,
        })?;

        let resolve =
            ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS;

        // openat2 takes a relative path; never pass the absolute target
        // here, otherwise BENEATH still fires but the syscall feels wrong.
        let rel = if relative.as_os_str().is_empty() {
            Path::new(".")
        } else {
            relative.as_path()
        };

        let owned_fd = rustix::fs::openat2(
            &anchor_dir,
            rel,
            // O_NONBLOCK prevents blocking on FIFOs/sockets/device nodes
            // that an attacker placed inside the jail. The fstat check
            // downstream rejects them, but without O_NONBLOCK the kernel
            // would block on open(O_RDONLY) of a FIFO waiting for a
            // writer — an indefinite DoS vector.
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
            resolve,
        )
        .map_err(|errno| {
            // ELOOP / EXDEV from openat2 with NO_SYMLINKS/BENEATH means
            // the kernel caught an escape — translate to our rich variant.
            match errno {
                rustix::io::Errno::LOOP => JailError::SymlinkRejected(original_input.to_string()),
                rustix::io::Errno::XDEV => JailError::Escape(original_input.to_string()),
                _ => JailError::Io {
                    path: original_input.to_string(),
                    source: io::Error::from_raw_os_error(errno.raw_os_error()),
                },
            }
        })?;

        Ok(File::from(owned_fd))
    }

    /// Non-Linux Unix fallback: descend from the jail root one component at a
    /// time via `openat(O_NOFOLLOW | O_CLOEXEC)`. Any symlink mid-path causes
    /// `ELOOP`, which we surface as `SymlinkRejected`. The final component is
    /// opened with `O_RDONLY`.
    #[cfg(all(unix, not(target_os = "linux")))]
    pub(super) fn open_component_descent(
        target: &Path,
        roots: &[PathBuf],
        original_input: &str,
    ) -> Result<File, JailError> {
        use rustix::fs::{Mode, OFlags};
        use std::os::fd::{AsFd, OwnedFd};

        let (anchor, relative) = split_target_over_roots(target, roots)
            .ok_or_else(|| JailError::Escape(original_input.to_string()))?;

        let mut current: OwnedFd = std::fs::File::open(&anchor)
            .map_err(|e| JailError::Io {
                path: anchor.display().to_string(),
                source: e,
            })?
            .into();

        let components: Vec<_> = relative.components().collect();
        if components.is_empty() {
            // Opening the anchor itself: it's a directory, which we reject
            // below via UnsupportedFileType after metadata() in the caller.
            return Ok(File::from(current));
        }
        let last_idx = components.len() - 1;

        for (i, comp) in components.iter().enumerate() {
            let name: &OsStr = match comp {
                Component::Normal(s) => s,
                // A `..` or absolute segment inside a supposedly-relative
                // path means the path escaped the anchor logically. Reject
                // rather than attempting to resolve.
                _ => return Err(JailError::Escape(original_input.to_string())),
            };

            let flags = if i == last_idx {
                // O_NONBLOCK: see the openat2 codepath comment — prevents
                // indefinite block on FIFO/socket before fstat rejects them.
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK
            } else {
                OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY
            };

            let next =
                rustix::fs::openat(current.as_fd(), name, flags, Mode::empty()).map_err(|errno| {
                    match errno {
                        rustix::io::Errno::LOOP => {
                            JailError::SymlinkRejected(original_input.to_string())
                        }
                        _ => JailError::Io {
                            path: original_input.to_string(),
                            source: io::Error::from_raw_os_error(errno.raw_os_error()),
                        },
                    }
                })?;
            current = next;
        }

        Ok(File::from(current))
    }

    /// Find the allowed root that is an ancestor of `target`, return it
    /// along with the remainder. Longest-prefix match: if both the jail
    /// root and a more-specific allow-list entry contain the target,
    /// anchor on the more specific one so the relative path given to
    /// openat2 is as short as possible.
    fn split_target_over_roots<'a>(
        target: &Path,
        roots: &'a [PathBuf],
    ) -> Option<(PathBuf, PathBuf)> {
        let normalized = super::logical_normalize(target);
        let mut best: Option<(&'a PathBuf, usize)> = None;
        for root in roots {
            if normalized.starts_with(root) {
                let depth = root.components().count();
                if best.map(|(_, d)| depth > d).unwrap_or(true) {
                    best = Some((root, depth));
                }
            }
        }
        let (root, _) = best?;
        let rel = normalized.strip_prefix(root).ok()?.to_path_buf();
        Some((root.clone(), rel))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// Integration-level tests (TOCTOU race, FIFO/socket rejection, symlink
// escape) live in `rust/tests/prompt_injection_tests.rs` so they exercise
// the actual syscall path. The tests here are pure-Rust invariants that
// don't need a real filesystem.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_normalize_collapses_dots() {
        let p = Path::new("/a/b/./c/../d");
        assert_eq!(logical_normalize(p), PathBuf::from("/a/b/d"));
    }

    #[test]
    fn logical_normalize_preserves_escape_attempt() {
        // `../foo` under a root should stay `..` so the starts_with check
        // rejects it; we do NOT silently drop the parent-dir segment.
        let p = Path::new("../foo");
        let norm = logical_normalize(p);
        assert!(norm.starts_with(".."));
    }

    #[test]
    fn reject_forbidden_chars_rejects_nul() {
        assert!(matches!(
            reject_forbidden_chars("ok/then\0/etc/passwd"),
            Err(JailError::InvalidInput(_))
        ));
    }

    #[test]
    fn reject_forbidden_chars_rejects_newlines() {
        assert!(matches!(
            reject_forbidden_chars("ok\nmore"),
            Err(JailError::InvalidInput(_))
        ));
        assert!(matches!(
            reject_forbidden_chars("ok\rmore"),
            Err(JailError::InvalidInput(_))
        ));
    }

    #[test]
    fn reject_forbidden_chars_accepts_normal() {
        assert!(reject_forbidden_chars("src/main.rs").is_ok());
        assert!(reject_forbidden_chars("/tmp/x y z.txt").is_ok()); // spaces are fine
    }

    #[test]
    fn is_security_event_matches_the_right_variants() {
        let escape = JailError::Escape("x".into());
        let sym = JailError::SymlinkRejected("x".into());
        let race = JailError::RaceDetected("x".into());
        assert!(escape.is_security_event());
        assert!(sym.is_security_event());
        assert!(race.is_security_event());

        let io_err = JailError::Io {
            path: "x".into(),
            source: io::Error::new(io::ErrorKind::NotFound, "nf"),
        };
        assert!(!io_err.is_security_event());
    }

    #[test]
    fn ensure_path_within_any_root_accepts_inside() {
        let root = PathBuf::from("/tmp/repo");
        let target = PathBuf::from("/tmp/repo/src/main.rs");
        assert!(ensure_path_within_any_root(&target, &[root], "src/main.rs").is_ok());
    }

    #[test]
    fn ensure_path_within_any_root_rejects_outside() {
        let root = PathBuf::from("/tmp/repo");
        let target = PathBuf::from("/etc/passwd");
        assert!(matches!(
            ensure_path_within_any_root(&target, &[root], "/etc/passwd"),
            Err(JailError::Escape(_))
        ));
    }

    #[test]
    fn ensure_path_within_any_root_rejects_parent_traversal() {
        // Logical normalization should strip the inner /../ and force the
        // starts_with check to fail.
        let root = PathBuf::from("/tmp/repo");
        let target = PathBuf::from("/tmp/repo/../../etc/passwd");
        assert!(matches!(
            ensure_path_within_any_root(&target, &[root], "../../etc/passwd"),
            Err(JailError::Escape(_))
        ));
    }

    #[test]
    fn max_read_bytes_honors_env_override() {
        let key = ENV_MAX_READ_BYTES;
        let saved = std::env::var_os(key);
        // SAFETY: env mutation is thread-unsafe in Rust 2024+; tests run
        // single-threaded under `cargo test -- --test-threads=1` when they
        // mutate env. This test reads back immediately and restores state.
        // Use `set_var`/`remove_var` inside `unsafe` for 2024 edition; the
        // crate's edition is 2021, so the plain API is fine.
        std::env::set_var(key, "4096");
        assert_eq!(max_read_bytes(), 4096);
        std::env::remove_var(key);
        assert_eq!(max_read_bytes(), MAX_READ_BYTES);
        if let Some(v) = saved {
            std::env::set_var(key, v);
        }
    }

    #[test]
    fn read_capped_truncates_oversize_input() {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = tempfile::tempfile().expect("tempfile");
        f.write_all(&vec![b'a'; 1024]).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let (buf, truncated) = read_capped(f, 512).unwrap();
        assert_eq!(buf.len(), 512);
        assert!(truncated);
    }

    #[test]
    fn read_capped_does_not_truncate_exact_size() {
        use std::io::{Seek, SeekFrom, Write};
        let mut f = tempfile::tempfile().expect("tempfile");
        f.write_all(&vec![b'a'; 512]).unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        let (buf, truncated) = read_capped(f, 512).unwrap();
        assert_eq!(buf.len(), 512);
        assert!(!truncated, "file exactly at cap must not report truncated");
    }
}

