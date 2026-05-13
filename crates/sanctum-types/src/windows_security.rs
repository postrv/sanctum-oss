//! Windows security helpers for current-user scoped IPC and files.

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(windows)]
use std::ffi::c_void;
#[cfg(windows)]
use std::io;
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::Foundation::LocalFree;
#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
#[cfg(windows)]
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

/// File access rights used when applying Windows ACLs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsAclAccess {
    /// Current user may read only.
    Read,
    /// Current user may read and write.
    ReadWrite,
    /// Current user has full control, inherited by children.
    DirectoryFullControl,
}

impl WindowsAclAccess {
    #[cfg(windows)]
    const fn icacls_rights(self) -> &'static str {
        match self {
            Self::Read => "R",
            Self::ReadWrite => "M",
            Self::DirectoryFullControl => "(OI)(CI)F",
        }
    }
}

/// Return the access level that corresponds to a Unix-style owner mode.
#[must_use]
pub const fn acl_access_for_owner_mode(mode: u32) -> WindowsAclAccess {
    if mode & 0o200 == 0 {
        WindowsAclAccess::Read
    } else {
        WindowsAclAccess::ReadWrite
    }
}

/// Parse `whoami /user /fo csv /nh` output and return the first SID.
#[must_use]
pub fn parse_whoami_user_sid_csv(output: &str) -> Option<String> {
    output.lines().find_map(|line| {
        parse_csv_line(line)
            .into_iter()
            .find(|field| is_user_sid(field))
    })
}

/// Build the protected DACL SDDL used for Sanctum named pipes.
#[must_use]
pub fn named_pipe_security_sddl(user_sid: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{user_sid})")
}

/// Sanitize a username or path component for use in a named pipe name.
#[must_use]
pub fn sanitize_pipe_component(component: &str) -> String {
    let sanitized: String = component
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '-'
            }
        })
        .collect();
    let trimmed = sanitized.trim_matches('-');
    if trimmed.is_empty() {
        "user".to_owned()
    } else {
        trimmed.to_owned()
    }
}

#[cfg(windows)]
#[must_use]
pub fn current_username_for_endpoint() -> Option<String> {
    std::env::var("USER")
        .ok()
        .or_else(|| std::env::var("USERNAME").ok())
        .filter(|value| !value.is_empty())
        .map(|value| sanitize_pipe_component(&value))
}

#[cfg(windows)]
pub fn current_user_sid() -> io::Result<String> {
    let output = std::process::Command::new("whoami")
        .args(["/user", "/fo", "csv", "/nh"])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "whoami /user failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    parse_whoami_user_sid_csv(&stdout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "whoami output did not include a user SID",
        )
    })
}

#[cfg(windows)]
pub fn reject_reparse_point(path: &Path) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing to use reparse point: {}", path.display()),
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn restrict_path_to_current_user(path: &Path, access: WindowsAclAccess) -> io::Result<()> {
    let sid = current_user_sid()?;
    let grant = format!("*{sid}:{}", access.icacls_rights());
    let output = std::process::Command::new("icacls")
        .arg(path)
        .args(["/inheritance:r", "/grant:r", &grant])
        .args([
            "/remove:g",
            "*S-1-1-0",
            "*S-1-5-11",
            "*S-1-5-32-545",
            "*S-1-5-4",
        ])
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "icacls failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}

#[cfg(windows)]
pub struct CurrentUserSecurityAttributes {
    attrs: SECURITY_ATTRIBUTES,
    descriptor: PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl CurrentUserSecurityAttributes {
    pub fn for_named_pipe() -> io::Result<Self> {
        let sid = current_user_sid()?;
        Self::from_sddl(&named_pipe_security_sddl(&sid))
    }

    pub const fn as_mut_ptr(&mut self) -> *mut c_void {
        std::ptr::addr_of_mut!(self.attrs).cast()
    }

    #[allow(unsafe_code)]
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
        // SAFETY: `wide` is null-terminated and lives for the duration of the
        // call. The API writes an allocated self-relative security descriptor
        // to `descriptor`, which this type releases with LocalFree in Drop.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_mut_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            return Err(io::Error::last_os_error());
        }
        let attrs_len =
            u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "SECURITY_ATTRIBUTES size does not fit u32",
                )
            })?;
        Ok(Self {
            attrs: SECURITY_ATTRIBUTES {
                nLength: attrs_len,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
            descriptor,
        })
    }
}

#[cfg(windows)]
impl Drop for CurrentUserSecurityAttributes {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            // SAFETY: `descriptor` was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW and has not
            // been freed yet; LocalFree is the documented deallocator.
            let _ = unsafe { LocalFree(self.descriptor) };
        }
    }
}

fn is_user_sid(value: &str) -> bool {
    let value = value.trim();
    value.starts_with("S-1-")
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'S' || b == b'-')
}

fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut chars = line.trim().chars().peekable();
    let mut in_quotes = false;

    while let Some(ch) = chars.next() {
        match ch {
            '"' if in_quotes && chars.peek() == Some(&'"') => {
                field.push('"');
                let _ = chars.next();
            }
            '"' => in_quotes = !in_quotes,
            ',' if !in_quotes => {
                fields.push(field.trim().to_owned());
                field.clear();
            }
            other => field.push(other),
        }
    }

    if !field.is_empty() || line.ends_with(',') {
        fields.push(field.trim().to_owned());
    }
    fields
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_whoami_sid_csv() {
        let output = "\"DESKTOP\\\\alice\",\"S-1-5-21-100-200-300-1001\"\r\n";
        assert_eq!(
            parse_whoami_user_sid_csv(output).unwrap(),
            "S-1-5-21-100-200-300-1001"
        );
    }

    #[test]
    fn ignores_malformed_whoami_output() {
        assert!(parse_whoami_user_sid_csv("\"User\",\"not-a-sid\"").is_none());
    }

    #[test]
    fn named_pipe_sddl_is_current_user_only_plus_system_admins() {
        let sddl = named_pipe_security_sddl("S-1-5-21-1-2-3-1001");
        assert!(sddl.contains("D:P"));
        assert!(sddl.contains("(A;;GA;;;SY)"));
        assert!(sddl.contains("(A;;GA;;;BA)"));
        assert!(sddl.contains("(A;;GA;;;S-1-5-21-1-2-3-1001)"));
        assert!(!sddl.contains("WD"));
        assert!(!sddl.contains("BU"));
    }

    #[test]
    fn owner_mode_maps_to_acl_access() {
        assert_eq!(acl_access_for_owner_mode(0o400), WindowsAclAccess::Read);
        assert_eq!(
            acl_access_for_owner_mode(0o600),
            WindowsAclAccess::ReadWrite
        );
    }

    #[test]
    fn pipe_component_sanitizes_path_like_values() {
        assert_eq!(
            sanitize_pipe_component("DOMAIN\\Alice Smith"),
            "DOMAIN-Alice-Smith"
        );
        assert_eq!(sanitize_pipe_component("@@@"), "user");
    }
}
