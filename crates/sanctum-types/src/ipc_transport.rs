//! Cross-platform IPC transport.
//!
//! Unix builds use Unix domain sockets. Windows builds use named pipes. The
//! framing protocol remains in [`crate::ipc`].

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncRead, AsyncWrite};

/// IPC endpoint for the current platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcEndpoint {
    /// Unix domain socket path.
    Unix(PathBuf),
    /// Windows named pipe name, e.g. `sanctum-laurence`.
    NamedPipe(String),
}

impl IpcEndpoint {
    /// Build the platform-default endpoint from the legacy socket path/name.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn platform_default(socket_path: PathBuf) -> Self {
        #[cfg(unix)]
        {
            Self::Unix(socket_path)
        }
        #[cfg(windows)]
        {
            let user = crate::windows_security::current_username_for_endpoint();
            Self::NamedPipe(pipe_name_from_socket_path(&socket_path, user.as_deref()))
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self::Unix(socket_path)
        }
    }

    /// Display string suitable for logs.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::Unix(path) => path.display().to_string(),
            Self::NamedPipe(name) => format!(r"\\.\pipe\{name}"),
        }
    }

    /// Return the Unix path if this endpoint uses a filesystem socket.
    #[must_use]
    pub fn as_unix_path(&self) -> Option<&Path> {
        match self {
            Self::Unix(path) => Some(path),
            Self::NamedPipe(_) => None,
        }
    }

    /// Return the Windows pipe path.
    #[must_use]
    pub fn pipe_path(&self) -> Option<String> {
        match self {
            Self::Unix(_) => None,
            Self::NamedPipe(name) => Some(format!(r"\\.\pipe\{name}")),
        }
    }
}

impl fmt::Display for IpcEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.display())
    }
}

/// Async connected IPC stream.
pub trait AsyncIpcStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncIpcStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

/// Synchronous connected IPC stream.
pub trait SyncIpcStream: std::io::Read + std::io::Write + Send {}
impl<T> SyncIpcStream for T where T: std::io::Read + std::io::Write + Send {}

/// Platform listener wrapper.
pub struct IpcListener {
    endpoint: IpcEndpoint,
    #[cfg(all(unix, not(loom)))]
    listener: tokio::net::UnixListener,
    #[cfg(all(windows, not(loom)))]
    first_server: tokio::sync::Mutex<Option<tokio::net::windows::named_pipe::NamedPipeServer>>,
}

impl IpcListener {
    /// Bind a platform-specific IPC listener.
    ///
    /// # Errors
    ///
    /// Returns an error if the Unix socket or Windows named pipe cannot be
    /// created.
    pub fn bind(endpoint: &IpcEndpoint) -> io::Result<Self> {
        match endpoint {
            IpcEndpoint::Unix(path) => bind_unix(path, endpoint),
            IpcEndpoint::NamedPipe(name) => bind_named_pipe(name, endpoint),
        }
    }

    /// Accept one connection.
    ///
    /// # Errors
    ///
    /// Returns an error if the listener cannot accept a client connection.
    pub async fn accept(&self) -> io::Result<Box<dyn AsyncIpcStream>> {
        #[cfg(all(unix, not(loom)))]
        {
            let (stream, _) = self.listener.accept().await?;
            Ok(Box::new(stream))
        }

        #[cfg(all(windows, not(loom)))]
        {
            let server = {
                let mut guard = self.first_server.lock().await;
                if let Some(server) = guard.take() {
                    server
                } else {
                    create_named_pipe_server(
                        match &self.endpoint {
                            IpcEndpoint::NamedPipe(name) => name,
                            IpcEndpoint::Unix(_) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::InvalidInput,
                                    "windows listener requires named pipe endpoint",
                                ));
                            }
                        },
                        false,
                    )?
                }
            };
            server.connect().await?;
            Ok(Box::new(server))
        }

        #[cfg(any(loom, not(any(unix, windows))))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPC listener is not supported on this platform",
            ))
        }
    }

    /// Display the bound local address.
    #[must_use]
    pub fn local_addr_display(&self) -> String {
        self.endpoint.display()
    }
}

/// Connect asynchronously to an endpoint.
///
/// # Errors
///
/// Returns an error if the endpoint cannot be reached or the platform does not
/// support the endpoint kind.
pub async fn connect_async(endpoint: &IpcEndpoint) -> io::Result<Box<dyn AsyncIpcStream>> {
    match endpoint {
        IpcEndpoint::Unix(path) => {
            #[cfg(all(unix, not(loom)))]
            {
                Ok(Box::new(tokio::net::UnixStream::connect(path).await?))
            }
            #[cfg(any(loom, not(unix)))]
            {
                let _ = path;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unix sockets are not supported on this platform",
                ))
            }
        }
        IpcEndpoint::NamedPipe(name) => {
            #[cfg(all(windows, not(loom)))]
            {
                let path = format!(r"\\.\pipe\{name}");
                Ok(Box::new(
                    tokio::net::windows::named_pipe::ClientOptions::new().open(path)?,
                ))
            }
            #[cfg(any(loom, not(windows)))]
            {
                let _ = name;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Windows named pipes are not supported on this platform",
                ))
            }
        }
    }
}

/// Connect synchronously to an endpoint.
///
/// # Errors
///
/// Returns an error if the endpoint cannot be reached or the platform does not
/// support the endpoint kind.
pub fn connect_sync(endpoint: &IpcEndpoint) -> io::Result<Box<dyn SyncIpcStream>> {
    match endpoint {
        IpcEndpoint::Unix(path) => {
            #[cfg(unix)]
            {
                Ok(Box::new(std::os::unix::net::UnixStream::connect(path)?))
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Unix sockets are not supported on this platform",
                ))
            }
        }
        IpcEndpoint::NamedPipe(name) => {
            #[cfg(windows)]
            {
                let path = format!(r"\\.\pipe\{name}");
                Ok(Box::new(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(path)?,
                ))
            }
            #[cfg(not(windows))]
            {
                let _ = name;
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "Windows named pipes are not supported on this platform",
                ))
            }
        }
    }
}

#[cfg(all(unix, not(loom)))]
fn bind_unix(path: &Path, endpoint: &IpcEndpoint) -> io::Result<IpcListener> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    Ok(IpcListener {
        endpoint: endpoint.clone(),
        listener,
    })
}

#[cfg(any(loom, not(unix)))]
fn bind_unix(path: &Path, _endpoint: &IpcEndpoint) -> io::Result<IpcListener> {
    let _ = path;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Unix sockets are not supported on this platform",
    ))
}

#[cfg(all(windows, not(loom)))]
fn bind_named_pipe(name: &str, endpoint: &IpcEndpoint) -> io::Result<IpcListener> {
    let server = create_named_pipe_server(name, true)?;
    Ok(IpcListener {
        endpoint: endpoint.clone(),
        first_server: tokio::sync::Mutex::new(Some(server)),
    })
}

#[cfg(any(loom, not(windows)))]
fn bind_named_pipe(name: &str, _endpoint: &IpcEndpoint) -> io::Result<IpcListener> {
    let _ = name;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows named pipes are not supported on this platform",
    ))
}

#[cfg(all(windows, not(loom)))]
fn create_named_pipe_server(
    name: &str,
    first_instance: bool,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let mut options = tokio::net::windows::named_pipe::ServerOptions::new();
    options
        .first_pipe_instance(first_instance)
        .reject_remote_clients(true);
    create_named_pipe_server_with_current_user_dacl(&options, name)
}

#[cfg(all(windows, not(loom)))]
#[allow(unsafe_code)]
fn create_named_pipe_server_with_current_user_dacl(
    options: &tokio::net::windows::named_pipe::ServerOptions,
    name: &str,
) -> io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    let mut attrs = crate::windows_security::CurrentUserSecurityAttributes::for_named_pipe()?;
    let path = format!(r"\\.\pipe\{name}");
    // SAFETY: `attrs` owns a valid SECURITY_ATTRIBUTES value and backing
    // security descriptor for the duration of this call. Windows copies the
    // descriptor during CreateNamedPipeW, so dropping `attrs` after creation is
    // safe.
    unsafe { options.create_with_security_attributes_raw(path, attrs.as_mut_ptr()) }
}

#[cfg(windows)]
fn pipe_name_from_socket_path(socket_path: &Path, username: Option<&str>) -> String {
    let fallback_pid = std::process::id();
    if username.is_none() {
        tracing::warn!(
            fallback_pid,
            "Windows username unavailable; using PID-scoped Sanctum IPC pipe name"
        );
    }
    pipe_name_from_socket_path_with_pid(socket_path, username, fallback_pid)
}

#[cfg(any(windows, test))]
fn pipe_name_from_socket_path_with_pid(
    socket_path: &Path,
    username: Option<&str>,
    fallback_pid: u32,
) -> String {
    let base = socket_path
        .file_stem()
        .or_else(|| socket_path.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("sanctum");
    let base = crate::windows_security::sanitize_pipe_component(base);
    let user = username.map_or_else(
        || crate::windows_security::sanitize_pipe_component(&fallback_pid.to_string()),
        crate::windows_security::sanitize_pipe_component,
    );
    format!("{base}-{user}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_display_unix() {
        let endpoint = IpcEndpoint::Unix(PathBuf::from("/tmp/sanctum.sock"));
        assert_eq!(endpoint.display(), "/tmp/sanctum.sock");
    }

    #[test]
    fn endpoint_display_named_pipe() {
        let endpoint = IpcEndpoint::NamedPipe("sanctum-user".to_owned());
        assert_eq!(endpoint.display(), r"\\.\pipe\sanctum-user");
    }

    #[test]
    fn platform_pipe_name_is_user_scoped_and_sanitized() {
        let name = pipe_name_from_socket_path_with_pid(
            Path::new("sanctum.sock"),
            Some(r"DOMAIN\Alice Smith"),
            4242,
        );
        assert_eq!(name, "sanctum-DOMAIN-Alice-Smith");
    }

    #[test]
    fn platform_pipe_name_uses_pid_when_username_missing() {
        let name = pipe_name_from_socket_path_with_pid(Path::new("sanctum.sock"), None, 4242);
        assert_eq!(name, "sanctum-4242");
    }
}
