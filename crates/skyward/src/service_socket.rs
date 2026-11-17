use crate::service_security::{with_create_contexts, CreateContextOps};
use anyhow::{bail, ensure, Context, Result};
use std::cell::Cell;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const ANDROID_FD_BASE: RawFd = 64;
const DUPLICATE_FD_BASE: RawFd = 256;
const MAX_SOCKETS: usize = 64;

/// The fixed Android socket directory must not be writable by untrusted accounts.
/// Path-based cleanup and ownership changes are safe only under that invariant.
fn validate_socket_directory(directory: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("inspect socket directory {}", directory.display()))?;
    ensure!(
        metadata.file_type().is_dir(),
        "{} is not a socket directory",
        directory.display()
    );
    ensure!(
        metadata.mode() & 0o022 == 0,
        "socket directory {} is writable by other accounts",
        directory.display()
    );
    #[cfg(target_os = "android")]
    ensure!(
        metadata.uid() == 0,
        "socket directory {} is not owned by root",
        directory.display()
    );
    Ok(())
}

/// Owner of the filesystem entry for an init-style socket.
#[derive(Clone, Copy)]
pub(crate) struct SocketOwner {
    pub(crate) uid: u32,
    pub(crate) gid: u32,
}

/// A Unix stream socket created for an init-style service.
pub(crate) struct BoundSocket {
    name: String,
    path: PathBuf,
    listener: UnixListener,
    identity: (u64, u64),
}

impl BoundSocket {
    pub(crate) fn bind(
        name: &str,
        directory: &Path,
        mode: u32,
        owner: SocketOwner,
        contexts: Option<&dyn CreateContextOps>,
        socket_context: Option<&CStr>,
        file_context: Option<&CStr>,
    ) -> Result<Self> {
        ensure!(
            !name.is_empty()
                && name != "."
                && name != ".."
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "invalid init socket name {name:?}"
        );
        ensure!(mode <= 0o777, "invalid init socket mode {mode:o}");
        validate_socket_directory(directory)?;
        ensure!(
            socket_context.is_some() || file_context.is_none(),
            "a SELinux socket path label requires a socket context"
        );
        let path = directory.join(name);
        clear_stale_socket(&path)?;
        let address = socket_address(&path)?;
        let address_length = socket_address_length(&path)?;
        let bound_identity = Cell::new(None);
        let create_socket = || {
            let fd =
                unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if fd < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { OwnedFd::from_raw_fd(fd) })
            }
        };
        let bind_socket = |fd: OwnedFd| {
            let result = unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
                    address_length,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let metadata = fs::symlink_metadata(&path)?;
            if !metadata.file_type().is_socket() {
                return Err(io::Error::other(format!(
                    "{} is not a Unix socket",
                    path.display()
                )));
            }
            bound_identity.set(Some((metadata.dev(), metadata.ino())));
            Ok(fd)
        };
        let created = if let (Some(ops), Some(socket_context)) = (contexts, socket_context) {
            with_create_contexts(
                ops,
                Some(socket_context),
                file_context,
                create_socket,
                bind_socket,
            )
            .with_context(|| format!("create init socket {}", path.display()))
        } else {
            ensure!(
                socket_context.is_none() && file_context.is_none(),
                "SELinux contexts require context operations"
            );
            bind_socket(create_socket()?)
                .with_context(|| format!("create init socket {}", path.display()))
        };
        let fd = match created {
            Ok(fd) => fd,
            Err(error) => {
                if let Some(identity) = bound_identity.get() {
                    remove_socket_if_same(&path, identity);
                }
                return Err(error);
            }
        };
        let identity = bound_identity
            .get()
            .context("bound init socket has no filesystem identity")?;
        let setup = (|| -> Result<()> {
            set_owner_mode(&path, owner.uid, owner.gid, mode)?;
            let result = unsafe { libc::listen(fd.as_raw_fd(), i32::MAX) };
            if result < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("listen on init socket {}", path.display()));
            }
            Ok(())
        })();
        if let Err(error) = setup {
            drop(fd);
            remove_socket_if_same(&path, identity);
            return Err(error);
        }
        let listener = unsafe { UnixListener::from_raw_fd(fd.into_raw_fd()) };
        Ok(Self {
            name: name.to_owned(),
            path,
            listener,
            identity,
        })
    }
}

fn socket_address(path: &Path) -> Result<libc::sockaddr_un> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    ensure!(
        bytes.len() < address.sun_path.len(),
        "init socket path is too long: {}",
        path.display()
    );
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    address.sun_path[bytes.len()] = 0;
    Ok(address)
}

fn socket_address_length(path: &Path) -> Result<libc::socklen_t> {
    let bytes = path.as_os_str().as_bytes();
    ensure!(
        bytes.iter().all(|byte| *byte != 0),
        "init socket path contains a NUL"
    );
    ensure!(
        bytes.len()
            < std::mem::size_of::<libc::sockaddr_un>() - std::mem::size_of::<libc::sa_family_t>(),
        "init socket path is too long: {}",
        path.display()
    );
    Ok((std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t)
}

fn set_owner_mode(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<()> {
    let path_c = CString::new(path.as_os_str().as_bytes()).context("socket path contains a NUL")?;
    if unsafe { libc::lchown(path_c.as_ptr(), uid, gid) } < 0 {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("give {} to {uid}:{gid}", path.display()));
    }
    if unsafe {
        libc::fchmodat(
            libc::AT_FDCWD,
            path_c.as_ptr(),
            mode as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error())
            .with_context(|| format!("set {} mode to {mode:o}", path.display()));
    }
    Ok(())
}

fn remove_socket_if_same(path: &Path, identity: (u64, u64)) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_socket() && (metadata.dev(), metadata.ino()) == identity {
        let _ = fs::remove_file(path);
    }
}

impl Drop for BoundSocket {
    fn drop(&mut self) {
        remove_socket_if_same(&self.path, self.identity);
    }
}

/// Keep duplicated descriptors open in the parent until `Command::spawn`
/// has run its pre-exec callbacks. The child receives the listener at a
/// stable descriptor number and the environment variable Android init uses.
pub(crate) struct Handoff {
    _duplicates: Vec<OwnedFd>,
}

pub(crate) fn pass_to_command(command: &mut Command, sockets: &[BoundSocket]) -> Result<Handoff> {
    ensure!(
        sockets.len() <= MAX_SOCKETS,
        "too many init sockets: {}",
        sockets.len()
    );
    let mut duplicates = Vec::with_capacity(sockets.len());
    let mut mappings = Vec::with_capacity(sockets.len());
    for (index, socket) in sockets.iter().enumerate() {
        let target = ANDROID_FD_BASE + index as RawFd;
        let minimum = DUPLICATE_FD_BASE + index as RawFd;
        let source =
            unsafe { libc::fcntl(socket.listener.as_raw_fd(), libc::F_DUPFD_CLOEXEC, minimum) };
        if source < 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("duplicate init socket {}", socket.path.display()));
        }
        duplicates.push(unsafe { OwnedFd::from_raw_fd(source) });
        command.env(
            format!("ANDROID_SOCKET_{}", socket.name),
            target.to_string(),
        );
        mappings.push((source, target));
    }
    unsafe {
        command.pre_exec(move || {
            for (source, target) in &mappings {
                if libc::dup2(*source, *target) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(Handoff {
        _duplicates: duplicates,
    })
}

fn clear_stale_socket(path: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect init socket path {}", path.display()));
        }
    };
    ensure!(
        metadata.file_type().is_socket(),
        "refusing to replace non-socket {}",
        path.display()
    );
    match UnixStream::connect(path) {
        Ok(_) => bail!("init socket {} is already active", path.display()),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::ECONNREFUSED) | Some(libc::ENOENT)
            ) =>
        {
            fs::remove_file(path)
                .with_context(|| format!("remove stale init socket {}", path.display()))?;
            Ok(())
        }
        Err(error) => Err(error)
            .with_context(|| format!("check whether init socket {} is active", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::{pass_to_command, BoundSocket, SocketOwner};
    use anyhow::Result;
    use std::fs;
    use std::os::unix::fs::{FileTypeExt, PermissionsExt};
    use std::process::Command;

    fn socket(dir: &std::path::Path) -> Result<BoundSocket> {
        BoundSocket::bind(
            "notify-topology",
            dir,
            0o660,
            SocketOwner {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            },
            None,
            None,
            None,
        )
    }

    #[test]
    fn bound_control_socket_has_the_init_mode_and_is_removed_on_drop() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("notify-topology");
        let socket = socket(dir.path())?;
        let metadata = fs::symlink_metadata(&path)?;
        assert!(metadata.file_type().is_socket());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o660);
        drop(socket);
        assert!(!path.exists());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn inherited_control_socket_uses_android_init_environment_and_fd() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let socket = socket(dir.path())?;
        let mut command = Command::new("/bin/sh");
        command.args(["-c", "test -S /proc/self/fd/64 && env"]);
        let _handoff = pass_to_command(&mut command, &[socket])?;
        let output = command.output()?;
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "ANDROID_SOCKET_notify-topology=64"));
        Ok(())
    }

    #[test]
    fn refuses_a_socket_directory_writable_by_other_accounts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777))?;
        assert!(socket(dir.path()).is_err());
        assert!(!dir.path().join("notify-topology").exists());
        Ok(())
    }

    struct ContextRecorder(std::rc::Rc<std::cell::RefCell<Vec<String>>>);

    impl crate::service_security::CreateContextOps for ContextRecorder {
        fn set_socket_create(&self, context: Option<&std::ffi::CStr>) -> std::io::Result<()> {
            self.0.borrow_mut().push(match context {
                Some(context) => format!("socket:{}", context.to_string_lossy()),
                None => "socket:clear".into(),
            });
            Ok(())
        }

        fn set_file_create(&self, context: Option<&std::ffi::CStr>) -> std::io::Result<()> {
            self.0.borrow_mut().push(match context {
                Some(context) => format!("file:{}", context.to_string_lossy()),
                None => "file:clear".into(),
            });
            Ok(())
        }
    }

    #[test]
    fn bind_applies_and_resets_selinux_socket_and_path_contexts() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let events = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let ops = ContextRecorder(events.clone());
        let socket_context = std::ffi::CString::new("u:r:service:s0").unwrap();
        let file_context = std::ffi::CString::new("u:object_r:socket:s0").unwrap();
        let socket = BoundSocket::bind(
            "notify-topology",
            dir.path(),
            0o660,
            SocketOwner {
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
            },
            Some(&ops),
            Some(&socket_context),
            Some(&file_context),
        )?;
        assert_eq!(
            *events.borrow(),
            [
                "socket:u:r:service:s0",
                "socket:clear",
                "file:u:object_r:socket:s0",
                "file:clear",
            ]
        );
        drop(socket);
        Ok(())
    }

    #[test]
    fn refuses_paths_and_non_socket_files() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let root = SocketOwner { uid: 0, gid: 0 };
        assert!(BoundSocket::bind(
            "../escape",
            dir.path(),
            0o660,
            root,
            None,
            None,
            None
        )
        .is_err());
        let path = dir.path().join("notify-topology");
        fs::write(&path, b"leave this file alone")?;
        assert!(
            BoundSocket::bind(
                "notify-topology",
                dir.path(),
                0o660,
                root,
                None,
                None,
                None
            )
            .is_err()
        );
        assert_eq!(fs::read(path)?, b"leave this file alone");
        Ok(())
    }
}
