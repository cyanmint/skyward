use anyhow::{ensure, Context, Result};
use std::ffi::{CStr, CString};
use std::io;

pub(crate) trait CreateContextOps {
    fn set_socket_create(&self, context: Option<&CStr>) -> io::Result<()>;
    fn set_file_create(&self, context: Option<&CStr>) -> io::Result<()>;
}

pub(crate) fn transition_context(current: &CStr, computed: &CStr) -> Result<CString> {
    ensure!(
        !computed.to_bytes().is_empty(),
        "SELinux returned an empty service context"
    );
    ensure!(
        current != computed,
        "SELinux policy defines no service domain transition from {}",
        current.to_string_lossy()
    );
    Ok(computed.to_owned())
}

fn with_action(error: io::Error, action: &str) -> io::Error {
    io::Error::new(error.kind(), format!("{action}: {error}"))
}

fn finish_context<T>(operation: io::Result<T>, reset: io::Result<()>) -> io::Result<T> {
    match (operation, reset) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(reset)) => Err(io::Error::new(
            reset.kind(),
            format!("{operation}; additionally failed to reset SELinux creation context: {reset}"),
        )),
    }
}

pub(crate) fn with_create_contexts<T>(
    ops: &dyn CreateContextOps,
    socket_context: Option<&CStr>,
    file_context: Option<&CStr>,
    create_socket: impl FnOnce() -> io::Result<T>,
    bind_socket: impl FnOnce(T) -> io::Result<T>,
) -> io::Result<T> {
    if let Some(context) = socket_context {
        ops.set_socket_create(Some(context))
            .map_err(|error| with_action(error, "set the SELinux context for the socket object"))?;
    }
    let created = create_socket();
    let created = if socket_context.is_some() {
        let reset = ops
            .set_socket_create(None)
            .map_err(|error| with_action(error, "clear the SELinux socket creation context"));
        finish_context(created, reset)?
    } else {
        created?
    };
    if let Some(context) = file_context {
        ops.set_file_create(Some(context))
            .map_err(|error| with_action(error, "set the SELinux context for the socket path"))?;
    }
    let bound = bind_socket(created);
    if file_context.is_some() {
        let reset = ops
            .set_file_create(None)
            .map_err(|error| with_action(error, "clear the SELinux file creation context"));
        finish_context(bound, reset)
    } else {
        bound
    }
}

use std::ffi::{c_char, c_int, c_ushort, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::Arc;

type IsEnabled = unsafe extern "C" fn() -> c_int;
type GetContext = unsafe extern "C" fn(*mut *mut c_char) -> c_int;
type GetFileContext = unsafe extern "C" fn(*const c_char, *mut *mut c_char) -> c_int;
type ComputeCreate =
    unsafe extern "C" fn(*const c_char, *const c_char, c_ushort, *mut *mut c_char) -> c_int;
type StringToClass = unsafe extern "C" fn(*const c_char) -> c_ushort;
type FreeContext = unsafe extern "C" fn(*mut c_char);
type SetContext = unsafe extern "C" fn(*const c_char) -> c_int;

struct Api {
    library: usize,
    is_enabled: IsEnabled,
    get_context: GetContext,
    get_file_context: GetFileContext,
    compute_create: ComputeCreate,
    string_to_class: StringToClass,
    free_context: FreeContext,
    set_exec_context: SetContext,
    set_socket_create: SetContext,
    set_file_create: SetContext,
}

impl Drop for Api {
    fn drop(&mut self) {
        unsafe { libc::dlclose(self.library as *mut c_void) };
    }
}

unsafe fn symbol<T: Copy>(library: *mut c_void, name: &CStr) -> Result<T> {
    let symbol = unsafe { libc::dlsym(library, name.as_ptr()) };
    ensure!(
        !symbol.is_null(),
        "find {} in libselinux.so",
        name.to_string_lossy()
    );
    Ok(unsafe { std::mem::transmute_copy(&symbol) })
}

impl Api {
    fn load() -> Result<Option<Arc<Self>>> {
        let library = unsafe { libc::dlopen(c"libselinux.so".as_ptr(), libc::RTLD_NOW) };
        ensure!(!library.is_null(), "load libselinux.so");
        let loaded = unsafe {
            (|| -> Result<Self> {
                Ok(Self {
                    library: library as usize,
                    is_enabled: symbol(library, c"is_selinux_enabled")?,
                    get_context: symbol(library, c"getcon")?,
                    get_file_context: symbol(library, c"getfilecon")?,
                    compute_create: symbol(library, c"security_compute_create")?,
                    string_to_class: symbol(library, c"string_to_security_class")?,
                    free_context: symbol(library, c"freecon")?,
                    set_exec_context: symbol(library, c"setexeccon")?,
                    set_socket_create: symbol(library, c"setsockcreatecon")?,
                    set_file_create: symbol(library, c"setfscreatecon")?,
                })
            })()
        };
        let api = match loaded {
            Ok(api) => api,
            Err(error) => {
                unsafe { libc::dlclose(library) };
                return Err(error);
            }
        };
        match unsafe { (api.is_enabled)() } {
            0 => {
                drop(api);
                Ok(None)
            }
            1 => Ok(Some(Arc::new(api))),
            _ => Err(std::io::Error::last_os_error()).context("check whether SELinux is enabled"),
        }
    }

    fn compute_service_context(&self, executable: &Path) -> Result<CString> {
        let executable = CString::new(executable.as_os_str().as_bytes())
            .context("service executable path contains a NUL")?;
        let mut current = std::ptr::null_mut();
        ensure!(
            unsafe { (self.get_context)(&mut current) } == 0 && !current.is_null(),
            "get SELinux context of recovery process: {}",
            std::io::Error::last_os_error()
        );
        let current_guard = ContextGuard {
            api: self,
            value: current,
        };
        let mut file = std::ptr::null_mut();
        let file_context_len = unsafe { (self.get_file_context)(executable.as_ptr(), &mut file) };
        ensure!(
            file_context_len > 0 && !file.is_null(),
            "get SELinux context of {}: {}",
            executable.to_string_lossy(),
            std::io::Error::last_os_error()
        );
        let file_guard = ContextGuard {
            api: self,
            value: file,
        };
        let class = unsafe { (self.string_to_class)(c"process".as_ptr()) };
        ensure!(class != 0, "SELinux policy has no process class");
        let mut computed = std::ptr::null_mut();
        ensure!(
            unsafe {
                (self.compute_create)(
                    current_guard.as_ptr(),
                    file_guard.as_ptr(),
                    class,
                    &mut computed,
                )
            } == 0
                && !computed.is_null(),
            "compute SELinux service context for {}: {}",
            executable.to_string_lossy(),
            std::io::Error::last_os_error()
        );
        let computed_guard = ContextGuard {
            api: self,
            value: computed,
        };
        transition_context(unsafe { CStr::from_ptr(current_guard.as_ptr()) }, unsafe {
            CStr::from_ptr(computed_guard.as_ptr())
        })
    }
}

struct ContextGuard<'a> {
    api: &'a Api,
    value: *mut c_char,
}

impl ContextGuard<'_> {
    fn as_ptr(&self) -> *const c_char {
        self.value
    }
}

impl Drop for ContextGuard<'_> {
    fn drop(&mut self) {
        if !self.value.is_null() {
            unsafe { (self.api.free_context)(self.value) };
        }
    }
}

#[derive(Clone)]
pub(crate) struct ServiceContext {
    api: Arc<Api>,
    value: CString,
}

impl ServiceContext {
    pub(crate) fn label(&self) -> &CStr {
        &self.value
    }

    pub(crate) fn set_for_exec(&self) -> std::io::Result<()> {
        let result = unsafe { (self.api.set_exec_context)(self.value.as_ptr()) };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

impl CreateContextOps for ServiceContext {
    fn set_socket_create(&self, context: Option<&CStr>) -> std::io::Result<()> {
        let context = context.map_or(std::ptr::null(), CStr::as_ptr);
        if unsafe { (self.api.set_socket_create)(context) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn set_file_create(&self, context: Option<&CStr>) -> std::io::Result<()> {
        let context = context.map_or(std::ptr::null(), CStr::as_ptr);
        if unsafe { (self.api.set_file_create)(context) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }
}

fn require_enabled<T>(api: Option<T>) -> Result<T> {
    api.context("SELinux is disabled but the configured service requires SELinux support")
}

#[derive(Clone)]
pub(crate) struct ServiceSecurity {
    api: Arc<Api>,
}

impl ServiceSecurity {
    pub(crate) fn load() -> Result<Self> {
        let api = require_enabled(Api::load()?)?;
        Ok(Self { api })
    }

    pub(crate) fn service_context(
        &self,
        executable: &Path,
        explicit: Option<&str>,
    ) -> Result<ServiceContext> {
        let value = match explicit {
            Some(label) => {
                ensure!(
                    !label.is_empty(),
                    "explicit SELinux service context is empty"
                );
                CString::new(label).context("explicit SELinux service context contains a NUL")?
            }
            None => self.api.compute_service_context(executable)?,
        };
        Ok(ServiceContext {
            api: self.api.clone(),
            value,
        })
    }

    #[cfg(any(target_os = "android", test))]
    pub(crate) fn socket_file_context(
        &self,
        slot: skyward_vab::Slot,
        path: &Path,
    ) -> Result<Option<CString>> {
        let Some(label) = crate::relabel::file_context(slot, path, libc::S_IFSOCK)? else {
            return Ok(None);
        };
        Ok(Some(
            CStr::from_bytes_with_nul(&label)
                .context("SELinux socket path label is not NUL-terminated")?
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{require_enabled, transition_context, with_create_contexts, Api, CreateContextOps};
    use std::cell::RefCell;
    use std::ffi::{c_char, c_int, c_ushort, CStr, CString};
    use std::io;
    use std::path::Path;
    use std::rc::Rc;

    static RECOVERY_CONTEXT: &[u8] = b"u:r:recovery:s0\0";
    static QSEE_EXEC_CONTEXT: &[u8] = b"u:object_r:tee_exec:s0\0";
    static QSEE_PROCESS_CONTEXT: &[u8] = b"u:r:tee:s0\0";

    unsafe extern "C" fn mock_get_context(output: *mut *mut c_char) -> c_int {
        unsafe { *output = RECOVERY_CONTEXT.as_ptr().cast_mut().cast() };
        0
    }

    unsafe extern "C" fn mock_get_file_context(
        _path: *const c_char,
        output: *mut *mut c_char,
    ) -> c_int {
        unsafe { *output = QSEE_EXEC_CONTEXT.as_ptr().cast_mut().cast() };
        QSEE_EXEC_CONTEXT.len() as c_int - 1
    }

    unsafe extern "C" fn mock_compute_create(
        _source: *const c_char,
        _target: *const c_char,
        _class: c_ushort,
        output: *mut *mut c_char,
    ) -> c_int {
        unsafe { *output = QSEE_PROCESS_CONTEXT.as_ptr().cast_mut().cast() };
        0
    }

    unsafe extern "C" fn mock_is_enabled() -> c_int {
        1
    }
    unsafe extern "C" fn mock_string_to_class(_name: *const c_char) -> c_ushort {
        1
    }
    unsafe extern "C" fn mock_free_context(_context: *mut c_char) {}
    unsafe extern "C" fn mock_set_context(_context: *const c_char) -> c_int {
        0
    }

    #[test]
    fn accepts_the_positive_length_returned_by_getfilecon() {
        let api = Api {
            library: 0,
            is_enabled: mock_is_enabled,
            get_context: mock_get_context,
            get_file_context: mock_get_file_context,
            compute_create: mock_compute_create,
            string_to_class: mock_string_to_class,
            free_context: mock_free_context,
            set_exec_context: mock_set_context,
            set_socket_create: mock_set_context,
            set_file_create: mock_set_context,
        };
        let context = api.compute_service_context(Path::new("/vendor/bin/qseecomd"));
        std::mem::forget(api);
        assert_eq!(context.unwrap().as_bytes_with_nul(), QSEE_PROCESS_CONTEXT);
    }

    #[test]
    fn a_service_requiring_selinux_fails_closed_when_selinux_is_disabled() {
        assert!(require_enabled::<()>(None).is_err());
        assert_eq!(require_enabled(Some(7)).unwrap(), 7);
    }

    struct Recorder(Rc<RefCell<Vec<String>>>);

    impl CreateContextOps for Recorder {
        fn set_socket_create(&self, context: Option<&CStr>) -> io::Result<()> {
            self.0.borrow_mut().push(match context {
                Some(value) => format!("socket:{}", value.to_string_lossy()),
                None => "socket:clear".into(),
            });
            Ok(())
        }

        fn set_file_create(&self, context: Option<&CStr>) -> io::Result<()> {
            self.0.borrow_mut().push(match context {
                Some(value) => format!("file:{}", value.to_string_lossy()),
                None => "file:clear".into(),
            });
            Ok(())
        }
    }

    #[test]
    fn creates_socket_with_init_context_order_and_resets_contexts() -> io::Result<()> {
        let events = Rc::new(RefCell::new(Vec::new()));
        let ops = Recorder(events.clone());
        let socket = CString::new("u:r:hal_keymint_default:s0").unwrap();
        let file = CString::new("u:object_r:socket_device:s0").unwrap();
        let result = with_create_contexts(
            &ops,
            Some(&socket),
            Some(&file),
            || {
                events.borrow_mut().push("socket()".into());
                Ok(64)
            },
            |fd| {
                events.borrow_mut().push(format!("bind({fd})"));
                Ok(fd)
            },
        )?;
        assert_eq!(result, 64);
        assert_eq!(
            *events.borrow(),
            [
                "socket:u:r:hal_keymint_default:s0",
                "socket()",
                "socket:clear",
                "file:u:object_r:socket_device:s0",
                "bind(64)",
                "file:clear",
            ]
        );
        Ok(())
    }

    #[test]
    fn clears_socket_context_when_socket_creation_fails() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let ops = Recorder(events.clone());
        let socket = CString::new("u:r:hal_keymint_default:s0").unwrap();
        let result = with_create_contexts(
            &ops,
            Some(&socket),
            None,
            || Err(io::Error::from_raw_os_error(libc::EMFILE)),
            |_| Ok(()),
        );
        assert_eq!(result.unwrap_err().raw_os_error(), Some(libc::EMFILE));
        assert_eq!(
            *events.borrow(),
            ["socket:u:r:hal_keymint_default:s0", "socket:clear"]
        );
    }

    #[test]
    fn rejects_a_computed_context_without_a_domain_transition() {
        let recovery = c"u:r:recovery:s0";
        let result = transition_context(recovery, recovery);
        assert!(
            result.is_err(),
            "init must not silently run the service in recovery"
        );
    }

    #[test]
    fn accepts_the_policy_computed_service_domain() {
        let recovery = c"u:r:recovery:s0";
        let keymint = c"u:r:hal_keymint_default:s0";
        assert_eq!(transition_context(recovery, keymint).unwrap(), keymint);
    }
}
