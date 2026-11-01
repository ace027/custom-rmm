//! Windows service host: SCM dispatcher, status reporting, stop control and
//! the SYSTEM+Administrators-only DACL on the watchdog root. The only module
//! of the crate allowed to use `unsafe` (FFI calls only).

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use rmm_watchdog::log;
use rmm_watchdog::supervisor::Supervisor;
use serde_json::json;
use windows::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, HLOCAL, LocalFree, NO_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, OBJECT_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows::core::{BOOL, PCWSTR, PWSTR};

use crate::RunOpts;

/// Service name (ignored by the SCM for own-process services).
const SERVICE_NAME: &str = "rmm-watchdog";
/// Protected DACL: full control for SYSTEM and Administrators, inherited by
/// files and subdirectories, nothing inherited from the parent.
const ROOT_SDDL: &str = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

static STOP: AtomicBool = AtomicBool::new(false);
static OPTS: OnceLock<RunOpts> = OnceLock::new();
/// Raw `SERVICE_STATUS_HANDLE` (0 until registered).
static STATUS_HANDLE: AtomicUsize = AtomicUsize::new(0);

fn wide(s: &std::ffi::OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

/// Frees a `LocalAlloc` allocation on drop.
struct LocalBuf(*mut c_void);

impl Drop for LocalBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate
            // with LocalAlloc and is freed exactly once, here.
            unsafe {
                LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

/// Run under the service control manager; returns when the service stops.
pub(crate) fn run(opts: RunOpts) -> Result<(), String> {
    OPTS.set(opts)
        .map_err(|_| "service started twice".to_owned())?;
    let mut name = wide(SERVICE_NAME.as_ref());
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR::null(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` is terminated by a null entry and, like `name`, lives
    // until the dispatcher returns (after the service has stopped).
    unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) }
        .map_err(|e| format!("StartServiceCtrlDispatcherW: {e} (start it through the SCM)"))
}

fn set_status(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32, wait_hint_ms: u32) {
    let raw = STATUS_HANDLE.load(Ordering::SeqCst);
    if raw == 0 {
        return;
    }
    let accepted = if state == SERVICE_RUNNING {
        SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    } else {
        0
    };
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: accepted,
        dwWin32ExitCode: if exit_code == 0 {
            NO_ERROR.0
        } else {
            ERROR_SERVICE_SPECIFIC_ERROR.0
        },
        dwServiceSpecificExitCode: exit_code,
        dwCheckPoint: 0,
        dwWaitHint: wait_hint_ms,
    };
    // SAFETY: the handle was returned by RegisterServiceCtrlHandlerExW and
    // stays valid for the life of the process; `status` outlives the call.
    if let Err(e) = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(raw as *mut c_void), &status) }
    {
        log("service_status_failed", json!({ "error": e.to_string() }));
    }
}

unsafe extern "system" fn handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            set_status(SERVICE_STOP_PENDING, 0, 15_000);
            NO_ERROR.0
        }
        SERVICE_CONTROL_INTERROGATE => NO_ERROR.0,
        _ => ERROR_CALL_NOT_IMPLEMENTED.0,
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    let name = wide(SERVICE_NAME.as_ref());
    // SAFETY: `name` is NUL-terminated and outlives the call; `handler` has
    // the required signature and is valid for the life of the process.
    match unsafe { RegisterServiceCtrlHandlerExW(PCWSTR(name.as_ptr()), Some(handler), None) } {
        Ok(h) => STATUS_HANDLE.store(h.0 as usize, Ordering::SeqCst),
        Err(e) => {
            log("service_register_failed", json!({ "error": e.to_string() }));
            return;
        }
    }
    set_status(SERVICE_START_PENDING, 0, 10_000);
    let code = match serve() {
        Ok(()) => 0,
        Err(msg) => {
            log("service_failed", json!({ "error": msg }));
            1
        }
    };
    set_status(SERVICE_STOPPED, code, 0);
}

fn default_base() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("RMM")
}

fn serve() -> Result<(), String> {
    let opts = OPTS.get().ok_or("service options missing")?;
    let base = default_base();
    let root = opts.root.clone().unwrap_or_else(|| base.clone());
    let state_dir = opts.state_dir.clone().unwrap_or(base);
    std::fs::create_dir_all(&root).map_err(|e| format!("create {}: {e}", root.display()))?;
    protect_dir(&root)?;
    let cfg = crate::build_config(opts, root, state_dir)?;
    let mut sup = Supervisor::new(cfg).map_err(|e| format!("start: {e}"))?;
    set_status(SERVICE_RUNNING, 0, 0);
    sup.run(&STOP);
    Ok(())
}

/// Replace the DACL of `dir` with [`ROOT_SDDL`] (protected, inheritable).
/// Applied on every start, so a loosened ACL is repaired.
fn protect_dir(dir: &Path) -> Result<(), String> {
    let sddl = wide(ROOT_SDDL.as_ref());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated and outlives the call; `sd` is a valid
    // out pointer and the descriptor it receives is freed by `_sd`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| format!("build security descriptor: {e}"))?;
    let _sd = LocalBuf(sd.0);
    let mut present = BOOL(0);
    let mut defaulted = BOOL(0);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    // SAFETY: `sd` is a valid descriptor (kept alive by `_sd`) and every out
    // pointer refers to a live local.
    unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted) }
        .map_err(|e| format!("read DACL: {e}"))?;
    if !present.as_bool() || dacl.is_null() {
        return Err("security descriptor has no DACL".into());
    }
    let path = wide(dir.as_os_str());
    let info = OBJECT_SECURITY_INFORMATION(
        DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
    );
    // SAFETY: `path` is NUL-terminated and `dacl` points into the descriptor
    // kept alive by `_sd`; both outlive the call.
    let err = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path.as_ptr()),
            SE_FILE_OBJECT,
            info,
            None,
            None,
            Some(dacl.cast_const()),
            None,
        )
    };
    if err != NO_ERROR {
        return Err(format!(
            "set DACL on {}: win32 error {}",
            dir.display(),
            err.0
        ));
    }
    log(
        "root_protected",
        json!({ "root": dir.display().to_string() }),
    );
    Ok(())
}
