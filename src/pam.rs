//! Minimal PAM authentication bound at runtime via `dlopen("libpam.so.0")`.
//!
//! This avoids a build-time dependency on `libpam-dev` (headers / the `.so`
//! symlink) while still using the real system PAM stack — the same mechanism
//! `sshd` and `login` use. Authentication runs the given PAM service (default
//! `login`) with the supplied username/password.
#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void, CString};
use std::ptr;
use std::sync::OnceLock;

use libloading::{Library, Symbol};

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1; // password
const PAM_PROMPT_ECHO_ON: c_int = 2; // login name
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv:
        extern "C" fn(c_int, *const *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

/// Credentials handed to the conversation callback.
struct AppData {
    user: CString,
    pass: CString,
}

/// PAM conversation callback. PAM owns the returned array and every `resp`
/// string, freeing them with `free()`, so we allocate with `calloc`/`strdup`.
extern "C" fn conversation(
    num_msg: c_int,
    msg: *const *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || appdata.is_null() || msg.is_null() || resp.is_null() {
        return PAM_CONV_ERR;
    }
    let n = num_msg as usize;
    let ad = unsafe { &*(appdata as *const AppData) };

    let arr = unsafe { libc::calloc(n, std::mem::size_of::<PamResponse>()) as *mut PamResponse };
    if arr.is_null() {
        return PAM_BUF_ERR;
    }

    for i in 0..n {
        let m = unsafe { *msg.add(i) };
        let entry = unsafe { &mut *arr.add(i) };
        entry.resp_retcode = 0;
        entry.resp = ptr::null_mut();
        if m.is_null() {
            continue;
        }
        match unsafe { (*m).msg_style } {
            PAM_PROMPT_ECHO_OFF => entry.resp = unsafe { libc::strdup(ad.pass.as_ptr()) },
            PAM_PROMPT_ECHO_ON => entry.resp = unsafe { libc::strdup(ad.user.as_ptr()) },
            // PAM_ERROR_MSG / PAM_TEXT_INFO: nothing to answer.
            _ => {}
        }
    }

    unsafe { *resp = arr };
    PAM_SUCCESS
}

type PamStart =
    unsafe extern "C" fn(*const c_char, *const c_char, *const PamConv, *mut *mut c_void) -> c_int;
type PamAuth = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;
type PamEnd = unsafe extern "C" fn(*mut c_void, c_int) -> c_int;

fn lib() -> Result<&'static Library, String> {
    static LIB: OnceLock<Result<Library, String>> = OnceLock::new();
    LIB.get_or_init(|| unsafe {
        Library::new("libpam.so.0").map_err(|e| format!("cannot load libpam.so.0: {e}"))
    })
    .as_ref()
    .map_err(|e| e.clone())
}

/// Authenticate `user`/`password` against the PAM `service`. Returns `Ok(())`
/// only on full success (authentication **and** account management).
///
/// This blocks (PAM modules may do I/O) — call it from a blocking context.
pub fn authenticate(service: &str, user: &str, password: &str) -> Result<(), String> {
    let lib = lib()?;

    let service_c = CString::new(service).map_err(|_| "bad service".to_string())?;
    let user_c = CString::new(user).map_err(|_| "invalid username".to_string())?;
    let appdata = AppData {
        user: CString::new(user).map_err(|_| "invalid username".to_string())?,
        pass: CString::new(password).map_err(|_| "invalid password".to_string())?,
    };

    let conv = PamConv {
        conv: conversation,
        appdata_ptr: &appdata as *const AppData as *mut c_void,
    };

    unsafe {
        let pam_start: Symbol<PamStart> = lib.get(b"pam_start\0").map_err(|e| e.to_string())?;
        let pam_authenticate: Symbol<PamAuth> =
            lib.get(b"pam_authenticate\0").map_err(|e| e.to_string())?;
        let pam_acct_mgmt: Symbol<PamAuth> =
            lib.get(b"pam_acct_mgmt\0").map_err(|e| e.to_string())?;
        let pam_end: Symbol<PamEnd> = lib.get(b"pam_end\0").map_err(|e| e.to_string())?;

        let mut handle: *mut c_void = ptr::null_mut();
        let rc = pam_start(service_c.as_ptr(), user_c.as_ptr(), &conv, &mut handle);
        if rc != PAM_SUCCESS {
            return Err(format!("pam_start failed (rc={rc})"));
        }

        let auth_rc = pam_authenticate(handle, 0);
        let acct_rc = if auth_rc == PAM_SUCCESS {
            pam_acct_mgmt(handle, 0)
        } else {
            auth_rc
        };
        pam_end(handle, auth_rc);

        // Keep appdata alive across the PAM calls above.
        drop(appdata);

        if auth_rc == PAM_SUCCESS && acct_rc == PAM_SUCCESS {
            Ok(())
        } else {
            Err(format!(
                "authentication failed (auth={auth_rc}, acct={acct_rc})"
            ))
        }
    }
}
