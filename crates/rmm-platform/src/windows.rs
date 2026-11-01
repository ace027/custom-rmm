use crate::keystore::validate_name;
use crate::smbios::parse_rsmb;
use crate::{HwFacts, KeyStore, Platform, PlatformError};
use ::windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_MORE_DATA, HANDLE, HLOCAL, LocalFree,
};
use ::windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use ::windows::Win32::Security::Cryptography::{
    CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData,
};
use ::windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use ::windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
use ::windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
use ::windows::Win32::System::SystemInformation::{
    ComputerNameDnsHostname, FIRMWARE_TABLE_PROVIDER, GetComputerNameExW, GetSystemFirmwareTable,
};
use ::windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use ::windows::core::{PCWSTR, PWSTR, w};
use std::ffi::c_void;
use std::fs;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// `'RSMB'`: the raw SMBIOS firmware table provider.
const RSMB: FIRMWARE_TABLE_PROVIDER = FIRMWARE_TABLE_PROVIDER(0x5253_4D42);
/// SID string of LocalSystem.
const SYSTEM_SID: &str = "S-1-5-18";

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn os_err(what: &str, e: impl std::fmt::Display) -> PlatformError {
    PlatformError::Os(format!("{what}: {e}"))
}

/// Read a REG_SZ value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`.
fn registry_string(name: PCWSTR) -> Option<String> {
    let key = w!("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
    let mut bytes: u32 = 0;
    // SAFETY: a null data pointer asks for the required size in `bytes`, which
    // is a valid out pointer; key and name are NUL-terminated literals.
    let probe = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            name,
            RRF_RT_REG_SZ,
            None,
            None,
            Some(&mut bytes),
        )
    };
    if probe.is_err() || bytes == 0 {
        return None;
    }
    let mut buf = vec![0u16; (bytes as usize).div_ceil(2)];
    let mut cap = u32::try_from(buf.len() * 2).ok()?;
    // SAFETY: `buf` provides `cap` writable bytes and `cap` is passed as its
    // size, so the API cannot write past the buffer.
    let got = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key,
            name,
            RRF_RT_REG_SZ,
            None,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            Some(&mut cap),
        )
    };
    if got.is_err() {
        return None;
    }
    let units = (cap as usize / 2).min(buf.len());
    let s = String::from_utf16_lossy(&buf[..units]);
    Some(s.trim_end_matches('\0').trim().to_owned())
}

/// Frees a buffer allocated by the CryptoAPI / SDDL conversion on drop.
struct LocalBuf(*mut c_void);

impl Drop for LocalBuf {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate with
            // LocalAlloc and it is freed exactly once, here.
            unsafe {
                LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

/// Closes a kernel handle on drop.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle was opened by this module and is closed once, here.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

/// SID string of the user the current process runs as.
fn current_user_sid() -> Result<String, PlatformError> {
    let mut token = HANDLE::default();
    // SAFETY: GetCurrentProcess returns a pseudo-handle that needs no closing;
    // `token` is a valid out pointer and is closed by `OwnedHandle`.
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
        .map_err(|e| os_err("open process token", e))?;
    let token = OwnedHandle(token);
    let mut len = 0u32;
    // SAFETY: a null buffer asks for the required size in `len`; the call
    // fails with ERROR_INSUFFICIENT_BUFFER, which is expected here.
    let _ = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut len) };
    // u64 elements keep the buffer aligned for TOKEN_USER (it holds a pointer).
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` provides at least `len` writable bytes.
    unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            Some(buf.as_mut_ptr().cast::<c_void>()),
            len,
            &mut len,
        )
    }
    .map_err(|e| os_err("query token user", e))?;
    // SAFETY: the call succeeded, so `buf` starts with an aligned TOKEN_USER
    // whose SID points into `buf`, which outlives this borrow.
    let user = unsafe { &*buf.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = PWSTR::null();
    // SAFETY: `user.User.Sid` is a valid SID and `sid` a valid out pointer;
    // the string is freed by `LocalBuf`.
    unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) }
        .map_err(|e| os_err("format token SID", e))?;
    let _guard = LocalBuf(sid.0.cast::<c_void>());
    // SAFETY: on success `sid` is a NUL-terminated UTF-16 string.
    unsafe { sid.to_string() }.map_err(|e| os_err("decode token SID", e))
}

/// Protected DACL for the key directory: full control for SYSTEM and for the
/// user running the agent, nothing inherited. In production the agent runs as
/// SYSTEM, so only SYSTEM is granted.
fn key_dir_sddl() -> Result<Vec<u16>, PlatformError> {
    let user = current_user_sid()?;
    let mut sddl = String::from("D:P(A;OICI;FA;;;SY)");
    if user != SYSTEM_SID {
        sddl.push_str(&format!("(A;OICI;FA;;;{user})"));
    }
    Ok(sddl.encode_utf16().chain(Some(0)).collect())
}

/// Create `dir` (and missing parents) with the protected key-directory DACL on
/// the leaf. An existing directory is left untouched.
fn create_protected_dir(dir: &Path) -> Result<(), PlatformError> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(|e| os_err("create parent dir", e))?;
    }
    let sddl = key_dir_sddl()?;
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is NUL-terminated and outlives the call, and `sd` is a
    // valid out pointer; the allocated descriptor is released by `LocalBuf`.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(|e| os_err("build security descriptor", e))?;
    let _guard = LocalBuf(sd.0);
    let attrs = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };
    let path = wide(dir);
    // SAFETY: `path` is NUL-terminated and `attrs` (with the descriptor kept
    // alive by `_guard`) outlives the call.
    match unsafe { CreateDirectoryW(PCWSTR(path.as_ptr()), Some(&attrs)) } {
        Ok(()) => Ok(()),
        Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => Ok(()),
        Err(e) => Err(os_err("create state dir", e)),
    }
}

/// Agent key protected with DPAPI in the SYSTEM user scope (no
/// `CRYPTPROTECT_LOCAL_MACHINE`), stored in the named file under the state dir.
#[derive(Debug)]
pub(crate) struct DpapiKeyStore {
    dir: PathBuf,
    name: String,
}

impl DpapiKeyStore {
    pub(crate) fn new(dir: &Path, name: &str) -> Self {
        Self {
            dir: dir.to_path_buf(),
            name: name.to_owned(),
        }
    }

    fn path(&self) -> Result<PathBuf, PlatformError> {
        validate_name(&self.name)?;
        Ok(self.dir.join(&self.name))
    }
}

impl KeyStore for DpapiKeyStore {
    fn load(&self) -> Result<Option<[u8; 32]>, PlatformError> {
        let blob = match fs::read(self.path()?) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(os_err("read key file", e)),
        };
        let len = u32::try_from(blob.len()).map_err(|_| os_err("key file", "too large"))?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: len,
            pbData: blob.as_ptr().cast_mut(),
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `input` points at `blob`, which outlives the call and is only
        // read; `out` is a valid out blob whose buffer is freed below.
        unsafe {
            CryptUnprotectData(
                &input,
                None,
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| os_err("DPAPI unprotect failed (corrupt or foreign key blob)", e))?;
        let _free = LocalBuf(out.pbData.cast::<c_void>());
        // SAFETY: on success `out` describes `cbData` readable bytes.
        let plain = Zeroizing::new(unsafe {
            std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec()
        });
        if !out.pbData.is_null() {
            // SAFETY: zero the DPAPI-owned plaintext before it is freed.
            unsafe { std::ptr::write_bytes(out.pbData, 0, out.cbData as usize) };
        }
        let seed: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| os_err("key file", "decrypted key has wrong length"))?;
        Ok(Some(seed))
    }

    fn store(&self, seed: &[u8; 32]) -> Result<(), PlatformError> {
        let path = self.path()?;
        create_protected_dir(&self.dir)?;
        let input = CRYPT_INTEGER_BLOB {
            cbData: 32,
            pbData: seed.as_ptr().cast_mut(),
        };
        let mut out = CRYPT_INTEGER_BLOB::default();
        // SAFETY: `input` points at the 32-byte seed, only read; the description
        // is a NUL-terminated literal; `out` is freed below.
        unsafe {
            CryptProtectData(
                &input,
                w!("rmm-agent"),
                None,
                None,
                None,
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out,
            )
        }
        .map_err(|e| os_err("DPAPI protect failed", e))?;
        let _free = LocalBuf(out.pbData.cast::<c_void>());
        // SAFETY: on success `out` describes `cbData` readable bytes.
        let blob = unsafe { std::slice::from_raw_parts(out.pbData, out.cbData as usize) };

        let tmp = self.dir.join(format!("{}.tmp", self.name));
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(blob)?;
            f.sync_all()
        };
        write().map_err(|e| {
            let _ = fs::remove_file(&tmp);
            os_err("write key file", e)
        })?;
        let (from, to) = (wide(&tmp), wide(&path));
        // SAFETY: both paths are NUL-terminated and outlive the call.
        unsafe {
            MoveFileExW(
                PCWSTR(from.as_ptr()),
                PCWSTR(to.as_ptr()),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|e| {
            let _ = fs::remove_file(&tmp);
            os_err("replace key file", e)
        })
    }

    fn delete(&self) -> Result<(), PlatformError> {
        match fs::remove_file(self.path()?) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(os_err("delete key file", e)),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Current;

impl Platform for Current {
    fn hostname(&self) -> Result<String, PlatformError> {
        let mut size: u32 = 0;
        // SAFETY: a null buffer with size 0 is the documented way to probe the
        // required length; `size` is a valid out pointer for the whole call.
        let probe = unsafe { GetComputerNameExW(ComputerNameDnsHostname, None, &mut size) };
        match probe {
            Err(e) if e.code() == ERROR_MORE_DATA.to_hresult() => {}
            Err(e) => return Err(PlatformError::Os(e.to_string())),
            Ok(()) => {}
        }
        let mut buf = vec![0u16; size as usize];
        // SAFETY: `buf` holds `size` u16 elements and `size` is passed as its
        // capacity, so the API never writes beyond the buffer.
        unsafe {
            GetComputerNameExW(
                ComputerNameDnsHostname,
                Some(PWSTR(buf.as_mut_ptr())),
                &mut size,
            )
        }
        .map_err(|e| PlatformError::Os(e.to_string()))?;
        // On success `size` excludes the terminating NUL.
        buf.truncate(size as usize);
        Ok(String::from_utf16_lossy(&buf))
    }

    fn hw_facts(&self) -> HwFacts {
        // SAFETY: a null buffer asks for the required table size.
        let size = unsafe { GetSystemFirmwareTable(RSMB, 0, None) };
        if size == 0 {
            return HwFacts::default();
        }
        let mut buf = vec![0u8; size as usize];
        // SAFETY: `buf` is `size` writable bytes, passed as the buffer slice.
        let written = unsafe { GetSystemFirmwareTable(RSMB, 0, Some(&mut buf)) } as usize;
        if written == 0 {
            return HwFacts::default();
        }
        buf.truncate(written.min(buf.len()));
        parse_rsmb(&buf)
    }

    fn os_info(&self) -> (String, String) {
        let get = |n: PCWSTR| registry_string(n).unwrap_or_default();
        let product = get(w!("ProductName"));
        let display = get(w!("DisplayVersion"));
        let build = get(w!("CurrentBuild"));
        let version = format!("{product} {display} (build {build})");
        ("windows".to_owned(), version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::KEY_FILE;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("rmm-ks-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).expect("scratch dir");
        d
    }

    #[test]
    fn dpapi_round_trip() {
        let dir = scratch("dpapi");
        let ks = DpapiKeyStore::new(&dir, KEY_FILE);
        assert_eq!(ks.load().expect("load"), None);
        ks.store(&[5; 32]).expect("store");
        let on_disk = fs::read(ks.path().expect("path")).expect("read");
        assert_ne!(
            on_disk.as_slice(),
            [5u8; 32].as_slice(),
            "must be encrypted"
        );
        assert_eq!(ks.load().expect("load"), Some([5; 32]));
        ks.store(&[6; 32]).expect("replace");
        assert_eq!(ks.load().expect("load"), Some([6; 32]));
        ks.delete().expect("delete");
        assert_eq!(ks.load().expect("load"), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupted_blob_is_an_error() {
        let dir = scratch("corrupt");
        let ks = DpapiKeyStore::new(&dir, KEY_FILE);
        ks.store(&[5; 32]).expect("store");
        let mut blob = fs::read(ks.path().expect("path")).expect("read");
        let mid = blob.len() / 2;
        blob[mid] ^= 0xff;
        fs::write(ks.path().expect("path"), &blob).expect("corrupt");
        assert!(ks.load().is_err());
        fs::write(ks.path().expect("path"), b"junk").expect("junk");
        assert!(ks.load().is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn protected_dir_can_be_created() {
        let parent = scratch("acl");
        let dir = parent.join("RMM");
        create_protected_dir(&dir).expect("create");
        assert!(dir.exists());
        create_protected_dir(&dir).expect("existing dir is fine");
    }

    #[test]
    fn os_info_and_hw_facts_work() {
        let (family, version) = Current.os_info();
        assert_eq!(family, "windows");
        assert!(version.contains("build"));
        let _ = Current.hw_facts();
    }
}
