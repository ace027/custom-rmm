use crate::{Platform, PlatformError};
use ::windows::Win32::Foundation::ERROR_MORE_DATA;
use ::windows::Win32::System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW};
use ::windows::core::PWSTR;

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
}
