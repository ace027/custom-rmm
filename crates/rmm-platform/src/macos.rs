use crate::{Platform, PlatformError};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Current;

impl Platform for Current {
    fn hostname(&self) -> Result<String, PlatformError> {
        let uts = rustix::system::uname();
        Ok(uts.nodename().to_string_lossy().into_owned())
    }
}
