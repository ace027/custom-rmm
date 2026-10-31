use crate::{HwFacts, Platform, PlatformError};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Current;

impl Platform for Current {
    fn hostname(&self) -> Result<String, PlatformError> {
        let uts = rustix::system::uname();
        Ok(uts.nodename().to_string_lossy().into_owned())
    }

    fn hw_facts(&self) -> HwFacts {
        // macOS support is a later phase; no hardware facts yet.
        HwFacts::default()
    }

    fn os_info(&self) -> (String, String) {
        // macOS support is a later phase; the version is filled in then.
        ("macos".to_owned(), String::new())
    }
}
