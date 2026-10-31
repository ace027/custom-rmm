use std::fs;

use crate::{HwFacts, Platform, PlatformError};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Current;

/// Read one DMI attribute; `None` on any error (containers, no permission).
fn dmi(name: &str) -> Option<String> {
    let raw = fs::read_to_string(format!("/sys/class/dmi/id/{name}")).ok()?;
    let t = raw.trim();
    (!t.is_empty()).then(|| t.to_owned())
}

/// Extract `PRETTY_NAME` from os-release content.
fn pretty_name(os_release: &str) -> Option<String> {
    os_release.lines().find_map(|l| {
        let v = l.strip_prefix("PRETTY_NAME=")?.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|x| x.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
            .unwrap_or(v);
        Some(v.to_owned())
    })
}

impl Platform for Current {
    fn hostname(&self) -> Result<String, PlatformError> {
        let uts = rustix::system::uname();
        Ok(uts.nodename().to_string_lossy().into_owned())
    }

    fn hw_facts(&self) -> HwFacts {
        HwFacts {
            smbios_uuid: dmi("product_uuid"),
            system_serial: dmi("product_serial"),
            board_serial: dmi("board_serial"),
            manufacturer: dmi("sys_vendor"),
            model: dmi("product_name"),
        }
    }

    fn os_info(&self) -> (String, String) {
        let version = fs::read_to_string("/etc/os-release")
            .ok()
            .and_then(|c| pretty_name(&c))
            .unwrap_or_default();
        ("linux".to_owned(), version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pretty_name() {
        assert_eq!(
            pretty_name("NAME=Debian\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n").as_deref(),
            Some("Debian GNU/Linux 12")
        );
        assert_eq!(pretty_name("PRETTY_NAME='X 1'").as_deref(), Some("X 1"));
        assert_eq!(pretty_name("NAME=x"), None);
    }

    #[test]
    fn hw_facts_never_fail() {
        // Missing sysfs files (containers) just give None fields.
        let _ = Current.hw_facts();
        assert_eq!(Current.os_info().0, "linux");
    }
}
