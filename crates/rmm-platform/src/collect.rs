//! Inventory and metric collection through `sysinfo` (OS APIs, no shelling out).

use std::collections::HashSet;

use rmm_proto::telemetry::{
    METRIC_CPU_USAGE_PCT, METRIC_DISK_FREE_PREFIX, METRIC_MEM_TOTAL_BYTES, METRIC_MEM_USED_BYTES,
    METRIC_UPTIME_S, Volume,
};
use sysinfo::{
    CpuRefreshKind, Disks, MINIMUM_CPU_UPDATE_INTERVAL, MemoryRefreshKind, RefreshKind, System,
};

use crate::Platform;

/// Inventory facts; mirrors `rmm_proto::telemetry::Inventory` without the
/// message envelope (`v`, `msg_id`, `sent_at`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryFacts {
    /// OS family.
    pub os_family: String,
    /// OS version string.
    pub os_version: String,
    /// Host name.
    pub hostname: String,
    /// CPU model, if known.
    pub cpu_model: Option<String>,
    /// Logical CPU count, if known.
    pub cpu_cores: Option<u32>,
    /// Installed RAM in bytes, if known.
    pub ram_bytes: Option<u64>,
    /// Volumes with a non-zero size.
    pub volumes: Vec<Volume>,
    /// Last boot, unix seconds.
    pub last_boot: Option<i64>,
}

/// Volumes with non-zero size and unique mount points.
fn volumes() -> Vec<Volume> {
    let Ok(disks) = Disks::new_with_refreshed_list() else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for d in disks.iter() {
        let total = d.total_space();
        if total == 0 {
            continue;
        }
        let mount = d.mount_point().to_string_lossy().into_owned();
        if !seen.insert(mount.clone()) {
            continue;
        }
        out.push(Volume {
            mount,
            total_bytes: total,
            free_bytes: d.available_space().min(total),
        });
    }
    out
}

/// Collect the static facts of this machine.
pub fn inventory() -> InventoryFacts {
    let sys = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing())
            .with_memory(MemoryRefreshKind::nothing().with_ram()),
    )
    .ok();
    let platform = crate::current();
    let (os_family, os_version) = platform.os_info();
    let hostname = platform.hostname().unwrap_or_default();
    let cpus = sys.as_ref().map_or(&[][..], |s| s.cpus());
    let cpu_model = cpus
        .first()
        .map(|c| c.brand().trim().to_owned())
        .filter(|b| !b.is_empty());
    let cpu_cores = u32::try_from(cpus.len()).ok().filter(|n| *n > 0);
    let ram = sys.as_ref().map_or(0, |s| s.total_memory());
    let boot = System::boot_time().unwrap_or(0);
    InventoryFacts {
        os_family,
        os_version,
        hostname,
        cpu_model,
        cpu_cores,
        ram_bytes: (ram > 0).then_some(ram),
        volumes: volumes(),
        last_boot: i64::try_from(boot).ok().filter(|b| *b > 0),
    }
}

/// Seconds since boot, 0 if unavailable.
pub fn uptime_s() -> u64 {
    System::uptime().unwrap_or(0)
}

/// Collect current metrics as `(name, value)` pairs; all values are finite.
/// Blocks for [`MINIMUM_CPU_UPDATE_INTERVAL`] to measure CPU usage, so call it
/// from a blocking context.
pub fn sample() -> Vec<(String, f64)> {
    let mut out = Vec::new();
    if let Ok(mut sys) = System::new_with_specifics(
        RefreshKind::nothing()
            .with_cpu(CpuRefreshKind::nothing().with_usage())
            .with_memory(MemoryRefreshKind::nothing().with_ram()),
    ) {
        std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        sys.refresh_cpu_usage();
        sys.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
        out.push((
            METRIC_CPU_USAGE_PCT.to_owned(),
            f64::from(sys.global_cpu_usage()).clamp(0.0, 100.0),
        ));
        out.push((METRIC_MEM_USED_BYTES.to_owned(), sys.used_memory() as f64));
        out.push((METRIC_MEM_TOTAL_BYTES.to_owned(), sys.total_memory() as f64));
    }
    for v in volumes() {
        out.push((
            format!("{METRIC_DISK_FREE_PREFIX}{}", v.mount),
            v.free_bytes as f64,
        ));
    }
    if let Ok(up) = System::uptime() {
        out.push((METRIC_UPTIME_S.to_owned(), up as f64));
    }
    out.retain(|(_, v)| v.is_finite());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inventory_has_ram_and_volume() {
        let inv = inventory();
        assert!(inv.ram_bytes.unwrap_or(0) > 0);
        assert!(!inv.volumes.is_empty());
        assert!(inv.volumes.iter().all(|v| v.total_bytes > 0));
        let mut mounts: Vec<_> = inv.volumes.iter().map(|v| &v.mount).collect();
        mounts.sort();
        mounts.dedup();
        assert_eq!(mounts.len(), inv.volumes.len());
    }

    #[test]
    fn sample_is_finite_and_cpu_in_range() {
        let s = sample();
        assert!(s.iter().all(|(_, v)| v.is_finite()));
        let cpu = s
            .iter()
            .find(|(n, _)| n == METRIC_CPU_USAGE_PCT)
            .expect("cpu metric")
            .1;
        assert!((0.0..=100.0).contains(&cpu));
        assert!(s.iter().any(|(n, _)| n == METRIC_UPTIME_S));
    }
}
