//! Device identity discovery from system sources.

use std::fs;

use dmidecode::{EntryPoint, Structure};
use log::debug;

const DEFAULT_NAME: &str = "adibi";

/// Identity information advertised during the ADB CNXN handshake.
#[derive(Debug)]
pub(crate) struct DeviceInfo {
    /// Device serial number (from DMI, `/proc/cpuinfo`, or `/etc/machine-id`).
    pub serial: String,
    /// Human-readable device name (from `/etc/os-release` `PRETTY_NAME`).
    pub name: String,
    /// Hardware model (from DMI product, `/proc/cpuinfo`, or device-tree).
    pub model: String,
    /// Short device identifier (from `/etc/hostname`).
    pub device: String,
}

/// Product name and serial extracted from SMBIOS/DMI tables.
struct DmiInfo {
    product: Option<String>,
    serial: Option<String>,
}

fn read_dmi() -> Option<DmiInfo> {
    let entry_data = fs::read("/sys/firmware/dmi/tables/smbios_entry_point").ok()?;
    let table_data = fs::read("/sys/firmware/dmi/tables/DMI").ok()?;

    let entry_point = EntryPoint::search(&entry_data).ok()?;

    for structure in entry_point.structures(&table_data) {
        if let Ok(Structure::System(system)) = structure {
            return Some(DmiInfo {
                product: non_empty(system.product),
                serial: non_empty(system.serial),
            });
        }
    }

    None
}

fn read_cpuinfo_field(field: &str) -> Option<String> {
    let contents = fs::read_to_string("/proc/cpuinfo").ok()?;

    for line in contents.lines() {
        let (key, value) = line.split_once(':')?;
        if key.trim() == field {
            return non_empty(value.trim());
        }
    }

    None
}

fn read_device_tree_model() -> Option<String> {
    let contents = fs::read_to_string("/proc/device-tree/model").ok()?;
    non_empty(contents.trim_end_matches('\0').trim())
}

fn read_os_pretty_name() -> Option<String> {
    let contents = fs::read_to_string("/etc/os-release").ok()?;

    for line in contents.lines() {
        let (key, value) = line.split_once('=')?;
        if key == "PRETTY_NAME" {
            let value = value.trim_matches('"');
            return non_empty(value);
        }
    }

    None
}

fn read_machine_id() -> Option<String> {
    let contents = fs::read_to_string("/etc/machine-id").ok()?;
    non_empty(contents.trim())
}

fn read_hostname() -> Option<String> {
    let contents = fs::read_to_string("/etc/hostname").ok()?;
    non_empty(contents.trim())
}

fn non_empty(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_owned())
    }
}

impl DeviceInfo {
    /// Discovers device identity from system sources.
    ///
    /// Probes DMI tables, `/proc/cpuinfo`, device-tree, `/etc/os-release`,
    /// `/etc/machine-id`, and `/etc/hostname`, falling back to defaults when
    /// a source is unavailable.
    pub(crate) fn from_system() -> Self {
        let dmi = read_dmi().unwrap_or_else(|| {
            debug!("DMI tables not available");
            DmiInfo {
                product: None,
                serial: None,
            }
        });

        let serial = dmi
            .serial
            .or_else(|| read_cpuinfo_field("Serial"))
            .or_else(read_machine_id)
            .unwrap_or_else(|| DEFAULT_NAME.to_owned());

        let name = read_os_pretty_name().unwrap_or_else(|| DEFAULT_NAME.to_owned());

        let model = dmi
            .product
            .or_else(|| read_cpuinfo_field("Model"))
            .or_else(read_device_tree_model)
            .unwrap_or_else(|| DEFAULT_NAME.to_owned());

        let device = read_hostname().unwrap_or_else(|| DEFAULT_NAME.to_owned());

        DeviceInfo {
            serial,
            name,
            model,
            device,
        }
    }
}
