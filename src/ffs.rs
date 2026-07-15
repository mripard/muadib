//! `FunctionFS` event handling and USB gadget `ConfigFS` setup.

use core::fmt;
use std::{ffi::OsString, fs, io, mem::offset_of, os::fd::BorrowedFd, path::Path};

use log::info;
use thiserror::Error;

use crate::usb::{
    ADB_MANUFACTURER_EN, ADB_PRODUCT_EN, USB_LANG_EN_US, USB_PRODUCT_ID_ADB, USB_VENDOR_ID_GOOGLE,
};

const FFS_PATH: &str = "/run/muadib/ffs";
const GADGET_PATH: &str = "/sys/kernel/config/usb_gadget/muadib";

const FUNCTIONFS_BIND: u8 = 0;
const FUNCTIONFS_UNBIND: u8 = 1;
const FUNCTIONFS_ENABLE: u8 = 2;
const FUNCTIONFS_DISABLE: u8 = 3;
const FUNCTIONFS_SETUP: u8 = 4;
const FUNCTIONFS_SUSPEND: u8 = 5;
const FUNCTIONFS_RESUME: u8 = 6;

/// Representation of Linux' `usb_functionfs_event_type`
#[repr(u8)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum UsbFunctionFsEventType {
    Bind = FUNCTIONFS_BIND,
    Unbind = FUNCTIONFS_UNBIND,
    Enable = FUNCTIONFS_ENABLE,
    Disable = FUNCTIONFS_DISABLE,
    Setup = FUNCTIONFS_SETUP,
    Suspend = FUNCTIONFS_SUSPEND,
    Resume = FUNCTIONFS_RESUME,
}

#[derive(Debug, Error)]
#[error("Unknown FunctionFs Event Type: {0}")]
pub(crate) struct UsbFunctionFsEventTypeError(u8);

impl TryFrom<u8> for UsbFunctionFsEventType {
    type Error = UsbFunctionFsEventTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            FUNCTIONFS_BIND => Ok(Self::Bind),
            FUNCTIONFS_UNBIND => Ok(Self::Unbind),
            FUNCTIONFS_ENABLE => Ok(Self::Enable),
            FUNCTIONFS_DISABLE => Ok(Self::Disable),
            FUNCTIONFS_SETUP => Ok(Self::Setup),
            FUNCTIONFS_SUSPEND => Ok(Self::Suspend),
            FUNCTIONFS_RESUME => Ok(Self::Resume),
            other => Err(UsbFunctionFsEventTypeError(other)),
        }
    }
}

impl fmt::Display for UsbFunctionFsEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Representation of Linux' `usb_functionfs_event`
#[repr(C, packed)]
struct UsbFunctionFsEvent {
    // Actually usb_ctrlrequest, but we're not using it.
    _setup: [u8; 8],
    event_type: UsbFunctionFsEventType,
    _pad: [u8; 3],
}

/// Reads the next `FunctionFS` event and returns its type.
///
/// # Errors
///
/// Returns an error if the read fails, is too short, or contains an
/// unknown event type.
pub(crate) fn read_next_ffs_event_type(ep0: BorrowedFd<'_>) -> io::Result<UsbFunctionFsEventType> {
    let mut buf = [0u8; size_of::<UsbFunctionFsEvent>()];
    let n = rustix::io::read(ep0, &mut buf)?;
    if n < size_of::<UsbFunctionFsEvent>() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short ep0 event read",
        ));
    }

    UsbFunctionFsEventType::try_from(buf[offset_of!(UsbFunctionFsEvent, event_type)])
        .map_err(io::Error::other)
}

/// Creates the USB gadget directory structure in `ConfigFS`.
///
/// # Errors
///
/// Returns an error if any directory creation or file write in `ConfigFS` fails.
pub(crate) fn setup_gadget() -> io::Result<()> {
    let gadget_path = Path::new(GADGET_PATH);

    fs::create_dir_all(FFS_PATH)?;
    fs::create_dir_all(gadget_path)?;
    fs::write(
        gadget_path.join("idVendor"),
        format!("{USB_VENDOR_ID_GOOGLE:#06x}"),
    )?;
    fs::write(
        gadget_path.join("idProduct"),
        format!("{USB_PRODUCT_ID_ADB:#06x}"),
    )?;

    let strings_path = gadget_path.join("strings");
    let strings_en_path = strings_path.join(format!("{USB_LANG_EN_US:#x}"));

    fs::create_dir_all(&strings_en_path)?;
    fs::write(strings_en_path.join("manufacturer"), ADB_MANUFACTURER_EN)?;
    fs::write(strings_en_path.join("product"), ADB_PRODUCT_EN)?;

    let device_info = crate::device_info::DeviceInfo::from_system();
    info!("device serial: {}", device_info.serial);
    fs::write(strings_en_path.join("serialnumber"), &device_info.serial)?;

    let config_path = gadget_path.join("configs/c.1");
    fs::create_dir_all(&config_path)?;

    let config_strings_path = config_path.join("strings");
    let config_strings_en_path = config_strings_path.join(format!("{USB_LANG_EN_US:#x}"));
    fs::create_dir_all(&config_strings_en_path)?;

    fs::write(config_strings_en_path.join("configuration"), "adb")?;

    let function = gadget_path.join("functions/ffs.adb");
    fs::create_dir_all(&function)?;

    let link = config_path.join("ffs.adb");
    if !fs::exists(&link)? {
        std::os::unix::fs::symlink(&function, &link)?;
    }

    Ok(())
}

/// Returns the name of the first available USB Device Controller.
///
/// # Errors
///
/// Returns an error if `/sys/class/udc` cannot be read or is empty.
pub(crate) fn find_udc() -> io::Result<OsString> {
    fs::read_dir("/sys/class/udc")?
        .next()
        .transpose()?
        .map(|e| e.file_name())
        .ok_or(io::Error::new(io::ErrorKind::NotFound, "no UDC found"))
}

/// Binds the USB gadget to the first available UDC.
///
/// # Errors
///
/// Returns an error if no UDC is found or the `ConfigFS` write fails.
pub(crate) fn bind_udc() -> io::Result<()> {
    let udc = find_udc()?;

    info!(
        "binding to UDC: {}",
        udc.to_str().unwrap_or("(non-utf8 string)")
    );

    fs::write(Path::new(GADGET_PATH).join("UDC"), udc.as_encoded_bytes())
}

/// Unbinds the USB gadget from its current UDC.
///
/// # Errors
///
/// Returns an error if the `ConfigFS` write fails.
pub(crate) fn unbind_udc() -> io::Result<()> {
    fs::write(Path::new(GADGET_PATH).join("UDC"), "")
}
