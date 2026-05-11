//! USB class/subclass/protocol constants for the ADB interface.

#![expect(
    dead_code,
    reason = "This is shared between the main daemon and the build script"
)]

use core::{ptr, slice};

#[cfg(not(target_endian = "little"))]
compile_error!("muadib requires a little-endian target");

/// Trait for zero-copy conversion to a little-endian byte slice.
pub(crate) trait AsLittleEndianBytes {
    /// Returns `self` as a byte slice in little-endian wire format.
    fn as_le_bytes(&self) -> &[u8];
}

#[cfg(target_endian = "little")]
impl<T: Sized> AsLittleEndianBytes for T {
    fn as_le_bytes(&self) -> &[u8] {
        // SAFETY: We have a valid reference to &T and we know its lifetime is going to be at least
        // equal to ours.
        unsafe { slice::from_raw_parts(ptr::from_ref(self).cast::<u8>(), size_of::<Self>()) }
    }
}

/// USB manufacturer string for the ADB gadget.
pub(crate) const ADB_MANUFACTURER_EN: &str = "Android";

/// USB product string for the ADB gadget.
pub(crate) const ADB_PRODUCT_EN: &str = "Android Debug Bridge";

/// USB interface class for ADB (vendor-specific).
pub(crate) const USB_CLASS_ADB: u8 = 0xff;

/// USB interface subclass for ADB.
pub(crate) const USB_SUBCLASS_ADB: u8 = 0x42;

/// USB interface protocol for ADB.
pub(crate) const USB_PROTOCOL_ADB: u8 = 0x01;

/// Google's USB vendor ID.
pub(crate) const USB_VENDOR_ID_GOOGLE: u16 = 0x18d1;

/// USB product ID for ADB.
pub(crate) const USB_PRODUCT_ID_ADB: u16 = 0x4ee7;

/// USB language ID for English (US).
pub(crate) const USB_LANG_EN_US: u16 = 0x409;
