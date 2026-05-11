// Generates FunctionFS descriptor and string binary blobs for ADB.
//
// The resulting `descriptors.bin` and `strings.bin` are written to OUT_DIR and
// installed to `/usr/share/muadib/`. They are referenced by the systemd
// service unit's `USBFunctionDescriptors=` and `USBFunctionStrings=`
// directives.

#![expect(
    missing_docs,
    reason = "We don't care about the build script documentation"
)]

use std::{env, fs, io, path::Path};

#[path = "src/usb.rs"]
mod usb;

use crate::usb::{
    AsLittleEndianBytes as _, USB_CLASS_ADB, USB_LANG_EN_US, USB_PROTOCOL_ADB, USB_SUBCLASS_ADB,
};

// FunctionFS magic numbers
const FUNCTIONFS_DESCRIPTORS_MAGIC_V2: u32 = 3;
const FUNCTIONFS_STRINGS_MAGIC: u32 = 2;

// Descriptor flags
const FUNCTIONFS_HAS_FS_DESC: u32 = 1;
const FUNCTIONFS_HAS_HS_DESC: u32 = 2;

// USB descriptor types
const USB_DT_INTERFACE: u8 = 4;
const USB_DT_ENDPOINT: u8 = 5;

// Endpoint addresses
const EP_ADDR_OUT: u8 = 0x01;
const EP_ADDR_IN: u8 = 0x82;

// Bulk max packet sizes per speed
const FS_MAX_PACKET_SIZE: u16 = 64;
const HS_MAX_PACKET_SIZE: u16 = 512;

// ADB interface string (null-terminated)
const ADB_INTERFACE_STRING: &[u8; 14] = b"ADB Interface\0";

#[repr(C, packed)]
struct FfsDescsHeadV2 {
    magic: u32,
    length: u32,
    flags: u32,
}

#[repr(C, packed)]
struct FfsStringsHead {
    magic: u32,
    length: u32,
    str_count: u32,
    lang_count: u32,
}

#[repr(C, packed)]
struct UsbInterfaceDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_interface_number: u8,
    b_alternate_setting: u8,
    b_num_endpoints: u8,
    b_interface_class: u8,
    b_interface_sub_class: u8,
    b_interface_protocol: u8,
    i_interface: u8,
}

#[repr(C, packed)]
struct UsbEndpointDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    b_endpoint_address: u8,
    bm_attributes: u8,
    w_max_packet_size: u16,
    b_interval: u8,
}

#[repr(C, packed)]
struct FsHsDescriptors {
    intf: UsbInterfaceDescriptor,
    ep_out: UsbEndpointDescriptor,
    ep_in: UsbEndpointDescriptor,
}

#[repr(C, packed)]
struct AdbDescriptors {
    header: FfsDescsHeadV2,
    fs_count: u32,
    hs_count: u32,
    fs: FsHsDescriptors,
    hs: FsHsDescriptors,
}

#[repr(C, packed)]
struct AdbStrings {
    header: FfsStringsHead,
    lang_code: u16,
    string: [u8; ADB_INTERFACE_STRING.len()],
}

fn adb_interface() -> UsbInterfaceDescriptor {
    UsbInterfaceDescriptor {
        b_length: u8::try_from(size_of::<UsbInterfaceDescriptor>())
            .expect("Length of descriptor is < 255 bytes"),
        b_descriptor_type: USB_DT_INTERFACE,
        b_interface_number: 0,
        b_alternate_setting: 0,
        b_num_endpoints: 2,
        b_interface_class: USB_CLASS_ADB,
        b_interface_sub_class: USB_SUBCLASS_ADB,
        b_interface_protocol: USB_PROTOCOL_ADB,
        i_interface: 1,
    }
}

fn bulk_endpoint(address: u8, max_packet_size: u16) -> UsbEndpointDescriptor {
    UsbEndpointDescriptor {
        b_length: u8::try_from(size_of::<UsbEndpointDescriptor>())
            .expect("Length of descriptor is < 255 bytes"),
        b_descriptor_type: USB_DT_ENDPOINT,
        b_endpoint_address: address,
        bm_attributes: 0x02,
        w_max_packet_size: max_packet_size.to_le(),
        b_interval: 0,
    }
}

fn fs_hs_descs(max_packet_size: u16) -> FsHsDescriptors {
    FsHsDescriptors {
        intf: adb_interface(),
        ep_out: bulk_endpoint(EP_ADDR_OUT, max_packet_size),
        ep_in: bulk_endpoint(EP_ADDR_IN, max_packet_size),
    }
}

const DESCS_COUNT: u32 = 3; // interface + 2 endpoints

fn main() -> io::Result<()> {
    let out_dir = env::var("OUT_DIR").map_err(io::Error::other)?;
    let out_path = Path::new(&out_dir);

    fs::write(
        out_path.join("descriptors.bin"),
        AdbDescriptors {
            header: FfsDescsHeadV2 {
                magic: FUNCTIONFS_DESCRIPTORS_MAGIC_V2.to_le(),
                length: u32::try_from(size_of::<AdbDescriptors>())
                    .map_err(io::Error::other)?
                    .to_le(),
                flags: (FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC).to_le(),
            },
            fs_count: DESCS_COUNT.to_le(),
            hs_count: DESCS_COUNT.to_le(),
            fs: fs_hs_descs(FS_MAX_PACKET_SIZE.to_le()),
            hs: fs_hs_descs(HS_MAX_PACKET_SIZE.to_le()),
        }
        .as_le_bytes(),
    )?;

    fs::write(
        out_path.join("strings.bin"),
        AdbStrings {
            header: FfsStringsHead {
                magic: FUNCTIONFS_STRINGS_MAGIC.to_le(),
                length: u32::try_from(size_of::<AdbStrings>())
                    .map_err(io::Error::other)?
                    .to_le(),
                str_count: 1u32.to_le(),
                lang_count: 1u32.to_le(),
            },
            lang_code: USB_LANG_EN_US.to_le(),
            string: *ADB_INTERFACE_STRING,
        }
        .as_le_bytes(),
    )?;

    println!("cargo:rerun-if-changed=build.rs");

    Ok(())
}
