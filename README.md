# muadib

A Linux implementation of the Android Debug Bridge (ADB) device side,
written in Rust. It exposes a USB gadget via `FunctionFS` so that a host
running `adb` can connect to the device as if it were an Android
device.

## Status

Early development. Currently supports:

- USB gadget registration as an ADB interface (class 0xFF/0x42/0x01)

## Requirements

- Linux with `ConfigFS` and `FunctionFS` support
- A UDC (USB Device Controller), either hardware or `dummy_hcd` for
  testing
- systemd (for socket activation and gadget lifecycle management)

## Building

```
cargo build --release
```

The build generates `descriptors.bin` and `strings.bin` in the cargo
output directory. These are the `FunctionFS` descriptor and string blobs
referenced by the systemd service unit.

## Installation

Install the binary, `FunctionFS` blobs, and systemd units:

```
sudo install -m 755 target/release/muadib /usr/bin/muadib
sudo install -d /usr/share/muadib
sudo install -m 644 target/release/build/muadib-*/out/descriptors.bin /usr/share/muadib/
sudo install -m 644 target/release/build/muadib-*/out/strings.bin /usr/share/muadib/
sudo install -m 644 systemd/*.service systemd/*.socket systemd/*.mount /etc/systemd/system/
```

Enable the gadget service and socket:

```
sudo systemctl daemon-reload
sudo systemctl enable muadib-gadget.service
sudo systemctl enable muadib.socket
```

When a host connects over USB, systemd activates `muadib.service` via
socket activation on the `FunctionFS` endpoints.

## Host side

```
adb devices
adb get-serialno
```
