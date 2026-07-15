# adibi

A Linux implementation of the Android Debug Bridge (ADB) device side,
written in Rust. It exposes a USB gadget via `FunctionFS` so that a host
running `adb` can connect to the device as if it were an Android
device.

## Status

Early development. Currently supports:

- USB gadget registration as an ADB interface (class 0xFF/0x42/0x01)
- Device identity discovery from DMI, `/proc/cpuinfo`,
  `/etc/os-release`, and `/etc/hostname`
- Interactive shell (`adb shell`)
- File transfer (`adb pull`, `adb push`)
- Port forwarding (`adb forward`) over TCP, abstract Unix, and
  filesystem Unix sockets
- Reboot (`adb reboot`)

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
sudo install -m 755 target/release/adibi /usr/bin/adibi
sudo install -d /usr/share/adibi
sudo install -m 644 target/release/build/adibi-*/out/descriptors.bin /usr/share/adibi/
sudo install -m 644 target/release/build/adibi-*/out/strings.bin /usr/share/adibi/
sudo install -m 644 systemd/*.service systemd/*.socket systemd/*.mount /etc/systemd/system/
```

Enable the gadget service and socket:

```
sudo systemctl daemon-reload
sudo systemctl enable adibi-gadget.service
sudo systemctl enable adibi.socket
```

When a host connects over USB, systemd activates `adibi.service` via
socket activation on the `FunctionFS` endpoints.

## Host side

```
adb devices
adb get-serialno
adb shell
adb pull /path/on/device /local/path
adb push /local/path /path/on/device
adb forward tcp:HOST_PORT tcp:DEVICE_PORT
adb forward tcp:HOST_PORT localabstract:NAME
adb forward tcp:HOST_PORT localfilesystem:PATH
adb forward --remove tcp:HOST_PORT
adb reboot
```
