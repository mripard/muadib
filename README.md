# muadib

A Linux implementation of the Android Debug Bridge (ADB) device side,
written in Rust. It exposes a USB gadget via `FunctionFS` so that a host
running `adb` can connect to the device as if it were an Android
device.

## Status

Early development.

## Requirements

- Linux with `ConfigFS` and `FunctionFS` support
- A UDC (USB Device Controller), either hardware or `dummy_hcd` for
  testing
- systemd (for socket activation and gadget lifecycle management)

## Building

```
cargo build --release
```
