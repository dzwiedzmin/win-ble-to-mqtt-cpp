# win-ble-to-mqtt-cpp

> Xiaomi BLE To MQTT Gateway

Search, connect and authenticate to Xiaomi Mijia Bluetooth Temperature Humidity Sensor and relay the readings to a MQTT broker.
License: GPL.

Inspired and based on
https://github.com/urish/win-ble-cpp



## What does it do?

1. Scans for BLE devices with a `0x180f` Primary Service (Battery Level)
2. Connects to any matching device and Authenticates using Xiaomi protocol (otherwise the connection will be dropped after 10 seconds). No pairing, no Xiaomi Cloud needed.
3. Subscribes to temp and humitidity notifications and relays the reading to a MQTT broker.

Note: This only works on Windows 10 Creators Update. Prior Windows 10 versions did not support BLE connections with unpaired devices.

## Supported devices

Tested with a couple of LYWSDCGQ/01ZM sensors but should work with other BLE/Xiaomi sensors and devices with little or no changes.