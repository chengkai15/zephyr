.. zephyr:code-sample:: ble_peripheral_hogp
   :name: HID over GATT Profile Device (Peripheral)
   :relevant-api: bt_hogp_device bt_hid bt_bas bluetooth

   Expose a HID Service acting as a Bluetooth LE mouse.

Overview
********

Application demonstrating the HID over GATT Profile (HOGP) Device role. It
registers a HID Service describing a three button mouse with X, Y and wheel
axes, and once a Host subscribes to the Input Report it reports a horizontal
movement that changes direction every two seconds, so the pointer moves back
and forth on the connected Host.

Alongside the HID Service the sample enables the Device Information Service
(including the PnP ID characteristic required by HOGP) and the Battery
Service, which a HOGP Host expects to find on a HID Device.

All HID Service characteristics require an encrypted link, so the Host has to
pair with the device before reports can be exchanged.

Requirements
************

* A board with Bluetooth LE support
* A Host supporting HOGP (Linux with BlueZ, Windows, macOS, Android or iOS)

Building and Running
********************

This sample can be found under :zephyr_file:`samples/bluetooth/peripheral_hogp`
in the Zephyr tree.

.. zephyr-app-commands::
   :zephyr-app: samples/bluetooth/peripheral_hogp
   :board: nrf52840dk/nrf52840
   :goals: build flash
   :compact:

After flashing, the device advertises as ``Zephyr HOGP Mouse``. Pair with it
from the Host Bluetooth settings; it is then reported as a mouse and the
pointer starts moving. The sample logs the HID events it receives, for example
GET_REPORT and SET_REPORT requests, Protocol Mode changes, Suspend and Exit
Suspend, and notification enable and disable.
