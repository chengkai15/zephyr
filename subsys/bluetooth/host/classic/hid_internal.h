/** @file
 *  @brief Internal APIs for Bluetooth HID Device handling.
 */

/*
 * Copyright 2025 Xiaomi Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/bluetooth/classic/hid_device.h>

/** @brief Get the Bluetooth connection associated with a HID device.
 *
 * The pointer is only valid while the HID association is alive. Once
 * the HID device is disconnected the L2CAP channel underneath is torn
 * down and this helper returns NULL.
 *
 * @param hid HID device instance.
 *
 * @return Pointer to the Bluetooth connection, or NULL if no
 *         connection is associated.
 */
static inline struct bt_conn *bt_hid_device_conn(const struct bt_hid_device *hid)
{
	return hid->ctrl_session.br_chan.chan.conn;
}

/** @brief HID PSM values for control/interrupt channels. */
#define BT_L2CAP_PSM_HID_CTL 0x0011
#define BT_L2CAP_PSM_HID_INT 0x0013

/** @brief HIDP message types (upper nibble of HID header). */
#define BT_HID_MSG_TYPE_HANDSHAKE    0x00
#define BT_HID_MSG_TYPE_CONTROL      0x01
#define BT_HID_MSG_TYPE_GET_REPORT   0x04
#define BT_HID_MSG_TYPE_SET_REPORT   0x05
#define BT_HID_MSG_TYPE_GET_PROTOCOL 0x06
#define BT_HID_MSG_TYPE_SET_PROTOCOL 0x07
#define BT_HID_MSG_TYPE_GET_IDLE     0x08
#define BT_HID_MSG_TYPE_SET_IDLE     0x09
#define BT_HID_MSG_TYPE_DATA         0x0a
#define BT_HID_MSG_TYPE_DATAC        0x0b

/** @brief HID_CONTROL parameters (lower nibble of HID header). */
#define BT_HID_PAR_CONTROL_NOP                  0x00
#define BT_HID_PAR_CONTROL_HARD_RESET           0x01
#define BT_HID_PAR_CONTROL_SOFT_RESET           0x02
#define BT_HID_PAR_CONTROL_SUSPEND              0x03
#define BT_HID_PAR_CONTROL_EXIT_SUSPEND         0x04
#define BT_HID_PAR_CONTROL_VIRTUAL_CABLE_UNPLUG 0x05

/** @brief Mask for HID protocol parameter in SET/GET_PROTOCOL. */
#define BT_HID_PROTOCOL_MASK 0x01

/** @brief Report type field mask (lower two bits of parameter). */
#define BT_HID_PARAM_REPORT_TYPE_MASK 0x03
/** @brief Report size present flag in parameter field. */
#define BT_HID_PARAM_REPORT_SIZE_MASK 0x04

/** @brief Report type values used in GET/SET/DATA messages. */
#define BT_HID_PAR_REP_TYPE_OTHER   0x00
#define BT_HID_PAR_REP_TYPE_INPUT   0x01
#define BT_HID_PAR_REP_TYPE_OUTPUT  0x02
#define BT_HID_PAR_REP_TYPE_FEATURE 0x03

/** @brief HID device state machine values. */
enum bt_hid_state {
	BT_HID_STATE_DISCONNECTED = 0x00,
	BT_HID_STATE_CTRL_CONNECTING = 0x01,
	BT_HID_STATE_CTRL_CONNECTED = 0x02,
	BT_HID_STATE_INTR_CONNECTING = 0x03,
	BT_HID_STATE_CONNECTED = 0x04,
	BT_HID_STATE_DISCONNECTING = 0x05,
};

/** @brief HID header encoding (1 byte): upper nibble = message type, lower nibble = parameter. */
#define BT_HID_BUILD_HDR(t, p)       (uint8_t)((((t) & 0x0F) << 4) | ((p) & 0x0F))
#define BT_HID_GET_TRANS_FROM_HDR(x) (((x) >> 4) & 0x0f)
#define BT_HID_GET_PARAM_FROM_HDR(x) ((x) & 0x0f)

/** @brief HID header byte stored in a packed struct for buffer access. */
struct bt_hid_hdr {
	uint8_t header;
} __packed;
