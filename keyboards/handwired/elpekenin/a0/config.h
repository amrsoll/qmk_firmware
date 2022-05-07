#pragma once

/* USB Device descriptor parameter */
#define VENDOR_ID    0xFEED
#define PRODUCT_ID   0x6465
#define DEVICE_VER   0x0001
#define MANUFACTURER QMK
#define PRODUCT elpekenin a0
/* XAP Config */
#define RAW_USAGE_PAGE 0xFF51
#define RAW_USAGE_ID 0x58

/* Split configuration */
#define USE_SERIAL
#define MASTER_LEFT
#define SOFT_SERIAL_PIN D0

/* Matrix configuration */
#define DIODE_DIRECTION COL2ROW

#define MATRIX_ROWS 10
#define MATRIX_COLS 9

#define MATRIX_COL_PINS { D3, D2, D4, C6, D7, E6, B4, F4, F5 }
#define MATRIX_ROW_PINS { F6, F7, B1, B3, B2 }
#define AUDIO_PIN B5

/* Debounce reduces chatter (unintended double-presses) - set 0 if debouncing is not needed */
#define DEBOUNCE 5

// /* Mechanical locking support. Use KC_LCAP, KC_LNUM or KC_LSCR instead in keymap */
// #define LOCKING_SUPPORT_ENABLE
// /* Locking resynchronize hack */
// #define LOCKING_RESYNC_ENABLE

#define TAPPING_TERM 500

