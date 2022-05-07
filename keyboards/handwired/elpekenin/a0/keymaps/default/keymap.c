#include QMK_KEYBOARD_H
#include "keymap_spanish.h"
#include <string.h>
#include "raw_hid.h"

enum layer_names {
    _QWERTY,
    _FN,
    _LAYER2,
    _LAYER3,
};

enum my_keycodes {
    MY_VOLU = SAFE_RANGE,
    MY_LEFT,
    MY_UP,
    MY_RGHT,
    MY_DOWN,
    MY_4,

};

enum {
    TD_L,
    TD_R,
    TD_SPC,
};

uint8_t mod_state;

float song[][2] = SONG(MEGALOVANIA);

void my_clear(void){
    clear_mods();
    clear_weak_mods();
    clear_oneshot_mods();
}

void td_left_finished(qk_tap_dance_state_t *state, void *user_data) {
    mod_state = get_mods();
    switch (state->count) {
        case 1:
            tap_code16(ES_ACUT); // Â´ or {
            if (mod_state & MOD_BIT(KC_ALGR)) {
                tap_code16(ES_CCED); // }
            }
            break;

        case 2:
            tap_code16(ES_LBRC); // [
            tap_code16(ES_RBRC); // ]
            break;

        case 3:
            my_clear();
            tap_code16(ES_LPRN); // (
            tap_code16(ES_RPRN); // )
            break;

        default: // +3 times -> nothing
            break;
    }
    return;
}


void td_rght_finished(qk_tap_dance_state_t *state, void *user_data) {
    switch (state->count) {
        case 1:
            tap_code16(ALGR(ES_CCED)); // }
            break;

        case 2:
            tap_code16(ALGR(ES_PLUS)); // ]
            break;

        case 3:
            my_clear();
            tap_code16(S(KC_9)); // )
            break;

        case 4:
            my_clear();
            tap_code16(ES_CCED); // Ã§

        default: // +4 times -> nothing
            break;
    }
    return;
}


void td_spc_each(qk_tap_dance_state_t *state, void *user_data) {
    unregister_code16(KC_SPC);
    register_code16(KC_SPC);
    if ((state->count % 2) == 0) {
        SEND_STRING("  ");
    }
}

void td_spc_reset(qk_tap_dance_state_t *state, void *user_data) {
    unregister_code16(KC_SPC);
}

// All tap dance functions go here
qk_tap_dance_action_t tap_dance_actions[] = {
    [TD_L] = ACTION_TAP_DANCE_FN_ADVANCED(NULL, td_left_finished, NULL),
    [TD_R] = ACTION_TAP_DANCE_FN_ADVANCED(NULL, td_rght_finished, NULL),
    [TD_SPC] = ACTION_TAP_DANCE_FN_ADVANCED(td_spc_each, NULL, td_spc_reset),
};


const uint16_t PROGMEM keymaps[][MATRIX_ROWS][MATRIX_COLS] = {

 // Default layer
 [_QWERTY] =    LAYOUT_split_ortho_5x9(
                    KC_ESC,  ES_MORD, KC_1,    KC_2,  KC_3,    MY_4,     KC_5,  KC_6,                         KC_7,  KC_8,    KC_9,    KC_0,    ES_QUOT,  ES_IEXL,           KC_BSPC,
                    KC_TAB,           KC_Q,    KC_W,  KC_E,    KC_R,     KC_T,                       KC_Y,    KC_U,  KC_I,    KC_O,    KC_P,    ES_GRV,   ES_PLUS,           KC_DEL,
                    KC_CAPS,          KC_A,    KC_S,  KC_D,    KC_F,     KC_G,  KC_H,                         KC_J,  KC_K,    KC_L,    ES_NTIL, TD(TD_L), TD(TD_R), KC_ENT,  MY_VOLU,
                    KC_LSFT, ES_LABK, KC_Z,    KC_X,  KC_C,    KC_V,     KC_B,                       KC_N,    KC_M,  ES_COMM, ES_DOT,  ES_MINS, KC_RSFT,            MY_UP,   KC_VOLD,
                    KC_LCTL, KC_LGUI, KC_LALT, MO(1),        TD(TD_SPC),                          TD(TD_SPC),        MO(2),   KC_ALGR, MO(_FN), KC_RCTRL, MY_LEFT,  MY_DOWN, MY_RGHT
                ),


 // _FN Settings
 [_FN] =        LAYOUT_split_ortho_5x9(
                    XXXXXXX, A(KC_PSCR), KC_F1,   KC_F2,   KC_F3,   KC_F4,   KC_F5,   KC_F6,                    KC_F7,   KC_F8,   KC_F9,   KC_F10,  KC_F11,  KC_F12,           XXXXXXX,
                    XXXXXXX,             XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,          XXXXXXX,
                    XXXXXXX,             XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,
                    XXXXXXX,  XXXXXXX,   XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,          XXXXXXX, XXXXXXX,
                    XXXXXXX,  XXXXXXX,   XXXXXXX, XXXXXXX,          XXXXXXX,                           XXXXXXX,          XXXXXXX, XXXXXXX, _______, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX
                ),


 // _LAYER2 Settings
 // poner numpad
 [_LAYER2] =    LAYOUT_split_ortho_5x9(
                    _______,  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, KC_PSLS, KC_PAST, KC_PMNS, XXXXXXX,          XXXXXXX,
                    _______,           XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, KC_7,    KC_8,    KC_9,    KC_PPLS, XXXXXXX,          XXXXXXX,
                    XXXXXXX,           XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, KC_4,    KC_5,    KC_6,    XXXXXXX, XXXXXXX, XXXXXXX, MO(_LAYER3),
                    _______,  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, KC_1,    KC_2,    KC_3,    XXXXXXX,          XXXXXXX, TO(_QWERTY),
                    _______,  _______, _______, XXXXXXX,          XXXXXXX,                           KC_0,             ES_DOT,  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX
                ),


 // _LAYER3 Settings
 [_LAYER3] =    LAYOUT_split_ortho_5x9(
                    RESET,    XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,          XXXXXXX,
                    XXXXXXX,           XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,          XXXXXXX,
                    XXXXXXX,           XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, _______,
                    XXXXXXX,  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,                  XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX,          XXXXXXX, XXXXXXX,
                    XXXXXXX,  XXXXXXX, XXXXXXX, XXXXXXX,          XXXXXXX,                           XXXXXXX,          XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX, XXXXXXX
                ),
};


bool process_record_user (uint16_t keycode, keyrecord_t *record) {
    mod_state = get_mods();
    switch (keycode) {
        case MY_VOLU:
            if (record->event.pressed) {
                if (mod_state & MOD_BIT(KC_LSFT)) {  // LeftShift+VolU => LayerUp
                    layer_on(_LAYER2);
                } else {
                    register_code16(KC_VOLU); // else just vol_up
                }
            } else {
                unregister_code16(KC_VOLU);
            }
            return false;

        case MY_LEFT:
            if (record->event.pressed) {
                if (mod_state & MOD_BIT(KC_LALT)) {// LALT+LEFT=HOME
                    my_clear();
                    tap_code16(KC_HOME);
                } else {
                    register_code16(KC_LEFT); // else just left
                    return true;
                }
            } else {
                unregister_code16(KC_LEFT);
            }
            return false;

        case MY_UP:
            if (record->event.pressed) {
                if (mod_state & MOD_BIT(KC_LALT)) {// LALT+UP=PGUP
                    my_clear();
                    tap_code16(KC_LALT); // TODO
                    register_code16(KC_PGUP);
                } else {
                    register_code16(KC_UP); // else just UP
                    return true;
                }
            } else {
                unregister_code16(KC_UP);
                unregister_code16(KC_PGUP);
            }
            return false;

        case MY_RGHT:
            if (record->event.pressed) {
                if (mod_state & MOD_BIT(KC_LALT)) {// LALT+RGHT=END
                    my_clear();
                    tap_code16(KC_END);
                } else {
                    register_code16(KC_RGHT); // else just right
                    return true;
                }
            } else {
                unregister_code16(KC_RGHT);
            }
            return false;

        case MY_DOWN:
            if (record->event.pressed) {
                if (mod_state & MOD_BIT(KC_LALT)) {// LALT+DN=PGDN
                    my_clear();
                    register_code16(KC_PGDN);
                } else {
                    register_code16(KC_DOWN); // else just DOWN
                    return true;
                }
            } else {
                unregister_code16(KC_DOWN);
                unregister_code16(KC_PGDN);
            }
            return false;

        case MY_4:
            if (record->event.pressed) {
                if (mod_state & MOD_BIT(KC_ALGR)) { // spanish combo for tilde (~)
                    tap_code16(ES_TILD);
                } else if (mod_state & MOD_BIT(KC_LALT)) { // LALT+4=LALT+f4
                    tap_code16(A(KC_F4));
                } else {
                    register_code16(KC_4);
                    return true;
                }
            } else {
                unregister_code16(KC_4);
            }
            return false;
    }
    return true;
}

// This function is called when a packet is received on the raw HID interface.
// `length` will always be the size of the output (host to device) report in bytes - 32 in current QMK, but will eventually be raised to 64.
// Thus, if you wish to send variable length data, you should send the length along with the payload, splitting across multiple reports
// if needed, and handle the parsing yourself.
//
// In this simple example, we check that the first byte of the received data is the ASCII character 'A',
// in which case we respond with 'B' and toggle the backlight.
void raw_hid_receive(uint8_t *data, uint8_t length) {
    uint8_t response[RAW_EPSIZE];
    memset(response, 0, RAW_EPSIZE);

    // ------ Header ---------
    // copy token value
    response[0] = data[0];
    response[1] = data[1];

    // flags
    response[2] = 0b00000001;

    //length
    response[3] = length;
    // -----------------------

    // ------ Logic ---------
    if(data[3] == 'A') {
        response[4] = 'B';
    }
    else {
        response[4] = 'A';
    }

    response[10] = 1;
    response[11] = 2;
    response[12] = 3;

    response[RAW_EPSIZE-1] = 'F';
    raw_hid_send(response, RAW_EPSIZE);
}

void keyboard_post_init_user(void) {
    PLAY_SONG(song);
  // Customise these values to desired behaviour
  // debug_enable=true;
  // debug_matrix=true;
  // debug_keyboard=true;
  // debug_mouse=true;
}
