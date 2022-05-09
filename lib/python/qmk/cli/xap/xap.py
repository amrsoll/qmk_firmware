"""Interactions with compatible XAP devices
"""
import cmd
from contextlib import suppress
import gzip
import json
import random
import sys
from platform import platform

from milc import cli

KEYCODE_MAP = {
    # TODO: this should be data driven...
    0x0000: "XXXX",
    0x0004:	"KC_A",
    0x0005:	"KC_B",
    0x0006:	"KC_C",
    0x0007:	"KC_D",
    0x0008:	"KC_E",
    0x0009:	"KC_F",
    0x000A:	"KC_G",
    0x000B:	"KC_H",
    0x000C:	"KC_I",
    0x000D:	"KC_J",
    0x000E:	"KC_K",
    0x000F:	"KC_L",
    0x0010:	"KC_M",
    0x0011:	"KC_N",
    0x0012:	"KC_O",
    0x0013:	"KC_P",
    0x0014:	"KC_Q",
    0x0015:	"KC_R",
    0x0016:	"KC_S",
    0x0017:	"KC_T",
    0x0018:	"KC_U",
    0x0019:	"KC_V",
    0x001A:	"KC_W",
    0x001B:	"KC_X",
    0x001C:	"KC_Y",
    0x001D:	"KC_Z",
    0x001E:	"KC_1",
    0x001F:	"KC_2",
    0x0020:	"KC_3",
    0x0021:	"KC_4",
    0x0022:	"KC_5",
    0x0023:	"KC_6",
    0x0024:	"KC_7",
    0x0025:	"KC_8",
    0x0026:	"KC_9",
    0x0027:	"KC_0",
    0x0028:	"KC_ENTER",
    0x0029:	"KC_ESCAPE",
    0x002A:	"KC_BACKSPACE",
    0x002B:	"KC_TAB",
    0x002C:	"KC_SPACE",
    0x002D:	"KC_MINUS",
    0x002E:	"KC_EQUAL",
    0x002F:	"KC_LEFT_BRACKET",
    0x0030:	"KC_RIGHT_BRACKET",
    0x0031:	"KC_BACKSLASH",
    0x0032:	"KC_NONUS_HASH",
    0x0033:	"KC_SEMICOLON",
    0x0034:	"KC_QUOTE",
    0x0035:	"KC_GRAVE",
    0x0036:	"KC_COMMA",
    0x0037:	"KC_DOT",
    0x0038:	"KC_SLASH",
    0x0039:	"KC_CAPS_LOCK",
    0x003A:	"KC_F1",
    0x003B:	"KC_F2",
    0x003C:	"KC_F3",
    0x003D:	"KC_F4",
    0x003E:	"KC_F5",
    0x003F:	"KC_F6",
    0x0040:	"KC_F7",
    0x0041:	"KC_F8",
    0x0042:	"KC_F9",
    0x0043:	"KC_F10",
    0x0044:	"KC_F11",
    0x0045:	"KC_F12",
    0x0046:	"KC_PRINT_SCREEN",
    0x0047:	"KC_SCROLL_LOCK",
    0x0048:	"KC_PAUSE",
    0x0049:	"KC_INSERT",
    0x004A:	"KC_HOME",
    0x004B:	"KC_PAGE_UP",
    0x004C:	"KC_DELETE",
    0x004D:	"KC_END",
    0x004E:	"KC_PAGE_DOWN",
    0x004F:	"KC_RIGHT",
    0x0050:	"KC_LEFT",
    0x0051:	"KC_DOWN",
    0x0052:	"KC_UP",
    0x0053:	"KC_NUM_LOCK",
    0x0054:	"KC_KP_SLASH",
    0x0055:	"KC_KP_ASTERISK",
    0x0056:	"KC_KP_MINUS",
    0x0057:	"KC_KP_PLUS",
    0x0058:	"KC_KP_ENTER",
    0x0059:	"KC_KP_1",
    0x005A:	"KC_KP_2",
    0x005B:	"KC_KP_3",
    0x005C:	"KC_KP_4",
    0x005D:	"KC_KP_5",
    0x005E:	"KC_KP_6",
    0x005F:	"KC_KP_7",
    0x0060:	"KC_KP_8",
    0x0061:	"KC_KP_9",
    0x0062:	"KC_KP_0",
    0x0063:	"KC_KP_DOT",
    0x0064:	"KC_NONUS_BACKSLASH",
    0x0065:	"KC_APPLICATION",
    0x0066:	"KC_KB_POWER",
    0x0067:	"KC_KP_EQUAL",
    0x0068:	"KC_F13",
    0x0069:	"KC_F14",
    0x006A:	"KC_F15",
    0x006B:	"KC_F16",
    0x006C:	"KC_F17",
    0x006D:	"KC_F18",
    0x006E:	"KC_F19",
    0x006F:	"KC_F20",
    0x0070:	"KC_F21",
    0x0071:	"KC_F22",
    0x0072:	"KC_F23",
    0x0073:	"KC_F24",
    0x0074:	"KC_EXECUTE",
    0x0075:	"KC_HELP",
    0x0076:	"KC_MENU",
    0x0077:	"KC_SELECT",
    0x0078:	"KC_STOP",
    0x0079:	"KC_AGAIN",
    0x007A:	"KC_UNDO",
    0x007B:	"KC_CUT",
    0x007C:	"KC_COPY",
    0x007D:	"KC_PASTE",
    0x007E:	"KC_FIND",
}

# should create a config file or read from XAP specification
HID_REPORT_LENGTH  = 32 # size of each HID report
TOKEN_LENGTH       = 2  # bytes on each XAP transaction used for the token (transaction id)
PAYLOAD_LENGTH     = 1  # bytes on each XAP transaction used for specifying the payload length (also in bytes)
MAX_PAYLOAD_LENGTH = 128 # constrain in the specification to reduce RAM usage
TIMEOUT            = 1000 # timeout (in ms) we wait for an answer


def _is_xap_usage(x):
    return x['usage_page'] == 0xFF51 and x['usage'] == 0x0058


def _is_filtered_device(x):
    name = "%04X:%04X" % (x['vendor_id'], x['product_id'])
    return name.lower().startswith(cli.args.device.lower())


def _search():
    devices = filter(_is_xap_usage, hid.enumerate())
    if cli.args.device:
        devices = filter(_is_filtered_device, devices)

    return list(devices)


def print_dotted_output(kb_info_json, prefix=''):
    """Print the info.json in a plain text format with dot-joined keys.
    """
    for key in sorted(kb_info_json):
        new_prefix = f'{prefix}.{key}' if prefix else key

        if key in ['parse_errors', 'parse_warnings']:
            continue
        elif key == 'layouts' and prefix == '':
            cli.echo('    {fg_blue}layouts{fg_reset}: %s', ', '.join(sorted(kb_info_json['layouts'].keys())))
        elif isinstance(kb_info_json[key], bytes):
            conv = "".join(["{:02X}".format(b) for b in kb_info_json[key]])
            cli.echo('    {fg_blue}%s{fg_reset}: %s', new_prefix, conv)
        elif isinstance(kb_info_json[key], dict):
            print_dotted_output(kb_info_json[key], new_prefix)
        elif isinstance(kb_info_json[key], list):
            data = kb_info_json[key]
            if len(data) and isinstance(data[0], dict):
                for index, item in enumerate(data, start=0):
                    cli.echo('    {fg_blue}%s.%s{fg_reset}: %s', new_prefix, index, str(item))
            else:
                cli.echo('    {fg_blue}%s{fg_reset}: %s', new_prefix, ', '.join(sorted(map(str, data))))
        else:
            cli.echo('    {fg_blue}%s{fg_reset}: %s', new_prefix, kb_info_json[key])


def log_hid_report(report, sent=True):
    """Logs an HID report for debugging

    Args:
        sent: Whether this report is in our outbound
    """

    mode = 'Received'
    formatted = ''
    if sent: # remove leading 0 for logging purposes
        mode = 'Sending'
        removed = report.pop(0)
        formatted += f'Leading 0x00 | '
    # bytes 0&1 => token
    formatted += f'Token: {hex(int.from_bytes(report[:2], "little"))} | '

    # prepend the leading zero back, both kind of message's payload has the same alignment with this
    # could use manually insert "0", but im inserting the popped value just in case
    if sent:
        report.insert(0, removed)

    # received bytes 2/3=> Flags / Payload length
    else:
        formatted += f'Flags: {format(report[2], "b").zfill(8)} | '

    formatted += f'Payload Length: {hex(report[3])} | '

    # payload
    formatted += ' '.join(str(hex(v)) for v in report[4:])

    formatted += f' ({len(report)} bytes)'

    # distinguiss in/out going data
    if not sent:
        formatted += '\n' + '-'*50

    cli.log.debug('%s HID transaction:\n%s', mode, formatted)


def _hid_transaction(device, report):
    """Send an HID report and return its answer

    Returns:
        hid_report gotten from the keyboard
    """

    # pad with zeros if needed
    report.extend([0x00] * (HID_REPORT_LENGTH-len(report)))

    log_hid_report(report)

    device.write(bytes(report))
    hid_response = device.read(HID_REPORT_LENGTH, TIMEOUT)

    log_hid_report(hid_response, sent=False)

    # validate token received, remember the leading 0
    if report[1:3] != hid_response[:2]:
        # TODO implement logic upon received a "fail" message, just quits for now
        cli.log.critical("Token received doesn't match the sent one")
        sys.exit()


    # flag logic could maybe stop the process when device is locked or something

    return hid_response

def _merge_hid_reports(xap_transaction, hid_report):
    """Combine several HID reports into a single XAP transaction

    Args:
        xap_transaction
        hid_report

    Returns:
        xap_transaction with new data
    """

    # only add token and payload length headers on the 1st response HID report
    if not xap_transaction:
        xap_transaction.extend(hid_report[:4])

    # update flags on each HID report
    xap_transaction[2] = hid_report[2]

    # payload
    xap_transaction.extend(hid_report[4:])

    return xap_transaction


def log_xap_transaction(transaction, sent=True):
    """Logs a XAP transaction for debugging

    Args:
        sent: Whether this transaction is in our outbound
    """

    mode = 'Received'
    if sent: # remove leading 0 for logging purposes
        mode = 'Sending'
        removed = transaction.pop(0)

    # bytes 0&1 => token
    formatted = f'Token: {hex(int.from_bytes(transaction[:2], "little"))} | '

    # if sending, prepend the leading zero back, both kind of message's payload has the same alignment wit this
    if sent:
        transaction.insert(0, removed)

    # received bytes 2/3=> Flags / Payload length
    else:
        formatted += f'Flags: {format(transaction[2], "b").zfill(8)} | '

    formatted += f'Payload Length: {hex(transaction[3])} |'

    # payload
    counter = 4
    for v in transaction[4:]:
        formatted += f' {str(hex(v))}'
        counter += 1

        if counter == HID_REPORT_LENGTH: # split payload on HID sized block
            formatted += " //"
            counter = 4

    formatted += f' ({len(transaction)} bytes)'

    if sent:
        formatted += '\n' + '-'*50

    cli.log.debug('%s XAP transaction:\n%s', mode, formatted)


def _xap_transaction(
        device,
        #sub, route,
        *args, special=""
    ):
    # im assuming sub and route are optional fields, and args is used to set the *entire* payload

    # could maybe be changed to accept 1-key **kwargs so that we can use things like
    #     broadcast=1
    #     forget=True

    """Sends XAP transaction

    A XAP transaction can have up to 128 payload bytes, so we need to split it into several HID reports (64 bytes)

    Args:
        device: connection to the XAP-capable device
        special: Represents if this message is a special one (`fire&forget` or `broadcast` at the moment)

    Returns:
        payload of the response
    """

    # convert payload to bytes
    payload = bytearray()
    for arg in args:
        # if already in bytes just add at the end
        if isinstance(arg, (bytes, bytearray)):
            payload.extend(arg)

        # otherwise convert it
        # TODO some types and/or values might break this
        # check how many bytes are needed so that the data fits
        # check if its an Iterable
        # so on...
        else:
            payload.extend(arg.to_bytes(1, 'little'))

    payload_length = len(payload)

    # check if it fits in a single request
    if payload_length > MAX_PAYLOAD_LENGTH:
        raise ValueError('Payload is too big to fit in a single XAP transaction')

    # check special types of messages
    if special == 'forget':
        tok = 0x0000
    elif special == 'broadcast':
        tok = 0xFFFF
    else:
        tok = random.getrandbits(TOKEN_LENGTH * 8)
    token = tok.to_bytes(TOKEN_LENGTH, 'little')

    # set up the header
    # we need a 0 at the start of outgoing HID reports because of how hid.write() works
    header = bytearray([0x00])
    header.extend(token)
    header.extend(payload_length.to_bytes(PAYLOAD_LENGTH, 'little'))
    header_size = len(header)

    log_xap_transaction(header + payload)

    # initialize header-only report
    sent_report_size = header_size
    sent_report = header.copy()

    # initialize XAP response tracker
    received_transaction = []

    # divide the XAP transaction into several HID reports
    for byte in payload:
        sent_report.append(byte)
        sent_report_size += 1

        if sent_report_size == HID_REPORT_LENGTH:
            # TODO the logic in here might be combined into a single function
            received_report = _hid_transaction(device, sent_report)

            # merge all response HID reports into the response XAP transaction
            received_transaction = _merge_hid_reports(received_transaction, received_report)

            # reset the HID report
            sent_report = header.copy()
            sent_report_size = header_size

    # if there's some data remaining, send it
    if sent_report_size > header_size:
        received_report = _hid_transaction(device, sent_report)
        received_transaction = _merge_hid_reports(received_transaction, received_report)

    # remove trailing zeroes according to the payload data header of the response
    received_transaction_len = int(received_transaction[3])
    received_transaction = received_transaction[:4+received_transaction_len]

    log_xap_transaction(received_transaction, sent=False)

    # check if the transaction ended successfully
    if int(received_transaction[2]) != 0x01:
        return None

    # return response payload
    payload = received_transaction[4:]
    return payload


def _query_device(device):
    ver_data = _xap_transaction(device, 0x00, 0x00)
    if not ver_data:
        return {'xap': 'UNKNOWN', 'secure': 'UNKNOWN'}

    # to u32 to BCD string
    a = (ver_data[3] << 24) + (ver_data[2] << 16) + (ver_data[1] << 8) + (ver_data[0])
    ver = f'{a>>24}.{a>>16 & 0xFF}.{a & 0xFFFF}'

    secure = int.from_bytes(_xap_transaction(device, 0x00, 0x03), 'little')
    secure = 'unlocked' if secure == 2 else 'LOCKED'

    return {'xap': ver, 'secure': secure}


def _query_device_id(device):
    return _xap_transaction(device, 0x01, 0x08)


def _query_device_info_len(device):
    len_data = _xap_transaction(device, 0x01, 0x05)
    if not len_data:
        return 0

    # to u32
    return (len_data[3] << 24) + (len_data[2] << 16) + (len_data[1] << 8) + (len_data[0])


def _query_device_info_chunk(device, offset):
    return _xap_transaction(device, 0x01, 0x06, offset)


def _query_device_info(device):
    datalen = _query_device_info_len(device)
    if not datalen:
        return {}

    data = []
    offset = 0
    while offset < datalen:
        data += _query_device_info_chunk(device, offset)
        offset += 32
    str_data = gzip.decompress(bytearray(data[:datalen]))
    return json.loads(str_data)


def _list_devices():
    """Dump out available devices
    """
    cli.log.info('Available devices:')
    devices = _search()
    for dev in devices:
        device = hid.Device(path=dev['path'])

        data = _query_device(device)
        cli.log.info("  %04X:%04X %s %s [API:%s] %s", dev['vendor_id'], dev['product_id'], dev['manufacturer_string'], dev['product_string'], data['xap'], data['secure'])

        if cli.config.general.verbose:
            # TODO: better formatting like "lsusb -v"?
            data = _query_device_info(device)
            data["_id"] = _query_device_id(device)
            print_dotted_output(data)


def xap_dump_keymap(device):
    # get layer count
    layers = _xap_transaction(device, 0x04, 0x01)
    layers = int.from_bytes(layers, "little")
    print(f'layers:{layers}')

    # get keycode [layer:0, row:0, col:0]
    # keycode = _xap_transaction(device, 0x04, 0x02, b"\x00\x00\x00")

    # get encoder [layer:0, index:0, clockwise:0]
    keycode = _xap_transaction(device, 0x05, 0x02, b"\x00\x00\x00")

    keycode = int.from_bytes(keycode, "little")
    print(f'keycode:{KEYCODE_MAP.get(keycode, "unknown")}[{keycode}]')

    # set encoder [layer:0, index:0, clockwise:0, keycode:KC_A]
    _xap_transaction(device, 0x05, 0x03, b"\x00\x00\x00\x04\00")


def xap_broadcast_listen(device):
    try:
        cli.log.info("Listening for XAP broadcasts...")
        while True:
            array_alpha = device.read(64, TIMEOUT)
            if b'\xFF\xFF' == array_alpha[:2]:
                data_size = array_alpha[3]
                data = bytes(reversed(array_alpha[4:4+data_size]))
                if array_alpha[2] == 1:
                    cli.log.info(f"  Broadcast: Secure[{data}]")
                else:
                    cli.log.info(f"  Broadcast: type[{array_alpha[2]}] data:[{data}]")
    except KeyboardInterrupt:
        cli.log.info("Stopping...")


def xap_unlock(device):
    _xap_transaction(device, 0x00, 0x04)


class XAPShell(cmd.Cmd):
    intro = 'Welcome to the XAP shell.  Type help or ? to list commands.\n'
    prompt = 'Ψ> '

    def __init__(self, device):
        cmd.Cmd.__init__(self)
        self.device = device

    def do_about(self, arg):
        """Prints out the current version of QMK with a build date
        """
        data = _query_device(self.device)
        print(data)

    def do_unlock(self, arg):
        """Initiate secure unlock
        """
        xap_unlock(self.device)
        print("Done")

    def do_listen(self, arg):
        """Log out XAP broadcast messages
        """
        xap_broadcast_listen(self.device)

    def do_keycode(self, arg):
        """Prints out the keycode value of a certain layer, row, and column
        """
        data = bytes(map(int, arg.split()))
        if len(data) != 3:
            cli.log.error("Invalid args")
            return

        keycode = _xap_transaction(self.device, 0x04, 0x02, *data)
        keycode = int.from_bytes(keycode, 'little')
        print(f'keycode:{KEYCODE_MAP.get(keycode, "unknown")}[{keycode}]')

    def do_keymap(self, arg):
        """Prints out the keymap of a certain layer, given its row, column size (start_row, start_col)
        """

        data = bytes(map(int, arg.split()))
        if len(data) < 3:
            cli.log.error("Invalid args")
            return

        layer, rows, columns = data[:3]
        start_row = start_col = 0
        with suppress(Exception):
            start_row = data[3]
            start_col = data[4]

        # print(f'{data}')
        # print(f'{start_row=}')
        # print(f'{start_col=}')
        for row in range(start_row, start_row+rows):
            for column in range(start_col, start_col+columns):
                keycode = _xap_transaction(self.device, 0x04, 0x02, layer, row, column)
                keycode = int.from_bytes(keycode, 'little')
                print(f'{KEYCODE_MAP.get(keycode, "unknown")}[{keycode}]', end="  ")
            print()

    def do_exit(self, line):
        """Quit shell
        """
        return True

    def do_EOF(self, line):  # noqa: N802
        """Quit shell (ctrl+D)
        """
        return True

    def loop(self):
        """Wrapper for cmdloop that handles ctrl+C
        """
        try:
            self.cmdloop()
            print('')
        except KeyboardInterrupt:
            print('^C')
        return False


@cli.argument('-d', '--device', help='device to select - uses format <pid>:<vid>.')
@cli.argument('-l', '--list', arg_only=True, action='store_true', help='List available devices.')
@cli.argument('-i', '--interactive', arg_only=True, action='store_true', help='Start interactive shell.')
@cli.argument('action', nargs='*', default=['listen'], arg_only=True)
@cli.subcommand('Acquire debugging information from usb XAP devices.', hidden=False if cli.config.user.developer else True)
def xap(cli):
    """Acquire debugging information from XAP devices
    """
    # Lazy load to avoid issues
    global hid
    import hid

    if cli.args.list:
        return _list_devices()

    # Connect to first available device
    devices = _search()
    if not devices:
        cli.log.error("No devices found!")
        return False

    dev = devices[0]
    device = hid.Device(path=dev['path'])
    cli.log.info("Connected to %04X:%04X -- %s -- %s", dev['vendor_id'], dev['product_id'], dev['manufacturer_string'], dev['product_string'])

    # _xap_transaction(
    #     device,
    #     *range(28),
    #     ord('A')
    #     # long XAP payload test (2 HID reports)
    # )

    # sys.exit()

    # shell?
    if cli.args.interactive:
        XAPShell(device).loop()
        return True

    XAPShell(device).onecmd(" ".join(cli.args.action))
