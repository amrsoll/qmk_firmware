"""Interactions with compatible XAP devices
"""
import cmd
import json
import random
import gzip
from platform import platform
import sys

from milc import cli

KEYCODE_MAP = {
    # TODO: this should be data driven...
    0x04: 'KC_A',
    0x05: 'KC_B',
    0x29: 'KC_ESCAPE',
    0xF9: 'KC_MS_WH_UP',
}

# should create a config file or read from XAP specification
HID_REPORT_LENGTH  = 64 # size of each HID report
TOKEN_LENGTH       = 2  # bytes on each XAP transaction used for the token (transaction id)
PAYLOAD_LENGTH     = 1  # bytes on each XAP transaction used for specifying the payload length (also in bytes)
MAX_PAYLOAD_LENGTH = 128 # constrain in the specification to reduce RAM usage
TIMEOUT            = 1000 # timeout (in ms) we wait for an answer


def _is_xap_usage(x):
    return x['usage_page'] == 0xFF51 and x['usage'] == 0x0058


def _is_filtered_device(x):
    name = "%04x:%04x" % (x['vendor_id'], x['product_id'])
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


def log_xap_transaction(transaction, sent=True):
    """Logs a XAP transaction for debugging

    Args:
        sent: Whether this transaction is in our outbound
    """

    mode = 'Sending' if sent else 'Received'

    # bytes 0&1 => token
    formatted = f'Token: {hex(int.from_bytes(transaction[:2], "little"))} | '

    # received bytes 2/3=> Flags / Payload length
    if not sent:
        formatted += f'Flags: {format(transaction[2], "b").zfill(8)} | '
        offset = 3
    # sent byte 2 => Payload length
    else:
        offset = 2

    formatted += f'Payload Length: {hex(transaction[offset])} | '

    # payload
    formatted += ' '.join(str(hex(i)) for i in transaction[offset+1:])

    print(mode, "XAP ||", formatted)
    cli.log.debug('%s XAP transaction:\n%s', mode, formatted)


def _hid_transaction(device, report):
    """Send an HID report and return its answer

    Returns:
        hid_report gotten from the keyboard
    """

    device.write(bytes(report))
    hid_response = device.read(HID_REPORT_LENGTH, TIMEOUT)

    # disabled because something is wrong with data alignment

    # validate tok sent == resp
    # if report[:2] != hid_response[:2]:
    #     cli.log.critical("Token received doesn't match the sent one")
    #     sys.exit()
    #     # TODO implement logic upon received a "fail" message, just quits for now


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
    header = bytearray(token)
    header.extend(payload_length.to_bytes(PAYLOAD_LENGTH, 'little'))
    header_size = len(header)

    log_xap_transaction(header + payload)

    # initialize header-only report
    sent_report_size = header_size
    sent_report = header

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
            sent_report = header
            sent_report_size = header_size

    # if there's some data remaining, send it
    if sent_report_size > header_size:
        # pad with trailing zeros
        sent_report.extend([0x00] * (HID_REPORT_LENGTH-sent_report_size))
        received_report = _hid_transaction(device, sent_report)
        received_transaction = _merge_hid_reports(received_transaction, received_report)

    log_xap_transaction(received_transaction, sent=False)

    # check if the transaction ended successfully
    if int(received_transaction[2]) != 0x01:
        return None

    # return response payload
    received_transaction_len = int(received_transaction[3])
    return received_transaction[4:4 + received_transaction_len]


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
        cli.log.info("  %04x:%04x %s %s [API:%s] %s", dev['vendor_id'], dev['product_id'], dev['manufacturer_string'], dev['product_string'], data['xap'], data['secure'])

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
        while 1:
            array_alpha = device.read(64, 100)
            if str(b"\xFF\xFF") == str(array_alpha[:2]):
                if array_alpha[2] == 1:
                    cli.log.info("  Broadcast: Secure[%02x]", array_alpha[4])
                else:
                    cli.log.info("  Broadcast: type[%02x] data:[%02x]", array_alpha[2], array_alpha[4])
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

        keycode = _xap_transaction(self.device, 0x04, 0x02, data)
        keycode = int.from_bytes(keycode, 'little')
        print(f'keycode:{KEYCODE_MAP.get(keycode, "unknown")}[{keycode}]') # according to guidelines we should not use f-strings :(

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
    cli.log.info("Connected to %04x:%04x -- %s -- %s", dev['vendor_id'], dev['product_id'], dev['manufacturer_string'], dev['product_string'])

    _xap_transaction(
        device,
        0x00, # it works with another offset
        ord('A'))

    sys.exit()

    # shell?
    if cli.args.interactive:
        XAPShell(device).loop()
        return True

    XAPShell(device).onecmd(" ".join(cli.args.action))
