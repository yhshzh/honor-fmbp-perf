#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""CLI client for honor-perfd on HONOR MagicBook Pro 14 (FMB-P)."""

import argparse
import socket
import sys

SOCKET = '/run/honor-perf/control'
COMMANDS = {
    'status': 'show current mode, power state, PL1/PL2 limits, and auto policy',
    'high': 'enable High Performance mode (requires AC and battery >= 20%)',
    'balanced': 'switch to Smart Mode (pauses auto-high until unplug/drop if enabled)',
    'toggle': 'toggle between Smart Mode and High Performance mode',
    'auto': 'clear manual override and re-evaluate auto-high policy',
}


def request(command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as client:
        client.settimeout(8)
        client.connect(SOCKET)
        client.sendall(command.encode('ascii'))
        response = client.recv(4096).decode()
    prefix, _, message = response.partition(' ')
    if prefix == 'ERR':
        raise ValueError(message)
    if prefix != 'OK' or not message:
        raise ValueError('invalid daemon response')
    return message


def main():
    parser = argparse.ArgumentParser(
        prog='honor-perf',
        description='Control performance mode on HONOR MagicBook Pro 14 (FMB-P)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='\n'.join(f'  {cmd:9} {help_text}' for cmd, help_text in COMMANDS.items()),
    )
    parser.add_argument('command', choices=COMMANDS, nargs='?', default='status')
    args = parser.parse_args()
    try:
        print(request(args.command))
    except (FileNotFoundError, ConnectionRefusedError):
        print('Cannot connect to honor-perf.service. Is it running?', file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f'honor-perf: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
