#!/usr/bin/python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""HONOR MagicBook Pro 14 (FMB-P) userspace performance mode daemon."""

import errno
import hashlib
import logging
import lzma
import os
import pwd
import re
import select
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

DMI = Path('/sys/class/dmi/id')
WMI = Path('/sys/kernel/debug/huawei-wmi')
VAULT = Path('/sys/devices/platform/INTC1042:00/data_vault')
DPTF = Path('/sys/bus/acpi/devices/INTC1042:00/physical_node')
IMOK = Path('/sys/bus/platform/devices/INTC1042:00/imok')
CPUFREQ = Path('/sys/devices/system/cpu/cpufreq')
POWER = Path('/sys/class/power_supply')
RAPL = Path('/sys/class/powercap/intel-rapl-mmio:0')
PL1, PL2 = (RAPL / f'constraint_{i}_power_limit_uw' for i in (0, 1))
SOCKET = '/run/honor-perf/control'
APAT = b'/shared/export/f27632da-005b-45b7-8dc7-206229d42705/apat\0'
EVENT = re.compile(rb'Unknown key pressed, code: 0x02a([0156])\b', re.I)
MODES = ('Smart Mode', 'High Performance')
TITLE = 'Honor Performance Mode'

# BIOS 1.16 / Core Ultra 5 225H fallback PL2 limits (mW).
# Fault limits are preserved even if the firmware DataVault cannot be read.
FALLBACK = dict(
    Normal=72000, Normal_30C=60000, Perf=77000, Perf_30C=75000,
    Default=72000, MFG=45000, Fan_Fail_double=14500, Inlet_Fail=14000,
    Fan_Fail_single=30000, SHOP_FULL=12000, SHOP=40000,
)


def env_int(name, default):
    raw = os.environ.get(name, '').strip()
    return int(raw) if raw else default


def env_bool(name, default=True):
    raw = os.environ.get(name, '').strip().lower()
    if not raw:
        return default
    return raw not in ('0', 'false', 'no', 'off')


def load_config():
    threshold = env_int('HONOR_PERF_AUTO_HIGH_THRESHOLD', 0)
    if threshold and not (20 <= threshold <= 100):
        raise ValueError('HONOR_PERF_AUTO_HIGH_THRESHOLD must be 0 (off) or 20..100')
    imok_interval = max(0, env_int('HONOR_PERF_IMOK_INTERVAL', 4))
    ac_balanced_epp = os.environ.get('HONOR_PERF_AC_BALANCED_EPP', '64').strip()
    return dict(
        auto_high_threshold=threshold,
        notify=env_bool('HONOR_PERF_NOTIFY', True),
        sync_ppd=env_bool('HONOR_PERF_SYNC_PPD', True),
        ac_balanced_epp=ac_balanced_epp,
        imok_interval=imok_interval,
        ignore_dmi=env_bool('HONOR_PERF_IGNORE_DMI', False),
    )


def check_dmi():
    vendor = (DMI / 'sys_vendor').read_text().strip()
    product = (DMI / 'product_name').read_text().strip()
    if vendor != 'HONOR' or product != 'FMB-P':
        raise RuntimeError(f'Unsupported machine: {vendor!r} / {product!r} (expected HONOR / FMB-P)')


def payload(blob, kind):
    magic, start = struct.unpack_from('<HH', blob)
    size, tag = struct.unpack_from('<I4s', blob, 140)
    data = blob[start:start + size]
    if (magic != 0x1fe5 or start < 148 or tag != kind or len(data) != size
            or hashlib.sha256(data).digest() != blob[108:140]):
        raise ValueError('invalid DataVault segment')
    return data


def parse_vault(blob):
    repo = lzma.decompress(payload(blob, b'REPO'), format=lzma.FORMAT_ALONE)
    keys = payload(repo, b'KEYS')
    pos = 0
    while pos < len(keys):
        sig, _, length = struct.unpack_from('<HII', keys, pos)
        pos += 10
        key = keys[pos:pos + length]
        pos += length
        typ, size = struct.unpack_from('<II', keys, pos)
        pos += 8
        if sig != 0xa0d8 or size > len(keys) - pos:
            raise ValueError('invalid DataVault key')
        if key == APAT and typ == 7:
            break
        pos += size
    else:
        raise ValueError('missing PL2 APAT')

    fields = []
    end = pos + size
    while pos < end:
        typ, value = struct.unpack_from('<IQ', keys, pos)
        pos += 12
        if typ == 8:
            length = value
            value = keys[pos:pos + length].rstrip(b'\0').decode('ascii')
            pos += length
        elif typ != 4:
            raise ValueError('unexpected APAT field type')
        fields.append(value)
    if pos != end or fields[:1] != [2] or len(fields) % 6 != 1:
        raise ValueError('invalid APAT v2 rows')
    targets = {}
    for i in range(1, len(fields), 6):
        _, name, device, domain, action, value = fields[i:i + 6]
        if (device, domain, action) == (r'\_SB_.PC00.TCPU', 9, 'PL2PowerLimit'):
            targets[name] = int(value)
    if not FALLBACK.keys() <= targets.keys() or min(targets.values()) <= 0:
        raise ValueError('incomplete PL2 policy')
    return targets


def target(ac, oem, targets):
    for index, value, name in (
        (6, 2, 'Fan_Fail_double'),
        (4, 1, 'Inlet_Fail'),
        (6, 1, 'Fan_Fail_single'),
        (0, 2, 'SHOP_FULL'),
        (0, 1, 'SHOP'),
        (4, 2, 'MFG'),
    ):
        if oem[index] == value:
            return targets[name]
    if not ac:
        return 50000
    for index, name in ((1, 'Normal'), (2, 'Perf')):
        if oem[index] in (1, 2):
            return targets[name + ('_30C' if oem[index] == 2 else '')]
    return targets['Default']


def number(path):
    return int(path.read_text().strip())


def wmi(arg):
    (WMI / 'arg').write_text(f'{arg:#x}\n')
    groups = re.findall(r'\{([^{}]*)\}', (WMI / 'call').read_text())
    if len(groups) != 2:
        raise ValueError('unexpected huawei-wmi reply')
    reply = [int(b.strip(), 16) for b in groups[1].split(',') if b.strip()]
    if not reply or reply[0] != 0:
        raise ValueError(f'huawei-wmi rejected {arg:#x}')
    return reply


def snapshot():
    reply = wmi(0x0e04)
    if reply[1:2] not in ([0], [1]):
        raise ValueError('unknown GTUB mode')
    return (
        reply[1],
        number(POWER / 'ADP1/online'),
        number(POWER / 'BAT0/capacity'),
        tuple(number(DPTF / f'odvp{i}') for i in range(9)),
    )


def confirmed(mode, ac, oem):
    # Ordinary AC profiles have mutually exclusive Normal/Perf ODVP selectors.
    exceptional = oem[6] in (1, 2) or oem[4] in (1, 2) or oem[0] in (1, 2)
    return not ac or exceptional or (oem[1 + mode] in (1, 2) and oem[2 - mode] == 0)


def active_uids():
    uids = set()
    for seat in Path('/run/systemd/seats').glob('*'):
        try:
            match = re.search(r'^ACTIVE_UID=(\d+)$', seat.read_text(), re.M)
        except FileNotFoundError:
            continue
        if match:
            uids.add(int(match[1]))
    return uids


def optional(argv, **kwargs):
    try:
        subprocess.run(argv, check=True, timeout=2, **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        logging.info('%s', exc)


def notify(body):
    seats = active_uids()
    for bus in Path('/run/user').glob('[0-9]*/bus'):
        uid = int(bus.parent.name)
        if uid not in seats:
            continue
        user = pwd.getpwuid(uid)
        env = dict(
            HOME=user.pw_dir,
            LANG='C.UTF-8',
            XDG_RUNTIME_DIR=str(bus.parent),
            DBUS_SESSION_BUS_ADDRESS=f'unix:path={bus}',
        )
        optional(
            [
                '/usr/bin/notify-send',
                '-a', TITLE,
                '-h', 'string:x-canonical-private-synchronous:honor-perf',
                TITLE,
                body,
            ],
            user=uid,
            group=user.pw_gid,
            extra_groups=[],
            env=env,
            cwd='/',
        )


def set_epp(mode, ac, ac_balanced_epp='64'):
    if mode:
        value = 'performance'
    elif ac:
        if not ac_balanced_epp:
            return
        value = ac_balanced_epp
    else:
        value = 'balance_performance'
    for path in CPUFREQ.glob('policy*/energy_performance_preference'):
        try:
            path.write_text(value + '\n')
        except OSError:
            pass


def thermald_active():
    try:
        res = subprocess.run(
            ['/usr/bin/systemctl', 'is-active', '--quiet', 'thermald.service'],
            timeout=1,
        )
        return res.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def ping_imok():
    if IMOK.exists() and thermald_active():
        try:
            IMOK.write_text('0\n')
        except OSError as exc:
            logging.info('imok: %s', exc)


def limits():
    return f'PL1 {number(PL1) / 1e6:g}W / PL2 {number(PL2) / 1e6:g}W'


def reason(mode, ac, capacity, restricted=False):
    detail = 'firmware restriction' if restricted else 'requires AC power and battery >= 20%'
    supply = 'AC' if ac else 'Battery'
    return f'Cannot enable High Performance ({detail}); currently {MODES[mode]}, {supply} {capacity}%'


class Controller:
    def __init__(self, targets, config=None):
        self.targets = targets
        self.config = dict(
            auto_high_threshold=0,
            notify=True,
            sync_ppd=True,
            ac_balanced_epp='64',
            imok_interval=4,
            ignore_dmi=False,
        )
        if config:
            self.config.update(config)
        self.mode = None
        self.ac = None
        self.armed = True
        self.manual_balanced_override = False
        self.echo = (None, 0)
        self.failure_echo_until = 0
        self.sleep_offset = self.offset()
        self.last_pl1 = None
        self.last_epp_key = None
        self.next_imok = 0

    @staticmethod
    def offset():
        return time.clock_gettime(time.CLOCK_BOOTTIME) - time.monotonic()

    def _notify(self, body):
        if self.config['notify']:
            notify(body)

    def observe(self, state, announce=True):
        mode, ac, _, oem = state
        changed = self.mode != mode and confirmed(mode, ac, oem)
        if changed and self.config['sync_ppd']:
            optional(['/usr/bin/powerprofilesctl', 'set', ('balanced', 'performance')[mode]])
        if changed or self.last_epp_key != (mode, ac):
            set_epp(mode, ac, self.config['ac_balanced_epp'])
            self.last_epp_key = (mode, ac)
        wanted = target(ac, oem, self.targets) * 1000
        if number(PL2) != wanted:
            PL2.write_text(str(wanted))
        if changed and self.last_pl1 is not None:
            for _ in range(16):
                if number(PL1) != self.last_pl1:
                    break
                time.sleep(0.05)
        if changed and announce:
            verb = 'Enabled' if mode else 'Switched to'
            self._notify(f'{verb} {MODES[mode]} ({limits()})')
        if changed:
            self.mode = mode
            self.last_pl1 = number(PL1)
        elif self.last_pl1 is None:
            self.last_pl1 = number(PL1)

    def switch(self, state, wanted):
        mode, ac, capacity, _ = state
        if wanted and (not ac or capacity < 20):
            message = reason(mode, ac, capacity)
            self._notify(message)
            raise ValueError(message)
        if mode != wanted:
            wmi(0x0f04 | (wanted << 16))
            self.echo = (wanted, time.monotonic() + 2)
            for _ in range(12):
                state = snapshot()
                mode, ac, capacity, oem = state
                if mode == wanted and confirmed(mode, ac, oem):
                    break
                time.sleep(0.05)
            else:
                if mode != wanted and wanted:
                    message = reason(mode, ac, capacity, restricted=True)
                else:
                    message = 'Timed out waiting for firmware mode and ODVP sync'
                self._notify(message)
                self.failure_echo_until = time.monotonic() + 1
                raise ValueError(message)
        self.observe(state)
        return state

    def update(self, command=None, event=None):
        if command not in (None, 'status', 'auto', 'toggle', 'high', 'balanced'):
            raise ValueError('unknown command')
        now = time.monotonic()
        interval = self.config['imok_interval']
        if interval > 0 and now >= self.next_imok:
            ping_imok()
            self.next_imok = now + interval
        state = snapshot()
        if event in (0, 1):
            for _ in range(8):
                mode, ac, _, oem = state
                if confirmed(mode, ac, oem):
                    break
                time.sleep(0.05)
                state = snapshot()
        mode, ac, capacity, oem = state
        offset = self.offset()
        resumed = offset - self.sleep_offset > 10
        self.sleep_offset = offset

        threshold = self.config['auto_high_threshold']
        auto_enabled = threshold > 0
        eligible = auto_enabled and ac and capacity >= threshold
        plugged = self.ac == 0 and ac
        self.ac = ac

        if not auto_enabled or not ac or capacity < max(0, threshold - 2):
            self.armed = True
            self.manual_balanced_override = False
        if resumed or command == 'auto':
            self.armed = True
        if command == 'auto':
            self.manual_balanced_override = False

        if event in (5, 6):
            if time.monotonic() > self.failure_echo_until:
                self._notify(reason(mode, ac, capacity, restricted=event == 5))
        changed = self.mode is not None and mode != self.mode
        echo_mode, deadline = self.echo
        own_echo = event == echo_mode and time.monotonic() <= deadline
        if own_echo:
            self.echo = (None, 0)
        key = event == mode and not own_echo
        if (key or changed) and not (resumed or plugged or command == 'auto'):
            if mode:
                self.manual_balanced_override = False
            elif eligible:
                self.manual_balanced_override = True

        if command in ('high', 'balanced', 'toggle'):
            wanted = 1 - mode if command == 'toggle' else int(command == 'high')
            if not wanted and eligible:
                self.manual_balanced_override = True
            state = self.switch(state, wanted)
            if wanted:
                self.manual_balanced_override = False
            if eligible:
                self.armed = False
        elif eligible and self.armed and not mode and not self.manual_balanced_override:
            try:
                state = self.switch(state, 1)
            except ValueError:
                self.armed = False  # Wait for a new trigger after firmware rejection.
                raise
            self.armed = False
        else:
            self.observe(state, announce=changed)
            if eligible:
                self.armed = False

        if command:
            mode, ac, capacity, _ = state
            if not auto_enabled:
                policy = 'manual'
            elif self.manual_balanced_override:
                policy = 'manual-override (Smart)'
            else:
                policy = f'auto (>={threshold}% AC)'
            supply = 'AC' if ac else 'Battery'
            return f'{MODES[mode]} · {supply} {capacity}% · {limits()} · {policy}'


def read_events(fd):
    while True:
        try:
            record = os.read(fd, 8192)
        except BlockingIOError:
            return
        except OSError as exc:
            if exc.errno == errno.EPIPE:  # Ring buffer overrun; next read resumes.
                continue
            raise
        match = EVENT.search(record)
        if match:
            yield int(match[1])


def serve_client(listener, controller):
    client, _ = listener.accept()
    with client:
        client.settimeout(0.3)
        try:
            command = client.recv(64).decode('ascii')
            _, uid, _ = struct.unpack(
                '3i', client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if command != 'status' and uid and uid not in active_uids():
                raise ValueError('changing mode requires root or an active local session')
            result = 'OK ' + controller.update(command)
        except (ValueError, OSError) as exc:
            result = 'ERR ' + str(exc)
        try:
            client.sendall(result.encode())
        except OSError:
            pass


def main():
    logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
    config = load_config()
    if not config['ignore_dmi']:
        try:
            check_dmi()
        except (OSError, RuntimeError) as exc:
            logging.error('%s', exc)
            return 1
    try:
        targets = parse_vault(VAULT.read_bytes())
    except (OSError, ValueError, struct.error, lzma.LZMAError) as exc:
        logging.warning('DataVault: %s; using BIOS 1.16 225H fallback', exc)
        targets = FALLBACK
    controller = Controller(targets, config=config)
    fd = os.open('/dev/kmsg', os.O_RDONLY | os.O_NONBLOCK)
    os.lseek(fd, 0, os.SEEK_END)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        Path(SOCKET).unlink(missing_ok=True)
        listener.bind(SOCKET)
        os.chmod(SOCKET, 0o666)
        listener.listen(8)
        due = time.monotonic()
        while True:
            ready, _, _ = select.select([fd, listener], [], [], max(0, due - time.monotonic()))
            try:
                if fd in ready:
                    for event in read_events(fd):
                        controller.update(event=event)
                if time.monotonic() >= due:
                    due = time.monotonic() + 2
                    controller.update()
                if listener in ready:
                    serve_client(listener, controller)
            except (ValueError, OSError) as exc:
                logging.warning('%s', exc)


if __name__ == '__main__':
    sys.exit(main())
