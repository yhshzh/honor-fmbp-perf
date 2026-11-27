# SPDX-License-Identifier: GPL-2.0-or-later
"""Self-contained offline unit tests for honor-perfd and honor-perf."""

import errno
import hashlib
import importlib.util
import lzma
import os
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


daemon = load('honor-perfd')
cli = load('honor-perf')


def pack_segment(kind, data):
    header = bytearray(148)
    struct.pack_into('<HH', header, 0, 0x1fe5, 148)
    header[108:140] = hashlib.sha256(data).digest()
    struct.pack_into('<I4s', header, 140, len(data), kind)
    return bytes(header) + data


def pack_apat_v2(rows):
    buf = bytearray()
    buf += struct.pack('<IQ', 4, 2)  # revision 2
    for row_id, name, device, domain, action, value in rows:
        buf += struct.pack('<IQ', 4, row_id)
        for text in (name, device):
            raw = text.encode('ascii') + b'\0'
            buf += struct.pack('<IQ', 8, len(raw)) + raw
        buf += struct.pack('<IQ', 4, domain)
        raw_action = action.encode('ascii') + b'\0'
        buf += struct.pack('<IQ', 8, len(raw_action)) + raw_action
        buf += struct.pack('<IQ', 4, value)
    return bytes(buf)


def build_synthetic_vault(overrides=None):
    values = dict(daemon.FALLBACK)
    if overrides:
        values.update(overrides)
    rows = [
        (idx, name, r'\_SB_.PC00.TCPU', 9, 'PL2PowerLimit', mw)
        for idx, (name, mw) in enumerate(values.items(), start=1)
    ]
    apat = pack_apat_v2(rows)
    key = daemon.APAT
    keys_payload = (
        struct.pack('<HII', 0xa0d8, 0, len(key))
        + key
        + struct.pack('<II', 7, len(apat))
        + apat
    )
    repo = pack_segment(b'KEYS', keys_payload)
    compressed = lzma.compress(repo, format=lzma.FORMAT_ALONE)
    return pack_segment(b'REPO', compressed)


class VaultTests(unittest.TestCase):
    def test_parse_225h_and_285h_vaults(self):
        v225 = daemon.parse_vault(build_synthetic_vault())
        self.assertEqual(
            [v225[k] for k in ('Normal', 'Perf', 'Normal_30C', 'Perf_30C')],
            [72000, 77000, 60000, 75000],
        )
        v285 = daemon.parse_vault(build_synthetic_vault({'Perf': 115000}))
        self.assertEqual(v285['Perf'], 115000)

    def test_truncated_vault_raises(self):
        blob = build_synthetic_vault()
        with self.assertRaises(ValueError):
            daemon.parse_vault(blob[:-1])

    def test_live_sysfs_vault_if_present(self):
        if daemon.VAULT.exists() and os.access(daemon.VAULT, os.R_OK):
            parsed = daemon.parse_vault(daemon.VAULT.read_bytes())
            self.assertGreaterEqual(parsed['Perf'], parsed['Normal'])

    def test_safety_precedes_ac_profiles_and_dc_limit(self):
        targets = daemon.parse_vault(build_synthetic_vault())
        oem = [2, 2, 1, 0, 1, 0, 2, 0, 0]
        for expected, index, next_value in (
            (14500, 6, 1), (14000, 4, 0), (30000, 6, 0),
            (12000, 0, 1), (40000, 0, 0),
        ):
            for ac in (0, 1):
                self.assertEqual(daemon.target(ac, oem, targets), expected)
            oem[index] = next_value
        self.assertEqual(daemon.target(0, oem, targets), 50000)
        self.assertEqual(daemon.target(1, oem, targets), 60000)
        oem[1] = 1
        self.assertEqual(daemon.target(1, oem, targets), 72000)
        oem[1:3] = [0, 2]
        self.assertEqual(daemon.target(1, oem, targets), 75000)
        oem[2] = 0
        self.assertEqual(daemon.target(1, oem, targets), targets['Default'])


class InterfaceTests(unittest.TestCase):
    def test_wmi_uses_second_buffer(self):
        arg, call = Mock(), Mock()
        call.read_text.return_value = '[{0x00,0x00,0x00,0x00},{0x00,0x01,0xff}]'
        with patch.object(daemon, 'WMI') as root:
            root.__truediv__.side_effect = {'arg': arg, 'call': call}.__getitem__
            self.assertEqual(daemon.wmi(0x0e04), [0, 1, 255])
            arg.write_text.assert_called_once_with('0xe04\n')
            call.read_text.return_value = '[{0x00},{0x01,0x00}]'
            with self.assertRaisesRegex(ValueError, 'rejected'):
                daemon.wmi(0x0e04)

    def test_kmsg_codes_and_overrun(self):
        records = [OSError(errno.EPIPE, 'overrun'), b'unrelated kernel record']
        for code in (0, 1, 5, 6, 7):
            records.append(f'4,42,1234,-;huawei-wmi: Unknown key pressed, code: 0x02a{code}'.encode())
        with patch.object(daemon.os, 'read', side_effect=[*records, BlockingIOError()]):
            self.assertEqual(list(daemon.read_events(123)), [0, 1, 5, 6])

    def test_dmi_gate(self):
        with patch.object(daemon, 'DMI') as root:
            vendor, product = Mock(), Mock()
            vendor.read_text.return_value = 'HONOR\n'
            product.read_text.return_value = 'FMB-P\n'
            root.__truediv__.side_effect = {'sys_vendor': vendor, 'product_name': product}.__getitem__
            daemon.check_dmi()
            product.read_text.return_value = 'OTHER\n'
            with self.assertRaisesRegex(RuntimeError, 'Unsupported machine'):
                daemon.check_dmi()

    def test_config_validation(self):
        with patch.dict(os.environ, {'HONOR_PERF_AUTO_HIGH_THRESHOLD': '75', 'HONOR_PERF_NOTIFY': '0'}, clear=True):
            cfg = daemon.load_config()
            self.assertEqual(cfg['auto_high_threshold'], 75)
            self.assertFalse(cfg['notify'])
            self.assertEqual(cfg['ac_balanced_epp'], '64')
        with patch.dict(os.environ, {'HONOR_PERF_AUTO_HIGH_THRESHOLD': '10'}, clear=True):
            with self.assertRaises(ValueError):
                daemon.load_config()

    def test_imok_only_writes_when_thermald_active(self):
        fake_imok = Mock()
        fake_imok.exists.return_value = True
        with patch.object(daemon, 'IMOK', fake_imok):
            with patch.object(daemon, 'thermald_active', return_value=False):
                daemon.ping_imok()
                fake_imok.write_text.assert_not_called()
            with patch.object(daemon, 'thermald_active', return_value=True):
                daemon.ping_imok()
                fake_imok.write_text.assert_called_once_with('0\n')

    def test_set_power_profile_dbus_and_fallback(self):
        with patch.object(daemon.subprocess, 'run') as run:
            daemon.set_power_profile('performance')
            run.assert_called_once()
            argv = run.call_args.args[0]
            self.assertEqual(argv[:4], [
                '/usr/bin/busctl', 'set-property',
                'org.freedesktop.UPower.PowerProfiles',
                '/org/freedesktop/UPower/PowerProfiles',
            ])
            self.assertEqual(argv[-3:], ['ActiveProfile', 's', 'performance'])

        with patch.object(
            daemon.subprocess,
            'run',
            side_effect=[FileNotFoundError('no busctl'), FileNotFoundError('no busctl'), None],
        ) as run:
            daemon.set_power_profile('balanced')
            self.assertEqual(run.call_count, 3)
            self.assertEqual(run.call_args.args[0], ['/usr/bin/powerprofilesctl', 'set', 'balanced'])

        with patch.object(daemon.subprocess, 'run', side_effect=FileNotFoundError('missing')):
            daemon.set_power_profile('balanced')


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.mode, self.ac, self.capacity = 0, 1, 90
        self.sleep_offset = 0
        self.oem = [0] * 9
        self.notify = Mock()
        self.profile = Mock()
        self.epp = Mock()
        self.imok = Mock()
        self.stub = Mock(side_effect=self.set_mode)
        pl2 = Mock()
        pl2.read_text.return_value = '50000000'
        pl2.write_text.side_effect = lambda text: setattr(pl2.read_text, 'return_value', text)
        pl1 = Mock()
        pl1.read_text.return_value = '65000000'
        self.pl2 = pl2
        self.pl1 = pl1
        self.enterContext(patch.multiple(
            daemon,
            snapshot=self.snapshot,
            wmi=self.stub,
            set_power_profile=self.profile,
            notify=self.notify,
            set_epp=self.epp,
            ping_imok=self.imok,
            PL2=pl2,
            PL1=pl1,
        ))
        self.enterContext(patch.object(daemon.Controller, 'offset', lambda _: self.sleep_offset))
        self.controller = daemon.Controller(daemon.FALLBACK, config={'auto_high_threshold': 75})
        self.update = self.controller.update

    def snapshot(self):
        oem = self.oem.copy()
        oem[1 + self.mode] = 1
        return self.mode, self.ac, self.capacity, tuple(oem)

    def set_mode(self, arg):
        self.assertIn(arg, (0x000f04, 0x010f04))
        self.mode = arg >> 16

    def test_manual_default_does_not_auto_switch(self):
        ctrl = daemon.Controller(daemon.FALLBACK)  # default threshold = 0
        ctrl.update()
        self.stub.assert_not_called()
        self.assertEqual(self.pl2.read_text(), '72000000')
        self.assertIn('manual', ctrl.update('status'))

    def test_boot_and_stub_echo(self):
        self.update()
        self.update(event=1)
        self.stub.assert_called_once_with(0x010f04)
        self.imok.assert_called_once()
        self.profile.assert_called_once_with('performance')
        self.notify.assert_called_once_with('Enabled High Performance (PL1 65W / PL2 77W)')

    def test_boot_already_high(self):
        self.mode = 1
        self.update()
        self.stub.assert_not_called()
        self.notify.assert_not_called()
        self.assertEqual(self.pl2.read_text(), '77000000')

    def test_manual_balanced_hysteresis_and_resume(self):
        self.update()
        self.mode = 0
        self.update(event=0)
        self.assertTrue(self.controller.manual_balanced_override)
        self.sleep_offset += 90
        for self.capacity in (90, 74, 75, 73, 75):
            self.update()
        self.assertEqual(self.mode, 0)
        self.capacity = 72
        self.update()
        self.assertFalse(self.controller.manual_balanced_override)
        self.capacity = 75
        self.update()
        self.assertEqual(self.stub.call_count, 2)
        self.assertEqual(self.mode, 1)

    def test_cli_balanced_echo_and_auto(self):
        self.update()
        self.update('balanced')
        self.update(event=0)
        self.assertEqual(self.notify.call_count, 2)
        self.assertIn('manual-override', self.update('status'))
        self.update('auto')
        self.assertEqual(self.mode, 1)
        self.update('toggle')
        self.assertEqual(self.mode, 0)
        self.assertTrue(self.controller.manual_balanced_override)

    def test_plug_and_unplug(self):
        self.update()
        self.ac, self.mode = 0, 0
        self.update(event=0)
        self.assertFalse(self.controller.manual_balanced_override)
        self.assertIn('PL2 50W', self.notify.call_args.args[0])
        self.ac = 1
        self.update()
        self.assertEqual(self.mode, 1)
        self.update('balanced')
        self.ac = 0
        self.update()
        self.ac = 1
        self.update()
        self.assertEqual(self.mode, 1)

    def test_ac_threshold_crossing(self):
        self.capacity = 74
        self.update()
        self.stub.assert_not_called()
        self.capacity = 75
        self.update()
        self.assertEqual(self.mode, 1)

    def test_resume_with_ec_reset(self):
        self.update()
        self.mode = 0
        self.sleep_offset += 90
        self.update()
        self.assertEqual(self.mode, 1)
        self.assertFalse(self.controller.manual_balanced_override)

    def test_fault_appears_without_a_mode_change(self):
        self.update()
        self.oem[6] = 2
        self.update()
        self.assertEqual(self.pl2.read_text(), '14500000')
        self.notify.assert_called_once()

    def test_fn_p_high_and_restrictions(self):
        self.capacity = 35
        self.update()
        self.mode = 1
        self.update(event=1)
        self.assertIn('PL2 77W', self.notify.call_args.args[0])
        self.ac, self.mode, self.capacity = 0, 0, 19
        self.update()
        for event, text in ((5, 'firmware restriction'), (6, 'battery >= 20%')):
            self.update(event=event)
            msg = self.notify.call_args.args[0]
            self.assertIn(text, msg)
            self.assertIn('Smart Mode, Battery 19%', msg)
        with self.assertRaisesRegex(ValueError, 'requires AC power'):
            self.update('high')
        self.stub.assert_not_called()

    def test_cli_socket_round_trip(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
            listener.bind('')
            listener.listen()
            self.enterContext(patch.object(cli, 'SOCKET', listener.getsockname()))
            self.enterContext(patch.object(daemon, 'active_uids', return_value={os.getuid()}))
            for command in ('high', 'status', 'balanced', 'toggle', 'auto'):
                thread = threading.Thread(target=daemon.serve_client, args=(listener, self.controller))
                thread.start()
                try:
                    self.assertIn('PL2', cli.request(command))
                finally:
                    thread.join(1)
                self.assertFalse(thread.is_alive())


if __name__ == '__main__':
    unittest.main(verbosity=2)
