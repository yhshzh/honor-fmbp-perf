# honor-fmbp-perf

Interim Linux userspace daemon and CLI for **High Performance Mode** (高能模式) on the **HONOR MagicBook Pro 14 (2025, `FMB-P`)**, while proper upstream support in `huawei-wmi` (`platform_profile`) and `thermald` (`imok` / PL2 AP Policy) is pending.

Full firmware/protocol analysis and `stress-ng` measurements are documented in [colorcube/Linux-on-Honor-Magicbook-14-Pro#27](https://github.com/colorcube/Linux-on-Honor-Magicbook-14-Pro/issues/27) and summarized in [`docs/hardware/performance.md`](https://github.com/colorcube/Linux-on-Honor-Magicbook-14-Pro/blob/main/docs/hardware/performance.md).

## Tested Hardware

- **Laptop:** HONOR MagicBook Pro 14 (2025), **Mainland China edition (`C233`)**
- **DMI:** `HONOR` / `FMB-P` / Version `M1050` / SKU `C233` / Board `FMB-P-PCB`
- **CPU:** Intel Core Ultra 5 225H (Arrow Lake-H)
- **BIOS:** `1.16` (`02/27/2026`)
- **OS:** Arch Linux, kernel `7.3.5-arch1-1`, `thermald 2.5.13`

> Other `FMB-P` variants (such as Global `C100` or Core Ultra 9 285H) are expected to work because PL2 targets are parsed dynamically from the machine's live `INTC1042` DataVault rather than hardcoded, but only the Mainland China 225H (`C233`) BIOS 1.16 unit has been tested on hardware so far.

## What It Does

Pure Python 3 standard library daemon (`honor-perfd`) + unprivileged CLI (`honor-perf`) + systemd unit, paired with `thermald --adaptive`:

1. **EC mode switching (`GTUB`/`STUB` via stock `huawei-wmi` debugfs):**
   - Uses `/sys/kernel/debug/huawei-wmi/{arg,call}` (`0x0E04` query, `0x000F04` Smart Mode, `0x010F04` High Performance) — no out-of-tree kernel module required.
   - Verifies both `GTUB` and Intel DPTF `odvp1`/`odvp2` after switching.
2. **SKU-aware PL2 sync from live `INTC1042` DataVault:**
   - `thermald --adaptive` applies PL1, TCC offset, and ITMT from the main APAT, but ignores the separate `PL2 AP Policy` (`f27632da-005b-45b7-8dc7-206229d42705`), leaving `intel-rapl-mmio:0` PL2 stuck at 50 W.
   - `honor-perfd` validates and parses `/sys/devices/platform/INTC1042:00/data_vault` at startup (extracting e.g. `72 W / 77 W` on 225H or `72 W / 115 W` on the alternate 285H vault), enforces firmware fault limits (`Fan_Fail_*`, `Inlet_Fail`, etc.) first, caps DC at `50 W`, and syncs `/sys/class/powercap/intel-rapl-mmio:0/constraint_1_power_limit_uw`.
3. **Gated Intel DTT `IMOK` keep-alive:**
   - Writes `0` to `/sys/bus/platform/devices/INTC1042:00/imok` periodically **only while `thermald.service` is active**, lifting the EC's 50 W failsafe clamp while letting the EC reclaim failsafe control if `thermald` stops.
4. **AC Balanced EPP fix (`64`):**
   - `power-profiles-daemon`'s `balanced` profile sets `balance_performance` (EPP `128`), which kept the 225H around ~25 W under load. `honor-perfd` writes numeric `64` on AC Smart Mode (matching Honor's 225H AC policy), `performance` on High Performance, and `balance_performance` on battery.
5. **`Fn+P` support, desktop notifications, and optional AC auto-switching:**
   - Detects physical `Fn+P` switches (via `/dev/kmsg` on stock `huawei-wmi` plus 2 s `GTUB`/`ODVP` polling fallback) and sends replacing notifications via `notify-send` to the active local seat user.
   - Optional automatic High Performance on AC above a configurable battery percentage (disabled by default; respects manual `Fn+P` / CLI overrides).
   - DMI-gated to `HONOR` / `FMB-P` and peer-credential checked on `/run/honor-perf/control` (`status` for anyone, mode changes for `root` or active local seat user).

## Prerequisites

- Stock `huawei_wmi` kernel module and mounted `/sys/kernel/debug` (`debugfs`)
- `thermald` running with `--adaptive` (enabled automatically by Arch's default `thermald.service`; check your distro's unit file if using Fedora/Ubuntu)
- Python 3 (standard library only)
- Optional: `power-profiles-daemon` (`powerprofilesctl`), `libnotify` (`notify-send`)

## Install & Uninstall

```bash
git clone https://github.com/yhshzh/honor-fmbp-perf.git
cd honor-fmbp-perf
sudo ./install.sh
```

Uninstall (leaves `/etc/default/honor-perf` intact if you edited it):

```bash
sudo ./install.sh --uninstall
```

## Configuration

Edit `/etc/default/honor-perf` and run `sudo systemctl restart honor-perf.service`:

```ini
# Auto-enable High Performance on AC when battery >= threshold (20..100).
# 0 = disabled (manual Fn+P / CLI only, default).
HONOR_PERF_AUTO_HIGH_THRESHOLD=0

# Desktop notifications via notify-send (1=on, 0=off).
HONOR_PERF_NOTIFY=1

# Sync power-profiles-daemon balanced/performance (1=on, 0=off).
HONOR_PERF_SYNC_PPD=1

# Numeric CPU EPP on AC Smart Mode (empty = do not override).
HONOR_PERF_AC_BALANCED_EPP=64

# IMOK keep-alive interval in seconds while thermald.service is active (0 = off).
HONOR_PERF_IMOK_INTERVAL=4
```

When `HONOR_PERF_AUTO_HIGH_THRESHOLD` is set (e.g. `75`), High Performance turns on automatically at boot, AC plug-in, crossing upward into `>= 75%` (with 2% hysteresis), or resume if the EC reset to Smart Mode. Manually switching back to Smart Mode via `Fn+P` or `honor-perf balanced` pauses auto-switching until AC is unplugged/replugged, battery drops below `threshold - 2`, or you run `honor-perf auto`.

## CLI Usage

No `sudo` required from an active local desktop session:

```bash
honor-perf status    # show mode, AC/battery, PL1/PL2, and policy
honor-perf high      # switch to High Performance (AC + battery >= 20%)
honor-perf balanced  # switch to Smart Mode
honor-perf toggle    # toggle between Smart Mode and High Performance
honor-perf auto      # clear manual override and re-evaluate auto-high policy
```

## Known Caveats

- **Patched `huawei-wmi` keymap (`fixes/huawei-wmi-dkms`):** If `0x02a0`/`0x02a1`/`0x02a6` are already mapped in your kernel module, the kernel stops logging `Unknown key pressed` to `/dev/kmsg`. Mode changes, PL2/EPP sync, and mode-change notifications still work via the 2-second `GTUB`/`ODVP` poll, but instant `0x02a6` rejection notices (e.g. pressing `Fn+P` on battery) rely on unmapped kmsg events.
- **`IMOK` polling vs uevent:** Currently uses simple 4-second polling gated on `thermald.service` rather than listening for `thermal` subsystem `EVENT=8` (`THERMAL_EVENT_KEEP_ALIVE`) uevents. Upstream `thermald` should handle `EVENT=8` directly.
- **Scope:** Designed as a clean interim workaround until `platform_profile` lands in `huawei-wmi` and `imok` + PL2 AP Policy land in `thermald`.

## Tests

```bash
python3 test_honor_perf.py
```

## License

GPL-2.0-or-later (see [LICENSE](LICENSE)).
