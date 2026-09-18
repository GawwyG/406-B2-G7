#!/usr/bin/env python3
"""
Diagnostic for the "one-shot success vs. total failure" pattern seen in
run_experiments.py: some trials kill the connection on the attacker's
very first forged RST, others fire 600+ times across the whole download
and never land a single hit -- never something in between. This script
captures a live packet trace on h1 (the victim) *during* each trial, so
we can directly see, for a failing trial, exactly how the timing of each
forged RST compares to the real server segment it was racing against.

Key trick: our forged RSTs claim src=10.0.2.10 (the real server's IP) --
that's the whole point of the spoof -- so a capture on h1 filtered to
"src host 10.0.2.10" shows BOTH the real data segments AND our forged
RSTs, interleaved, in one single trace. They're trivially distinguishable
by TCP flags: a bare "Flags [R]" with no data is always one of ours (the
real server never sends a bare RST during normal operation); anything
else (data segments, plain ACKs) is real server traffic. No separate
correlation against the attacker's own log is even needed, though we keep
it too for cross-checking.

Run with (from anywhere, needs root):
    sudo python3 experiments/diagnose_race.py --trials 6

Stops early once it has captured at least one successful AND one failed
trial (or after --trials attempts, whichever comes first), then prints a
merged, millisecond-resolution timeline for the last failed trial
captured, and tells you where to find the raw traces for the rest.
"""

import argparse
import os
import re
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOPOLOGY_DIR = os.path.join(PROJECT_ROOT, "topology")
ATTACK_DIR = os.path.join(PROJECT_ROOT, "attack")
STREAMING_DIR = os.path.join(PROJECT_ROOT, "streaming")
EXPERIMENTS_DIR = os.path.join(PROJECT_ROOT, "experiments")
LOGS_DIR = os.path.join(EXPERIMENTS_DIR, "logs")

sys.path.insert(0, TOPOLOGY_DIR)
sys.path.insert(0, EXPERIMENTS_DIR)

from mininet.log import setLogLevel  # noqa: E402
from topo import build  # noqa: E402
from run_experiments import run_trial, run_bash, wait_for_video, estimate_transfer_seconds  # noqa: E402

TCPDUMP_LINE_RE = re.compile(
    r"^(\d+\.\d+) IP (\S+) > (\S+): Flags \[([^\]]+)\], seq (\d+)(?::(\d+))?.*length (\d+)"
)


class Args:
    """Minimal stand-in for the argparse.Namespace run_trial() expects."""
    def __init__(self, wan_bw, wan_delay_r1, wan_delay_h3, head_start, label=""):
        self.wan_bw = wan_bw
        self.wan_delay_r1 = wan_delay_r1
        self.wan_delay_h3 = wan_delay_h3
        self.head_start = head_start
        self.label = label


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--trials", type=int, default=6, help="max trials to attempt (default: 6)")
    p.add_argument("--wan-bw", type=float, default=1)
    p.add_argument("--wan-delay-r1", default="20ms")
    p.add_argument("--wan-delay-h3", default="5ms")
    p.add_argument("--head-start-fraction", type=float, default=0.15,
                    help="fraction of the estimated total transfer time to let the download run "
                         "before the attacker joins (default: 0.15) -- see run_experiments.py's "
                         "--head-start-fraction help for why this is a fraction, not fixed seconds")
    return p.parse_args()


def analyze_capture(pcap_log_path, attacker_log_path):
    """Merge the raw tcpdump trace with the attacker's own log into one
    human-readable, time-ordered timeline."""
    events = []
    with open(pcap_log_path) as f:
        for line in f:
            m = TCPDUMP_LINE_RE.match(line)
            if not m:
                continue
            ts, src, dst, flags, seq, seq_end, length = m.groups()
            is_forged = flags == "R"
            label = "FORGED RST (h2)" if is_forged else f"real server data ({flags})"
            events.append((float(ts), f"{label}: seq={seq} len={length} ({src} -> {dst})"))

    with open(attacker_log_path) as f:
        for line in f:
            if line.startswith("[attack] #"):
                # attacker.py's own timestamp is wall-clock HH:MM:SS.mmm,
                # not directly comparable to tcpdump's epoch time unless
                # we know the date -- skip merging these in directly, the
                # tcpdump trace alone already shows every forged RST it
                # actually put on the wire (that's what matters for the
                # race), the attacker log is just a cross-check that the
                # counts match.
                pass

    events.sort(key=lambda e: e[0])
    if not events:
        return "  (no matching packets captured -- check the capture filter/timing)"

    t0 = events[0][0]
    lines = []
    for ts, desc in events:
        lines.append(f"  t+{ts - t0:7.3f}s  {desc}")
    return "\n".join(lines)


def run_one_diagnostic_trial(net, trial_idx, expected_bytes, args):
    h1 = net.get("h1")
    pcap_log = os.path.join(LOGS_DIR, f"diag_{trial_idx}_h1_capture.log")
    open(pcap_log, "w").close()

    tcpdump_pid = h1.cmd(
        f'tcpdump -i h1-eth0 -nn -tt -K "src host 10.0.2.10 and tcp port 8000" '
        f'> "{pcap_log}" 2>&1 & echo $!'
    ).strip().splitlines()[-1]
    time.sleep(0.3)  # let tcpdump attach before the trial starts

    row = run_trial(net, trial_idx, "diag", expected_bytes, args)

    time.sleep(0.3)
    h1.cmd(f"kill {tcpdump_pid} 2>/dev/null")
    time.sleep(0.2)

    return row, pcap_log


def main():
    args_ns = parse_args()
    expected_bytes = wait_for_video(os.path.join(STREAMING_DIR, "video.mp4"))
    est_transfer_s = estimate_transfer_seconds(expected_bytes, args_ns.wan_bw)
    head_start = est_transfer_s * args_ns.head_start_fraction
    print(f"*** Estimated transfer time at {args_ns.wan_bw} Mbit/s: {est_transfer_s:.2f}s -- "
          f"head start: {head_start:.2f}s ({args_ns.head_start_fraction:.0%})")
    args = Args(args_ns.wan_bw, args_ns.wan_delay_r1, args_ns.wan_delay_h3, head_start)

    os.makedirs(LOGS_DIR, exist_ok=True)
    setLogLevel("warning")
    net = build(wan_bw=args.wan_bw, wan_delay_r1=args.wan_delay_r1, wan_delay_h3=args.wan_delay_h3)
    h3 = net.get("h3")

    try:
        print("*** Starting streaming server on h3")
        h3.cmd(f'cd "{STREAMING_DIR}" && python3 server.py > "{os.path.join(LOGS_DIR, "server.log")}" 2>&1 &')
        time.sleep(1.5)

        print("*** Enabling attacker visibility (OVS mirror)")
        run_bash(os.path.join(ATTACK_DIR, "mirror_enable.sh"))
        run_bash(os.path.join(TOPOLOGY_DIR, "defense_disable.sh"))  # ensure clean, undefended baseline

        have_success = False
        have_failure = False
        last_failed_trial = None

        for i in range(1, args_ns.trials + 1):
            if have_success and have_failure:
                break
            print(f"*** diagnostic trial {i}/{args_ns.trials}")
            row, pcap_log = run_one_diagnostic_trial(net, i, expected_bytes, args)
            outcome = "SUCCESS (attack killed it)" if row["success"] else "FAILURE (full download survived)"
            print(f"    {outcome} -- downloaded={row['downloaded_bytes']}/{expected_bytes} "
                  f"attempts={row['attempts_to_kill']}  capture={pcap_log}")
            if row["success"]:
                have_success = True
            else:
                have_failure = True
                last_failed_trial = (i, pcap_log)
            time.sleep(0.5)

        if last_failed_trial:
            i, pcap_log = last_failed_trial
            attacker_log = os.path.join(LOGS_DIR, f"attacker_diag_{i}.log")
            print(f"\n=== Timeline for failed trial #{i} (from {pcap_log}) ===")
            print(analyze_capture(pcap_log, attacker_log))
        else:
            print("\n(no failed trial captured within --trials attempts -- try increasing --trials)")

        print(f"\nAll raw captures are under {LOGS_DIR}/diag_*_h1_capture.log -- "
              f"inspect any of them directly (they're plain tcpdump text output).")

    finally:
        print("*** Tearing down")
        run_bash(os.path.join(TOPOLOGY_DIR, "defense_disable.sh"))
        net.stop()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 experiments/diagnose_race.py ...")
    main()
