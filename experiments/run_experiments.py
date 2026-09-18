#!/usr/bin/env python3
"""
Automated experiment runner for the TCP Reset Attack on Video Streaming
project. Produces the statistics the final report needs:

  - Attack success rate over N repeated trials (defense off)
  - The same, with the IP Source Guard defense enabled (before/after)
  - Per-trial attempts-to-kill and time-to-kill, for successful trials
  - Downloaded-bytes-fraction, to quantify "how much of the video survived"
  - Optionally: sweep WAN bandwidth/delay to show how the race margin
    (attacker's LAN-speed path vs. the server's WAN-routed path) affects
    success rate

Builds its own topology (no manual xterms/mininet CLI needed), drives the
server/attacker/client itself via the Mininet Python API, and writes a CSV
of per-trial results plus a printed summary.

Run with (from anywhere, needs root):
    sudo python3 experiments/run_experiments.py --trials 20
    sudo python3 experiments/run_experiments.py --trials 20 --scenarios on
    sudo python3 experiments/run_experiments.py --trials 20 --wan-bw 5 --wan-delay-r1 100ms --out experiments/results_fastwan.csv

Must NOT be run while a separate `sudo python3 topo.py` is already up --
this script builds and tears down its own topology instance.
"""

import argparse
import csv
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

from mininet.log import setLogLevel, info  # noqa: E402
from topo import build  # noqa: E402

RESULT_RE = re.compile(r"RESULT client_port=(\d+) attempts=(\d+) time_to_close=(\S+)")
FIRED_RE = re.compile(r"^\[attack\] #\d+", re.MULTILINE)
CURL_OUT_RE = re.compile(r"(\d+) (\d+) ([\d.]+) EXIT:(\d+)")


def parse_args():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--trials", type=int, default=15, help="trials per scenario (default: 15)")
    p.add_argument("--scenarios", choices=["off", "on", "both"], default="both",
                    help="defense off / on / both (default: both)")
    p.add_argument("--wan-bw", type=float, default=1, help="WAN link bandwidth in Mbit/s (default: 1)")
    p.add_argument("--wan-delay-r1", default="20ms", help="r1<->s2 link delay (default: 20ms)")
    p.add_argument("--wan-delay-h3", default="5ms", help="h3<->s2 link delay (default: 5ms)")
    p.add_argument("--out", default=os.path.join(EXPERIMENTS_DIR, "results.csv"), help="output CSV path")
    p.add_argument("--label", default="", help="free-text tag for this run's network condition (for combining multiple CSVs later)")
    p.add_argument("--head-start-fraction", type=float, default=0.15,
                    help="fraction of the estimated total transfer time to let the download run "
                         "before the attacker joins, modeling the attacker gaining visibility "
                         "partway through an already-flowing stream rather than being present "
                         "since before the handshake (default: 0.15). Expressed as a FRACTION, "
                         "not fixed seconds, so it stays proportionally meaningful as --wan-bw "
                         "changes the total transfer time -- a fixed number of seconds either "
                         "eats almost the whole transfer (high bandwidth) or barely registers "
                         "(low bandwidth).")
    return p.parse_args()


def estimate_transfer_seconds(expected_bytes, wan_bw_mbit):
    """Rough estimate of total download time at the given WAN bandwidth,
    ignoring TCP overhead/slow-start/RTT -- good enough to scale the
    head-start proportionally across different --wan-bw settings."""
    return (expected_bytes * 8) / (wan_bw_mbit * 1e6)


def run_bash(script_path, check=False):
    import subprocess
    return subprocess.run(["bash", script_path], capture_output=True, text=True, check=check)


def wait_for_video(path, timeout=5):
    if not os.path.exists(path):
        sys.exit(f"error: {path} does not exist -- run streaming/generate_video.sh first")
    return os.path.getsize(path)


def read_file_resilient(path, retries=5, delay=0.1):
    """Plain open().read(), tolerating the transient ENODATA/OSError
    hiccups DrvFS (the WSL2 <-> Windows /mnt/e mount) occasionally throws
    under rapid repeated file I/O across many trials -- not a real
    failure, just retry a few times before giving up."""
    for attempt in range(retries):
        try:
            with open(path) as f:
                return f.read()
        except OSError:
            if attempt == retries - 1:
                raise
            time.sleep(delay)


def wait_for_attacker_ready(log_path, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(log_path):
            try:
                if "listening on" in read_file_resilient(log_path):
                    return True
            except OSError:
                pass
        time.sleep(0.1)
    return False


def run_trial(net, trial_idx, scenario, expected_bytes, args):
    h1 = net.get("h1")
    h2 = net.get("h2")

    log_path = os.path.join(LOGS_DIR, f"attacker_{scenario}_{trial_idx}.log")
    curl_log_path = os.path.join(LOGS_DIR, f"curl_{scenario}_{trial_idx}.log")
    open(log_path, "w").close()
    open(curl_log_path, "w").close()

    # Start the download FIRST, in the background, and give it a head
    # start before the attacker joins -- this models the design report's
    # actual scenario (attacker gains on-path visibility partway through
    # an already-flowing stream), not "attacker present since before the
    # TCP handshake." Starting the attacker first instead made it react
    # to the handshake's final (data-free) ACK and kill the connection
    # before curl ever got to send its HTTP request.
    curl_cmd = (
        '(curl -s -o /dev/null -w "%{http_code} %{size_download} %{time_total}" '
        'http://10.0.2.10:8000/video.mp4; echo " EXIT:$?") '
        f'> "{curl_log_path}" 2>&1 & echo $!'
    )
    curl_pid = h1.cmd(curl_cmd).strip().splitlines()[-1]

    time.sleep(args.head_start)

    pid_out = h2.cmd(
        f'PYTHONUNBUFFERED=1 python3 "{os.path.join(ATTACK_DIR, "attacker.py")}" '
        f'> "{log_path}" 2>&1 & echo $!'
    )
    attacker_pid = pid_out.strip().splitlines()[-1]

    if not wait_for_attacker_ready(log_path):
        print(f"  [warn] trial {trial_idx}: attacker did not report ready in time")

    # Poll until curl's backgrounded process exits (or we time out as a
    # safety net -- shouldn't happen, but a hung trial would otherwise
    # block the whole run forever).
    deadline = time.time() + 60
    while time.time() < deadline:
        alive = h1.cmd(f"kill -0 {curl_pid} 2>/dev/null; echo $?").strip().splitlines()[-1]
        if alive != "0":
            break
        time.sleep(0.2)
    else:
        print(f"  [warn] trial {trial_idx}: curl did not finish within timeout")

    # Grace period so the attacker script has a chance to observe the
    # connection's own closing packet and print its RESULT line before we
    # kill it -- doesn't affect the success verdict (that comes from
    # curl's byte count), only the supplementary attempts/timing stats.
    time.sleep(0.5)
    h2.cmd(f"kill {attacker_pid} 2>/dev/null")
    time.sleep(0.2)

    curl_out = read_file_resilient(curl_log_path)
    m = CURL_OUT_RE.search(curl_out)
    if not m:
        print(f"  [warn] trial {trial_idx}: could not parse curl output: {curl_out!r}")
        http_code, downloaded, time_total, curl_exit = "0", "0", "0", "1"
    else:
        http_code, downloaded, time_total, curl_exit = m.groups()
    downloaded = int(downloaded)

    log_text = read_file_resilient(log_path)
    fired_count = len(FIRED_RE.findall(log_text))
    result_m = RESULT_RE.search(log_text)
    attempts_to_kill = int(result_m.group(2)) if result_m else fired_count
    time_to_close = result_m.group(3) if result_m else ""
    time_to_close = None if time_to_close in ("", "None") else float(time_to_close)

    success = (curl_exit != "0") or (downloaded < expected_bytes * 0.99)

    return {
        "trial": trial_idx,
        "scenario": scenario,
        "wan_bw": args.wan_bw,
        "wan_delay_r1": args.wan_delay_r1,
        "wan_delay_h3": args.wan_delay_h3,
        "label": args.label,
        "expected_bytes": expected_bytes,
        "downloaded_bytes": downloaded,
        "downloaded_fraction": round(downloaded / expected_bytes, 4) if expected_bytes else "",
        "http_code": http_code,
        "curl_time_total": time_total,
        "curl_exit": curl_exit,
        "success": success,
        "attempts_to_kill": attempts_to_kill,
        "time_to_close_s": time_to_close,
    }


def print_summary(rows):
    print("\n=== Summary ===")
    for scenario in sorted(set(r["scenario"] for r in rows)):
        srows = [r for r in rows if r["scenario"] == scenario]
        n = len(srows)
        successes = [r for r in srows if r["success"]]
        rate = 100 * len(successes) / n if n else 0
        print(f"\nScenario: defense={scenario}  ({n} trials)")
        print(f"  success rate: {rate:.1f}% ({len(successes)}/{n})")
        if successes:
            attempts = [r["attempts_to_kill"] for r in successes if r["attempts_to_kill"]]
            times = [r["time_to_close_s"] for r in successes if r["time_to_close_s"] is not None]
            if attempts:
                print(f"  mean attempts-to-kill (successful trials): {sum(attempts) / len(attempts):.1f}")
            if times:
                print(f"  mean time-to-close (successful trials): {sum(times) / len(times):.3f}s")
        failures = [r for r in srows if not r["success"]]
        if failures:
            fracs = [r["downloaded_fraction"] for r in failures if r["downloaded_fraction"] != ""]
            if fracs:
                print(f"  mean downloaded fraction (failed attacks, should be ~1.0): {sum(fracs) / len(fracs):.3f}")


def main():
    args = parse_args()
    os.makedirs(LOGS_DIR, exist_ok=True)

    expected_bytes = wait_for_video(os.path.join(STREAMING_DIR, "video.mp4"))

    est_transfer_s = estimate_transfer_seconds(expected_bytes, args.wan_bw)
    args.head_start = est_transfer_s * args.head_start_fraction
    print(f"*** Estimated transfer time at {args.wan_bw} Mbit/s: {est_transfer_s:.2f}s -- "
          f"head start: {args.head_start:.2f}s ({args.head_start_fraction:.0%})")

    setLogLevel("warning")
    net = build(wan_bw=args.wan_bw, wan_delay_r1=args.wan_delay_r1, wan_delay_h3=args.wan_delay_h3)

    h3 = net.get("h3")
    try:
        print("*** Starting streaming server on h3")
        h3.cmd(
            f'cd "{STREAMING_DIR}" && python3 server.py > "{os.path.join(LOGS_DIR, "server.log")}" 2>&1 &'
        )
        time.sleep(1.5)

        print("*** Enabling attacker visibility (OVS mirror)")
        run_bash(os.path.join(ATTACK_DIR, "mirror_enable.sh"))

        scenarios = ["off", "on"] if args.scenarios == "both" else [args.scenarios]
        rows = []
        write_header = not os.path.exists(args.out)
        # Append each trial's row to the CSV as soon as it's known, rather
        # than batching everything until the very end -- a single
        # transient error (e.g. the DrvFS/WSL2 mount's occasional ENODATA
        # hiccup under heavy repeated file I/O) used to lose every
        # already-completed trial in the run, since nothing was written
        # to disk until after the last one finished.
        with open(args.out, "a", newline="") as csv_file:
            writer = None
            for scenario in scenarios:
                if scenario == "on":
                    print("*** Enabling defense (IP Source Guard)")
                    run_bash(os.path.join(TOPOLOGY_DIR, "defense_enable.sh"))
                else:
                    run_bash(os.path.join(TOPOLOGY_DIR, "defense_disable.sh"))  # best-effort, ignore failure

                for i in range(1, args.trials + 1):
                    print(f"*** [{scenario}] trial {i}/{args.trials}")
                    row = run_trial(net, i, scenario, expected_bytes, args)
                    rows.append(row)
                    if writer is None:
                        writer = csv.DictWriter(csv_file, fieldnames=list(row.keys()))
                        if write_header:
                            writer.writeheader()
                    writer.writerow(row)
                    csv_file.flush()
                    print(f"    success={row['success']} downloaded={row['downloaded_bytes']}/{expected_bytes} "
                          f"attempts={row['attempts_to_kill']}")
                    time.sleep(0.5)

        print(f"\nWrote {len(rows)} rows to {args.out}")
        print_summary(rows)
    finally:
        print("*** Restoring default (vulnerable) state and tearing down")
        run_bash(os.path.join(TOPOLOGY_DIR, "defense_disable.sh"))
        net.stop()


if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("run as root: sudo python3 experiments/run_experiments.py ...")
    main()
