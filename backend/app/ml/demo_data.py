from __future__ import annotations

import csv
import io
from datetime import datetime, timedelta, timezone


def generate_labeled_demo_csv(rows_per_class: int = 60) -> bytes:
    """Create deterministic synthetic flows for pipeline demonstrations only."""
    output = io.StringIO()
    fields = ["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "duration", "packets", "bytes", "src_bytes", "dst_bytes", "src_packets", "dst_packets", "tcp_flags", "label"]
    writer = csv.DictWriter(output, fieldnames=fields)
    writer.writeheader()
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for index in range(rows_per_class):
        packets = 18 + index % 22
        byte_count = packets * (420 + index % 90)
        writer.writerow({
            "timestamp": (start + timedelta(seconds=index * 10)).isoformat(),
            "src_ip": f"10.10.{index % 8}.{10 + index % 200}", "dst_ip": f"10.20.{index % 6}.{20 + index % 180}",
            "src_port": 50000 + index % 1000, "dst_port": [53, 80, 443, 123][index % 4],
            "protocol": "UDP" if index % 4 in {0, 3} else "TCP", "duration": round(1.5 + (index % 13) * 0.23, 3),
            "packets": packets, "bytes": byte_count, "src_bytes": int(byte_count * .52), "dst_bytes": int(byte_count * .48),
            "src_packets": packets // 2 + packets % 2, "dst_packets": packets // 2,
            "tcp_flags": "ACK,PSH" if index % 4 in {1, 2} else "", "label": "benign",
        })
    for index in range(rows_per_class):
        packets = 2 + index % 7
        byte_count = packets * (54 + index % 38)
        writer.writerow({
            "timestamp": (start + timedelta(hours=1, seconds=index * 4)).isoformat(),
            "src_ip": f"10.30.{index % 5}.{30 + index % 190}", "dst_ip": f"10.40.{index % 18}.{40 + index % 170}",
            "src_port": 51000 + index % 1200, "dst_port": [22, 23, 445, 3389, 8080, 1433][index % 6],
            "protocol": "TCP", "duration": round(.04 + (index % 9) * .025, 3),
            "packets": packets, "bytes": byte_count, "src_bytes": int(byte_count * .78), "dst_bytes": int(byte_count * .22),
            "src_packets": max(1, packets - 1), "dst_packets": 1,
            "tcp_flags": "SYN", "label": "malicious",
        })
    return output.getvalue().encode("utf-8")
