from __future__ import annotations


def safe_ratio(numerator: float, denominator: float) -> float:
    return round(numerator / denominator, 6) if denominator > 0 else 0.0


def port_category(port: int) -> str:
    if port <= 1023:
        return "well_known"
    if port <= 49151:
        return "registered"
    return "dynamic"


def engineer_flow_features(event: dict) -> dict:
    """Produce deterministic model-ready features without raw identifiers."""
    duration = max(float(event["duration"]), 0.0)
    packets = max(int(event["packets"]), 0)
    byte_count = max(int(event["bytes"]), 0)
    src_bytes = max(int(event.get("src_bytes", 0)), 0)
    dst_bytes = max(int(event.get("dst_bytes", 0)), 0)
    src_packets = max(int(event.get("src_packets", 0)), 0)
    dst_packets = max(int(event.get("dst_packets", 0)), 0)
    return {
        "duration": duration,
        "total_packets": packets,
        "total_bytes": byte_count,
        "bytes_per_packet": safe_ratio(byte_count, packets),
        "packets_per_second": safe_ratio(packets, duration),
        "bytes_per_second": safe_ratio(byte_count, duration),
        "src_dst_byte_ratio": safe_ratio(src_bytes, dst_bytes),
        "src_dst_packet_ratio": safe_ratio(src_packets, dst_packets),
        "src_port_category": port_category(int(event["src_port"])),
        "dst_port_category": port_category(int(event["dst_port"])),
        "protocol": str(event["protocol"]).upper(),
        "has_tcp_flags": bool(event.get("tcp_flags")),
    }
