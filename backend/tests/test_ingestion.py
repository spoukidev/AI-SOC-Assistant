from app.ml.features import engineer_flow_features, port_category
from app.services.csv_ingestion import parse_csv_text


CSV_TEXT = """timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,packets,bytes,src_bytes,dst_bytes,tcp_flags
2026-08-21T10:00:00Z,10.0.0.1,10.0.0.2,51000,443,tcp,2.0,10,1000,700,300,SYN
2026-08-21T10:01:00Z,not-an-ip,10.0.0.3,51001,53,udp,0.2,2,180,90,90,
"""


def test_csv_parser_accepts_valid_rows_and_reports_invalid_rows():
    result = parse_csv_text(CSV_TEXT, "flows.csv", {})
    assert result.total_rows == 2
    assert len(result.events) == 1
    assert result.events[0]["protocol"] == "TCP"
    assert result.errors == [{"row": 3, "reason": "invalid source or destination IP address"}]
    assert result.events[0]["features"]["bytes_per_packet"] == 100.0


def test_feature_engineering_excludes_raw_identifiers():
    event = parse_csv_text(CSV_TEXT.splitlines()[0] + "\n" + CSV_TEXT.splitlines()[1], "flows.csv", {}).events[0]
    features = engineer_flow_features(event)
    assert "src_ip" not in features
    assert "dst_ip" not in features
    assert features["packets_per_second"] == 5.0
    assert port_category(443) == "well_known"
    assert port_category(51000) == "dynamic"
