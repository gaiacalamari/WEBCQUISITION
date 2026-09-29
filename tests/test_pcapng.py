from webcquisition_common.pcapng import (
    IncrementalPcapngReader,
    summarize,
    synthetic_header,
    synthetic_packet,
    synthetic_pcapng,
)

IFACE = r"\Device\NPF_{11111111-2222-3333-4444-555555555555}"


def test_summarize_synthetic(tmp_path):
    p = tmp_path / "c.pcapng"
    p.write_bytes(synthetic_pcapng(IFACE, 7, 1_780_000_000.0))
    s = summarize(p)
    assert s.valid and s.packets == 7 and s.interface_names == [IFACE]
    assert s.first_ts is not None and s.last_ts >= s.first_ts
    assert s.to_dict()["first_ts_utc"].endswith("Z")


def test_incremental_growth_and_truncated_tail(tmp_path):
    p = tmp_path / "c.pcapng"
    p.write_bytes(synthetic_header(IFACE))
    r = IncrementalPcapngReader(p)
    assert r.update().packets == 0
    pkt = synthetic_packet(1_780_000_000.0)
    with open(p, "ab") as fh:
        fh.write(pkt * 3 + pkt[:10])  # ultimo blocco scritto a metà (cattura in corso)
    s = r.update()
    assert s.packets == 3 and s.valid
    with open(p, "ab") as fh:
        fh.write(pkt[10:])
    assert r.update().packets == 4


def test_invalid_file(tmp_path):
    p = tmp_path / "x.pcapng"
    p.write_bytes(b"NOT A PCAPNG FILE AT ALL")
    assert not summarize(p).valid
