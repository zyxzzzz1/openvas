"""src/vuln/parse_report.py 的测试，输入为 data/samples/smoke_report.xml。"""

import copy
from collections import Counter
from pathlib import Path

import pytest
from lxml import etree

from src.vuln.parse_report import DISCLAIMER, ReportIntegrityError, load_report, parse_report

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "data" / "samples" / "smoke_report.xml"
FIELDS = {"asset_ip", "port", "nvt_oid", "name", "cvss", "cves", "solution", "qod",
          "threat", "solution_type", "cvss_version"}


@pytest.fixture(scope="module")
def parsed() -> dict:
    return parse_report(SAMPLE)


@pytest.fixture(scope="module")
def sample_tree() -> etree._ElementTree:
    return etree.parse(str(SAMPLE))


def write_variant(tree, tmp_path: Path, edit) -> Path:
    """复制样本树，用 edit(内层 report) 修改后写到临时文件。"""
    t = copy.deepcopy(tree)
    edit(t.getroot().find(".//report/report"))
    out = tmp_path / "variant.xml"
    t.write(str(out))
    return out


def test_stats(parsed):
    s = parsed["stats"]
    assert s["results_total"] == 630
    assert s["log_dropped"] == 90
    assert s["vulns"] == 630 - 90 - s["duplicates_dropped"]
    assert len(parsed["vulns"]) == s["vulns"]


def test_disclaimer_and_source(parsed):
    assert parsed["disclaimer"] == DISCLAIMER
    assert parsed["source_report_id"] == "6a6bb06c-1fb5-4d4a-ac25-bd3ec6211993"


def test_record_fields(parsed):
    for v in parsed["vulns"]:
        assert set(v) == FIELDS
        assert v["asset_ip"] == "192.168.56.11"
        assert v["nvt_oid"].startswith("1.3.6.1.4.1.25623.")
        assert 0 < v["cvss"] <= 10
        assert isinstance(v["qod"], int)
        assert v["cvss_version"] in {"v2", "v3"}
        assert all(c.startswith("CVE-") for c in v["cves"])


def test_no_log_results(parsed):
    # "SSL/TLS: Report Weak Cipher Suites" 在 25/tcp 上是 Log（severity=0，但 nvt/cvss_base=5.9），
    # 在 5432/tcp 上是 Medium（5.9）：只应保留后者
    assert all(v["threat"] != "Log" for v in parsed["vulns"])
    weak = {v["port"]: v["cvss"] for v in parsed["vulns"] if v["name"] == "SSL/TLS: Report Weak Cipher Suites"}
    assert weak == {"5432/tcp": 5.9}


def test_all_critical_kept(parsed):
    threats = Counter(v["threat"] for v in parsed["vulns"])
    assert threats["Critical"] == 101
    assert sum(v["cvss"] >= 9.0 for v in parsed["vulns"]) == 101


def test_qod_not_filtered(parsed):
    # 样本中有 QoD=30 的结果，parse_report 不应过滤
    assert min(v["qod"] for v in parsed["vulns"]) < 70


def test_keys_unique_and_sorted(parsed):
    keys = [(v["asset_ip"], v["port"], v["nvt_oid"]) for v in parsed["vulns"]]
    assert len(keys) == len(set(keys))
    cvss = [v["cvss"] for v in parsed["vulns"]]
    assert cvss == sorted(cvss, reverse=True)


def test_dedup_keeps_highest_severity_then_qod(sample_tree, tmp_path):
    """把一条非 Log 结果复制两份：一份降低 severity 但 QoD 最高，一份提高 severity 但 QoD 最低。"""
    state = {}

    def edit(report):
        results = report.find("results")
        orig = next(r for r in results if 1.0 < float(r.findtext("severity")) < 10.0)
        state["key"] = (orig.findtext("host").strip(), orig.findtext("port"), orig.find("nvt").get("oid"))
        sev = float(orig.findtext("severity"))
        low = copy.deepcopy(orig)
        low.find("severity").text = str(sev - 0.5)
        low.find("qod/value").text = "100"
        results.append(low)
        high = copy.deepcopy(orig)
        high.find("severity").text = str(sev + 0.1)
        high.find("qod/value").text = "1"
        results.append(high)
        state["expect"] = (float(high.findtext("severity")), 1)
        n = str(len(results))
        report.find("result_count/full").text = n
        report.find("result_count/filtered").text = n

    data = parse_report(write_variant(sample_tree, tmp_path, edit))
    hits = [v for v in data["vulns"] if (v["asset_ip"], v["port"], v["nvt_oid"]) == state["key"]]
    assert len(hits) == 1
    assert (hits[0]["cvss"], hits[0]["qod"]) == state["expect"]


def test_dedup_tie_on_severity_uses_qod(sample_tree, tmp_path):
    state = {}

    def edit(report):
        results = report.find("results")
        orig = next(r for r in results if float(r.findtext("severity")) > 0)
        state["key"] = (orig.findtext("host").strip(), orig.findtext("port"), orig.find("nvt").get("oid"))
        dup = copy.deepcopy(orig)
        dup.find("qod/value").text = str(int(orig.findtext("qod/value")) + 1)
        state["qod"] = int(dup.findtext("qod/value"))
        results.append(dup)
        n = str(len(results))
        report.find("result_count/full").text = n
        report.find("result_count/filtered").text = n

    data = parse_report(write_variant(sample_tree, tmp_path, edit))
    hits = [v for v in data["vulns"] if (v["asset_ip"], v["port"], v["nvt_oid"]) == state["key"]]
    assert len(hits) == 1 and hits[0]["qod"] == state["qod"]


def test_count_mismatch_raises(sample_tree, tmp_path):
    # 删除一条结果但不改 result_count，模拟导出被截断
    def edit(report):
        results = report.find("results")
        results.remove(results[0])

    with pytest.raises(ReportIntegrityError):
        load_report(write_variant(sample_tree, tmp_path, edit))


def test_filtered_full_mismatch_raises(sample_tree, tmp_path):
    def edit(report):
        report.find("result_count/filtered").text = "629"

    with pytest.raises(ReportIntegrityError):
        parse_report(write_variant(sample_tree, tmp_path, edit))
