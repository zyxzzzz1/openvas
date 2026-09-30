"""OpenVAS XML 报告 → 标准化漏洞记录 vulns.json（claude.md 第 7 节 M7）。

处理规则：
- 读取前做三数核对：实际 result 条数 == result_count/filtered == result_count/full，
  不一致说明导出时有结果被过滤或分页截断，直接报错退出。
- 不做 QoD 过滤，全部保留并写入 qod 字段（过滤在融合打分阶段按 fusion.yaml 的 min_qod 进行）。
- Log 结果（severity <= 0）不写入。
- 按 (asset_ip, port, nvt_oid) 去重：保留 severity 最高的，其次 QoD 最高的。

用法：
    python -m src.vuln.parse_report [--input XML] [--output JSON]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml
from lxml import etree

ROOT = Path(__file__).resolve().parents[2]
DISCLAIMER = "资产映射与漏洞数据来自实验环境，仅用于演示"


class ReportIntegrityError(Exception):
    """报告条数核对失败（导出不完整）。"""


def load_report(path: Path) -> etree._Element:
    """读取报告并做三数核对，返回内层 <report> 节点。"""
    root = etree.parse(str(path)).getroot()
    report = root.find(".//report/report")
    if report is None:
        raise ReportIntegrityError(f"{path} 中找不到内层 <report> 节点")
    n = len(report.findall("results/result"))
    filtered = (report.findtext("result_count/filtered") or "").strip()
    full = (report.findtext("result_count/full") or "").strip()
    if not (str(n) == filtered == full):
        raise ReportIntegrityError(
            f"条数不一致：导出 {n} 条，filtered={filtered or '缺失'}，full={full or '缺失'}；报告不完整，请重新导出"
        )
    return report


def _text(el: etree._Element, path: str) -> str:
    return (el.findtext(path) or "").strip()


def parse_result(result: etree._Element) -> dict:
    """把单个 <result> 节点转成标准化记录（含 Log 结果，是否丢弃由调用方决定）。"""
    nvt = result.find("nvt")
    solution = nvt.find("solution")
    severity_type = nvt.find("severities/severity")
    cvss_version = None
    if severity_type is not None and severity_type.get("type"):
        # cvss_base_v2 / cvss_base_v3 → v2 / v3
        cvss_version = severity_type.get("type").removeprefix("cvss_base_")
    qod = _text(result, "qod/value")
    return {
        "asset_ip": _text(result, "host"),
        "port": _text(result, "port"),
        "nvt_oid": nvt.get("oid"),
        "name": _text(nvt, "name"),
        "cvss": float(_text(result, "severity") or 0),
        "cves": [ref.get("id") for ref in nvt.iterfind("refs/ref[@type='cve']")],
        "solution": (solution.text or "").strip() if solution is not None else "",
        "qod": int(qod) if qod else None,
        "threat": _text(result, "threat"),
        "solution_type": (solution.get("type") or None) if solution is not None else None,
        "cvss_version": cvss_version,
    }


def parse_report(path: Path) -> dict:
    """解析报告，返回带免责声明和统计信息的对象；vulns 按 cvss 降序排列。"""
    report = load_report(path)
    records = [parse_result(r) for r in report.iterfind("results/result")]
    kept = [r for r in records if r["cvss"] > 0]

    best: dict[tuple, dict] = {}
    for rec in kept:
        key = (rec["asset_ip"], rec["port"], rec["nvt_oid"])
        cur = best.get(key)
        if cur is None or (rec["cvss"], rec["qod"] or 0) > (cur["cvss"], cur["qod"] or 0):
            best[key] = rec
    vulns = sorted(best.values(), key=lambda r: (-r["cvss"], r["asset_ip"], r["port"], r["nvt_oid"]))

    return {
        "disclaimer": DISCLAIMER,
        "source_report_id": report.get("id"),
        "source_file": str(path),
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "stats": {
            "results_total": len(records),
            "log_dropped": len(records) - len(kept),
            "duplicates_dropped": len(kept) - len(vulns),
            "vulns": len(vulns),
        },
        "vulns": vulns,
    }


def main() -> int:
    p = argparse.ArgumentParser(description="OpenVAS XML 报告 → vulns.json")
    p.add_argument("--config", type=Path, default=ROOT / "config" / "config.yaml")
    p.add_argument("--input", type=Path, help="默认取 config.yaml 的 vuln.report_xml")
    p.add_argument("--output", type=Path, help="默认取 config.yaml 的 vuln.vulns_json")
    args = p.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = yaml.safe_load(f)["vuln"]
    src = args.input or ROOT / cfg["report_xml"]
    dst = args.output or ROOT / cfg["vulns_json"]

    try:
        data = parse_report(src)
    except ReportIntegrityError as e:
        print(f"[失败] {e}", file=sys.stderr)
        return 4

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    s = data["stats"]
    print(
        f"[保存] {dst}：共 {s['results_total']} 条结果，丢弃 Log {s['log_dropped']} 条、"
        f"重复 {s['duplicates_dropped']} 条，写入 {s['vulns']} 条"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
