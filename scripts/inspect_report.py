"""打印 OpenVAS XML 报告中 result 节点的结构，供编写 parse_report.py 前确认字段。

对所有 result 节点做并集：列出每个子路径出现的次数、属性名和一个示例值，
并统计严重度分布、QoD 分布和 refs 类型。只读，不需要连接 gvmd。

用法：
    python -m scripts.inspect_report [data/samples/smoke_report.xml]
"""

import argparse
from collections import Counter
from pathlib import Path

from lxml import etree

ROOT = Path(__file__).resolve().parent.parent


def walk(el, path: str, stats: dict) -> None:
    """递归记录路径 → [出现次数, 属性名集合, 示例值]，保持首次出现顺序。"""
    entry = stats.setdefault(path, [0, set(), None])
    entry[0] += 1
    entry[1].update(el.attrib.keys())
    text = (el.text or "").strip()
    if text and entry[2] is None:
        entry[2] = " ".join(text.split())[:70]
    for child in el:
        if isinstance(child.tag, str):
            walk(child, f"{path}/{child.tag}", stats)


def main() -> None:
    p = argparse.ArgumentParser(description="查看 OpenVAS XML 报告结构")
    p.add_argument("path", type=Path, nargs="?", default=ROOT / "data" / "samples" / "smoke_report.xml")
    args = p.parse_args()

    root = etree.parse(str(args.path)).getroot()
    report = root.find(".//report/report")
    results = root.findall(".//results/result")
    print(f"文件：{args.path}")
    print(f"根节点：<{root.tag}>，内层报告 id={report.get('id') if report is not None else '?'}")
    print(f"result 总数：{len(results)}")
    if not results:
        return

    stats: dict = {}
    for r in results:
        walk(r, "result", stats)

    # 按"各级祖先的首次出现顺序"排序，保证子节点紧跟在父节点下方
    first_seen = {path: i for i, path in enumerate(stats)}

    def order(path: str) -> tuple:
        parts = path.split("/")
        return tuple(first_seen["/".join(parts[: i + 1])] for i in range(len(parts)))

    print("\n== result 节点结构（缩进=层级 | 属性 | [出现次数] | 示例值）")
    for path in sorted(stats, key=order):
        count, attrs, sample = stats[path]
        depth = path.count("/")
        name = path.rsplit("/", 1)[-1]
        attr_s = f" @{','.join(sorted(attrs))}" if attrs else ""
        sample_s = f"  = {sample}" if sample else ""
        print(f"{'  ' * depth}{name}{attr_s}  [{count}]{sample_s}")

    print("\n== threat 分布：", dict(Counter(r.findtext("threat") for r in results)))
    sev = [float(r.findtext("severity") or 0) for r in results]
    print(f"== severity：min={min(sev)} max={max(sev)}，>=7.0 的有 {sum(s >= 7 for s in sev)} 条")
    print("== qod/value 分布：", dict(Counter(r.findtext("qod/value") for r in results)))
    print("== refs 类型计数：", dict(Counter(ref.get("type") for ref in root.iterfind(".//results/result/nvt/refs/ref"))))
    ports = Counter(r.findtext("port") for r in results)
    print("== 端口（前 10）：", dict(ports.most_common(10)))


if __name__ == "__main__":
    main()
