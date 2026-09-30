"""最小化冒烟扫描：对 asset_map 中的单台靶机跑一次 OpenVAS 扫描并导出 XML 报告。

默认只做预检（dry-run）：连接、认证、校验 IP 是否在 gvm.lab_subnet 内、按名称解析
scan config / scanner / port list / report format 的 ID，并打印将要执行的步骤，不创建任何对象。
加 --execute 才会新建 target、task 并启动扫描（执行前还会要求输入 yes 确认）。

约束：
- 只新建对象，名称带 "smoke_test_" 前缀和时间戳，绝不查找或复用已有 target / task。
- 目标 IP 必须在 asset_map 中标记 scanned: true，且位于 gvm.lab_subnet 内，否则直接退出。
- 凭据只从环境变量 GVM_USER / GVM_PASSWORD 读取。

用法：
    python -m scripts.smoke_scan                      # 预检
    python -m scripts.smoke_scan --execute            # 创建并启动扫描，轮询到结束后导出报告
    python -m scripts.smoke_scan --report-id UUID     # 只导出已有报告（只读）
"""

import argparse
import ipaddress
import os
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree

ROOT = Path(__file__).resolve().parent.parent
NAME_PREFIX = "smoke_test_"
# 冒烟样本要看到全部结果：不应用 override、不按 QoD 过滤、不分页、包含 log 级别
# 注意 levels 必须含 c（Critical，严重度 >= 9.0，新版 gvmd 引入），否则 >= 9.0 的结果会被静默丢弃
REPORT_FILTER = "apply_overrides=0 min_qod=0 rows=-1 first=1 levels=chmlg"
FINISHED = {"Done", "Stopped", "Interrupted"}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="OpenVAS 冒烟扫描（默认只预检）")
    p.add_argument("--config", type=Path, default=ROOT / "config" / "config.yaml")
    p.add_argument("--asset-map", type=Path, default=ROOT / "config" / "asset_map.yaml")
    p.add_argument("--asset", default="ews_01", help="asset_map 中的资产名")
    p.add_argument("--scan-config", default="Full and fast")
    p.add_argument("--scanner", default="OpenVAS Default")
    p.add_argument("--port-list", default="All IANA assigned TCP")
    p.add_argument("--output", type=Path, default=ROOT / "data" / "samples" / "smoke_report.xml")
    p.add_argument("--poll", type=int, default=30, help="轮询间隔（秒）")
    p.add_argument("--timeout", type=int, default=4 * 3600, help="最长等待时间（秒）")
    p.add_argument("--execute", action="store_true", help="真正创建并启动扫描")
    p.add_argument("--yes", action="store_true", help="--execute 时跳过交互确认")
    p.add_argument("--report-id", help="只导出指定报告，不创建任何对象")
    return p.parse_args()


def load_yaml(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def resolve_host(args: argparse.Namespace, cfg: dict) -> str:
    """从 asset_map 取目标 IP，并校验 scanned 标记与实验网段。失败时直接退出。"""
    asset = load_yaml(args.asset_map).get("assets", {}).get(args.asset)
    if not asset:
        sys.exit(f"[停止] asset_map 中没有资产 {args.asset}")
    if not asset.get("scanned") or not asset.get("ip"):
        sys.exit(f"[停止] 资产 {args.asset} 未标记 scanned: true 或没有 IP")
    subnet = ipaddress.ip_network(cfg["gvm"]["lab_subnet"])
    ip = ipaddress.ip_address(asset["ip"])
    if ip not in subnet:
        sys.exit(f"[停止] {ip} 不在实验网段 {subnet} 内")
    print(f"[通过] {args.asset} = {ip}，位于实验网段 {subnet} 内")
    return str(ip)


def find_id(response, tag: str, name: str) -> str:
    """在 get_xxx 响应中按名称精确匹配，返回 id；找不到时退出。"""
    for el in response.findall(tag):
        if el.findtext("name") == name:
            return el.get("id")
    sys.exit(f"[停止] 找不到名为 “{name}” 的 {tag}")


def wait_for_task(gmp, task_id: str, poll_s: int, timeout_s: int) -> str:
    """轮询任务状态直到结束或超时，返回最终状态。"""
    start = time.monotonic()
    while True:
        task = gmp.get_task(task_id).find("task")
        status = task.findtext("status")
        progress = task.findtext("progress")
        elapsed = int(time.monotonic() - start)
        print(f"  [{elapsed // 60:3d} min] status={status} progress={progress}%", flush=True)
        if status in FINISHED:
            return status
        if elapsed > timeout_s:
            print(f"[警告] 超过 {timeout_s}s 仍未结束，停止等待（扫描仍在 gvmd 中继续）")
            return status
        time.sleep(poll_s)


def export_report(gmp, report_id: str, xml_format_id: str, output: Path) -> bool:
    """按 XML 格式导出完整报告并保存；返回导出条数是否与报告总数一致。"""
    response = gmp.get_report(
        report_id,
        filter_string=REPORT_FILTER,
        report_format_id=xml_format_id,
        ignore_pagination=True,
        details=True,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(etree.tostring(response, pretty_print=True, xml_declaration=True, encoding="UTF-8"))
    n = len(response.findall(".//results/result"))
    full = response.findtext(".//report/report/result_count/full")
    filtered = response.findtext(".//report/report/result_count/filtered")
    print(f"[保存] 报告 {report_id} → {output}（导出 {n} 条，filtered={filtered}，full={full}）")
    # 过滤条件已放开全部级别和 QoD，三个数应一致；不一致说明有结果被过滤或分页截断
    if str(n) == filtered == full:
        print("[通过] 导出条数与报告总数一致")
        return True
    print("[失败] 导出条数与报告总数不一致，报告不完整，请检查 REPORT_FILTER")
    return False


def main() -> int:
    args = parse_args()
    cfg = load_yaml(args.config)
    user, password = os.environ.get("GVM_USER"), os.environ.get("GVM_PASSWORD")
    if not user or not password:
        sys.exit("[停止] 未设置 GVM_USER / GVM_PASSWORD")

    host = None if args.report_id else resolve_host(args, cfg)
    connection = UnixSocketConnection(path=cfg["gvm"]["socket_path"], timeout=120)
    try:
        with Gmp(connection=connection, transform=EtreeCheckCommandTransform()) as gmp:
            gmp.authenticate(user, password)
            xml_format_id = find_id(gmp.get_report_formats(filter_string="rows=-1"), "report_format", "XML")

            if args.report_id:
                return 0 if export_report(gmp, args.report_id, xml_format_id, args.output) else 4

            config_id = find_id(gmp.get_scan_configs(filter_string="rows=-1"), "config", args.scan_config)
            scanner_id = find_id(gmp.get_scanners(filter_string="rows=-1"), "scanner", args.scanner)
            port_list_id = find_id(gmp.get_port_lists(filter_string="rows=-1"), "port_list", args.port_list)

            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            target_name = f"{NAME_PREFIX}{args.asset}_{stamp}"
            task_name = f"{NAME_PREFIX}{args.asset}_{stamp}"

            print("\n将要执行的步骤：")
            print(f"  1. create_target  name={target_name}  hosts=[{host}]")
            print(f"                    port_list={args.port_list} ({port_list_id})")
            print(f"  2. create_task    name={task_name}")
            print(f"                    config={args.scan_config} ({config_id})")
            print(f"                    scanner={args.scanner} ({scanner_id})")
            print("  3. start_task")
            print(f"  4. 每 {args.poll}s 轮询 get_task，直到 Done/Stopped/Interrupted（最长 {args.timeout}s）")
            print(f"  5. get_report（XML {xml_format_id}，filter “{REPORT_FILTER}”）→ {args.output}")

            if not args.execute:
                print("\n[预检完成] 未创建任何对象。确认无误后加 --execute 运行。")
                return 0
            if not args.yes and input("\n输入 yes 开始执行：").strip() != "yes":
                print("[已取消] 未创建任何对象。")
                return 0

            target_id = gmp.create_target(
                target_name,
                hosts=[host],
                port_list_id=port_list_id,
                comment="冒烟测试，可删除",
            ).get("id")
            print(f"[创建] target {target_name} ({target_id})")
            task_id = gmp.create_task(
                task_name, config_id, target_id, scanner_id, comment="冒烟测试，可删除"
            ).get("id")
            print(f"[创建] task {task_name} ({task_id})")
            report_id = gmp.start_task(task_id).findtext("report_id")
            print(f"[启动] report_id={report_id}（中途 Ctrl+C 不会停止扫描，可稍后用 --report-id 导出）")

            try:
                status = wait_for_task(gmp, task_id, args.poll, args.timeout)
            except KeyboardInterrupt:
                print(f"\n[中断] 停止轮询。扫描仍在继续：task={task_id} report={report_id}")
                return 130

            if not export_report(gmp, report_id, xml_format_id, args.output):
                return 4
            if status != "Done":
                print(f"[警告] 任务最终状态为 {status}，报告可能不完整")
                return 3
            return 0
    except GvmError as e:
        print(f"[失败] GMP 错误：{e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
