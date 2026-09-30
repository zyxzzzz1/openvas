## 当前阶段（请优先遵守）
- 当前只开发扩展部分（第 7 节 M6–M10 及 src/vuln、src/fusion、templates、app）。
- 机器学习部分（src/data、src/models、train/score/threshold/evaluate/attribution）暂不开发，不要创建或修改这些文件。
- 主线的输出用 mock 数据代替，mock 文件必须带 "is_mock": true 字段。
- 每完成一个步骤，先运行测试，再简要汇报改了哪些文件。
- 遇到说明书没写清的地方，先问我，不要自行假设。

# 项目说明书：面向工控系统的"过程异常检测 + 漏洞上下文"融合告警原型

> 【给协作 LLM 的上下文】
> 这是一个本科/研究生级别的工控安全课程或研究项目，周期 3 周，单人完成，语言为 Python。
> 主线是：在 HAI 工控数据集上，只用正常数据训练 LSTM 自编码器，做无监督攻击检测。
> 扩展部分是：把报警的"传感器归因结果"映射到虚构的工控资产，再结合 OpenVAS 对实验靶机的
> 真实扫描结果，生成带漏洞上下文和修复建议的告警卡片，并按风险排序。
> 请严格遵守第 2 节的约束，写代码时遵守第 11 节的约定。

---

## 1. 项目定位

| 部分 | 内容 | 占比 | 性质 |
|---|---|---|---|
| 主线 | LSTM-AE 无监督检测 + 4 个对比模型 + 阈值 + 评估 + 消融 | 约 80% | 定量实验，核心贡献 |
| 扩展 | 传感器归因 → 资产映射 → OpenVAS 漏洞富化 → 告警排序与卡片 | 约 20% | 原型系统 + 案例研究 |

一句话概括：物理过程层发现"哪里不对"，网络/主机层解释"可能从哪进来的、先修什么"。

纵深防御叙事：
- OpenVAS 负责攻击发生前，发现 IT/OT 边界资产的暴露面与已知漏洞（预防）。
- LSTM-AE 负责攻击发生时，发现物理过程的异常，包括通过合法指令篡改设定值、数值冻结、重放等
  网络层看不出漏洞利用痕迹的攻击（检测）。
- 归因 + 资产映射把两者连起来，把报警从"异常分数"变成"可行动的告警"。

---

## 2. 硬性约束（必须遵守）

1. 训练只用 HAI 的 train 文件（全为正常数据），按时间顺序切出最后 20% 作为验证集，不打乱。
2. test 文件（含攻击与逐秒标签）只在最终评估时使用一次，不得用于调参、选阈值或选模型。
3. 阈值 = 验证集正常数据异常分数的 99% 分位数。
4. 不使用 point-adjust 评估（会虚高指标）。
5. 标准化器（scaler）只在训练集上 fit。
6. 所有模型使用相同的数据划分、窗口设置和评价代码。
7. 扩展部分的资产映射是人为构造的，漏洞数据来自自建靶机扫描，与 HAI 中的攻击没有因果关系。
   因此融合部分不得声称提升了检测指标，只能作为原型演示与案例研究来写。
8. OpenVAS 只扫描自建的、隔离网络中的实验虚拟机。

---

## 3. 总体架构

```
┌──────────────────────── 主线：过程层异常检测 ────────────────────────┐
│ HAI CSV → 预处理(去常量列/标准化/滑窗) → 模型(LSTM-AE/VAE/DeepSVDD/  │
│ PCA/IForest) → 异常分数 → 阈值(验证集99%分位) → 报警事件               │
│                                     │                                │
│                                     ▼                                │
│                     传感器归因(逐传感器重构误差 Top-k)                │
└─────────────────────────────────────┬────────────────────────────────┘
                                      │ alert.json（含 top-k 传感器）
                                      ▼
┌──────────────────────── 扩展：告警富化与排序 ────────────────────────┐
│ 传感器 → 子系统(P1~P4) → 上游资产(asset_map.yaml)                     │
│                                     │                                │
│ OpenVAS(GMP/python-gvm) 扫描靶机 → 解析XML → vulns.json               │
│                                     │                                │
│ CISA KEV + FIRST EPSS 富化 ─────────┤                                │
│                                     ▼                                │
│        融合打分 priority = 异常严重度 × 资产暴露风险 × 资产关键度      │
│                                     ▼                                │
│        告警卡片(Markdown/HTML) + 排序列表 + 可选 Streamlit 演示       │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 4. 技术栈

| 类别 | 选型 | 用途 |
|---|---|---|
| 语言 | Python 3.10+ | 全项目 |
| 数据处理 | pandas, numpy | 读 CSV、滑窗 |
| 深度学习 | PyTorch 2.x | LSTM-AE、LSTM-VAE、Deep SVDD（手写实现） |
| 传统基线 | scikit-learn | PCA（重构误差）、IsolationForest、StandardScaler、指标计算 |
| 配置 | PyYAML + pydantic | config.yaml、asset_map.yaml、数据结构校验 |
| 实验记录 | TensorBoard 或 CSV 日志 | 训练曲线、消融结果 |
| 可视化 | matplotlib | 分数曲线、阈值线、攻击区间、归因热力图 |
| 漏洞扫描 | OpenVAS / Greenbone Community Edition | 扫描实验靶机 |
| 扫描自动化 | python-gvm（GMP 协议），lxml | 建任务、拉取 XML 报告并解析 |
| 威胁情报 | CISA KEV（JSON 源）、FIRST EPSS API | 漏洞在野利用状态与利用概率 |
| 存储 | SQLite（可选）/ JSON 文件 | 漏洞与告警持久化 |
| 报告输出 | Jinja2 | 生成告警卡片 Markdown/HTML |
| 演示（可选） | Streamlit | 告警列表 + 卡片的交互展示 |
| 靶机环境 | VirtualBox 或 Proxmox，仅主机（host-only）网络 | 2~4 台虚拟机模拟工程师站/HMI/历史服务器 |

---

## 5. 目录结构

```
ics-anomaly-vuln-fusion/
├── config/
│   ├── config.yaml            # 数据路径、窗口、模型超参、阈值分位数
│   ├── asset_map.yaml         # 子系统→资产→IP 的映射（人为构造）
│   └── fusion.yaml            # 融合打分的权重参数
├── data/
│   ├── raw/                   # HAI 原始 CSV（不入库）
│   ├── processed/             # 标准化后的 npy/parquet
│   └── intel/                 # kev.json, epss.csv 缓存
├── src/
│   ├── data/
│   │   ├── load_hai.py        # 读取、合并、时间排序、train/val 切分
│   │   ├── preprocess.py      # 去常量列、标准化、缺失处理
│   │   └── windowing.py       # 滑窗 Dataset
│   ├── models/
│   │   ├── lstm_ae.py
│   │   ├── lstm_vae.py
│   │   ├── deep_svdd.py
│   │   └── classic.py         # PCA、IsolationForest 封装
│   ├── train.py               # 统一训练入口 --model lstm_ae
│   ├── score.py               # 输出逐秒异常分数 + 逐传感器误差
│   ├── threshold.py           # 验证集 99% 分位
│   ├── evaluate.py            # 逐点指标 + 事件级指标
│   ├── attribution.py         # Top-k 传感器、子系统命中率
│   ├── vuln/
│   │   ├── gmp_client.py      # python-gvm 封装：建目标、建任务、启动、轮询、取报告
│   │   ├── parse_report.py    # OpenVAS XML → 标准化 vulns.json
│   │   └── intel.py           # 拉取并合并 KEV、EPSS
│   ├── fusion/
│   │   ├── asset_graph.py     # 读取 asset_map，传感器→子系统→资产
│   │   ├── risk.py            # 漏洞风险、资产风险计算
│   │   ├── prioritize.py      # 告警融合打分与排序
│   │   └── render_card.py     # Jinja2 生成告警卡片
│   └── utils/
├── templates/alert_card.md.j2
├── app/streamlit_app.py       # 可选
├── experiments/               # 消融实验配置与结果
├── reports/figures/
└── README.md
```

---

## 6. 主线模块设计

### M1 数据预处理
- 数据：HAI（https://github.com/icsdataset/hai），建议固定一个版本（如 21.03 或 22.04），在报告中写明。
- 读取多个 train CSV，按时间戳拼接排序；最后 20% 作为验证集。
- 删除训练集中方差为 0 的列；删除时间戳、标签列（attack、attack_P1 等）不作为特征。
- StandardScaler 只在训练部分 fit，然后变换验证集与测试集。
- 滑窗：窗口长度 W=60（秒），训练步长 stride=10，验证/测试步长 stride=1。
- 逐秒分数定义：每个窗口的分数赋给窗口的最后一个时间点；测试集前 W-1 秒不打分。

### M2 模型
| 模型 | 结构要点 | 异常分数 |
|---|---|---|
| LSTM-AE（主模型） | 编码器 LSTM(hidden=64, 1~2 层) → 取最后隐状态 → 重复 W 次 → 解码器 LSTM → Linear 回到特征维 | 窗口 MSE（也可只取最后 k 步） |
| LSTM-VAE | 编码器输出 μ、logσ²，重参数化后解码，损失 = 重构 + β·KL | 重构误差（或负 ELBO） |
| Deep SVDD | LSTM 编码器（无 bias）映射到隐空间，最小化到中心 c 的距离，c 由初始前向均值确定 | 到 c 的距离 |
| PCA | 在展平窗口或单时刻特征上拟合，保留 95% 方差 | 重构误差 |
| IsolationForest | 在展平窗口上拟合（窗口太大时可降采样或用窗口统计特征） | -score_samples |

- 训练：Adam，lr=1e-3，早停依据验证集重构损失，固定随机种子。
- 所有模型输出统一格式：`scores.npy`（逐秒），深度重构类模型额外输出 `per_sensor_err.npy`（逐秒×逐传感器）。

### M3 阈值与评估
- 阈值：验证集分数的 99% 分位数。
- 逐点指标：Precision、Recall、F1、AUROC（AUROC 与阈值无关）。
- 事件级指标：
  - 事件检出率：攻击区间 [start, end] 内至少有一次报警即算检出。
  - 检测延迟：首次报警时间 − start（单位：秒），报告中位数与均值。
  - 误报率：正常区间内的报警段数 / 正常时长（次/小时）。连续报警合并为一段。
- 不使用 point-adjust。

### M4 消融实验
- 窗口长度 W ∈ {30, 60, 120}
- 隐层大小 ∈ {32, 64, 128}
- 可选：阈值分位 ∈ {99, 99.5, 99.9}（仅作敏感性分析，不据此选阈值）

### M5 传感器归因（连接主线与扩展的桥梁）
- 对每个报警段，计算段内各传感器重构误差的均值，取 Top-k（k=3/5）。
- 传感器名的前缀（P1_、P2_、P3_、P4_）决定其所属子系统。
- 评估：
  - 子系统级命中率：Top-1 传感器所属子系统是否与标签中受攻击的子系统一致（若所用 HAI 版本提供
    attack_P1/attack_P2/attack_P3 等列，则直接使用）。
  - 传感器级 Hit@k：若能从 HAI 官方文档的攻击场景说明中取得被攻击的点位，则计算 Top-k 是否包含该点位。
- 这一步的结果是真实可评估的，是扩展部分唯一的定量指标。

---

## 7. 扩展模块设计

### M6 资产映射（asset_map.yaml，人为构造）
为每个子系统虚构一条"控制链"，并把部分资产指向真实的靶机 IP：

```yaml
subsystems:
  P1:
    name: 锅炉过程
    criticality: 0.9          # 0~1，业务关键度
    sensor_prefix: "P1_"
    assets: [plc_p1, hmi_main, ews_01]
  P2:
    name: 汽轮机过程
    criticality: 1.0
    sensor_prefix: "P2_"
    assets: [plc_p2, hmi_main, ews_01]
  P3:
    name: 水处理过程
    criticality: 0.7
    sensor_prefix: "P3_"
    assets: [plc_p3, hmi_main, ews_02]

assets:
  ews_01:   {role: 工程师站, purdue_level: 2, ip: 192.168.56.11, scanned: true}
  ews_02:   {role: 工程师站, purdue_level: 2, ip: 192.168.56.12, scanned: true}
  hmi_main: {role: HMI,     purdue_level: 2, ip: 192.168.56.20, scanned: true}
  historian:{role: 历史服务器, purdue_level: 3, ip: 192.168.56.30, scanned: true}
  plc_p1:   {role: PLC, purdue_level: 1, ip: null, scanned: false}  # OT 实践中不主动扫描 PLC

edges:   # 可达关系：谁能向谁下发指令或写数据
  - [historian, hmi_main]
  - [ews_01, plc_p1]
  - [ews_01, plc_p2]
  - [ews_02, plc_p3]
  - [hmi_main, plc_p1]
  - [hmi_main, plc_p2]
  - [hmi_main, plc_p3]
```

设计说明：PLC 不扫描（贴近 OT 实践，主动扫描可能导致控制器故障），风险通过其上游的工程师站、
HMI 间接体现。

### M7 漏洞采集（OpenVAS）
- 靶机示例：未打补丁的 Windows 评估版（模拟工程师站）、旧版本 Ubuntu 并运行老版本 Web/SMB/FTP
  服务（模拟 HMI 与历史服务器）。所有虚拟机放在 host-only 网络。
- gmp_client.py 需实现：
  - `connect()`：优先使用 UnixSocketConnection（/run/gvmd/gvmd.sock）
  - `ensure_target(name, hosts) -> target_id`
  - `create_task(name, target_id, config="Full and fast") -> task_id`
  - `start_and_wait(task_id, poll_s=30) -> report_id`
  - `fetch_report_xml(report_id) -> bytes`
- parse_report.py 输出标准化记录（vulns.json）：

```json
{
  "asset_ip": "192.168.56.11",
  "port": "445/tcp",
  "nvt_oid": "1.3.6.1.4.1.25623.1.0.xxxxx",
  "name": "漏洞名称",
  "cvss": 9.8,
  "cves": ["CVE-XXXX-XXXX"],
  "solution": "修复建议文本",
  "qod": 80
}
```

### M8 威胁情报富化
- KEV：下载 CISA KEV 的 JSON，构建 CVE 集合。
- EPSS：调用 FIRST EPSS API 批量查询 CVE 的 epss 分数（0~1），缓存到 data/intel/。
- 每条漏洞增加字段：`in_kev: bool`、`epss: float`。

### M9 融合打分（fusion.yaml 中的参数均可调）
1. 单条漏洞风险：
   `r_v = min(1, (cvss/10) × (1 + β·epss) × (γ if in_kev else 1))`，默认 β=1，γ=1.5
2. 资产风险：`R_asset = max(r_v)`（取该资产所有漏洞的最大值；无漏洞记 0）
3. 子系统暴露风险：`E_sub = max(R_asset)`，遍历该子系统的所有上游资产（沿 edges 反向可达）
4. 异常严重度：`S = min(1, 报警段内最大分数 / 阈值 − 1)`，并截断到 [0, 1]
5. 告警优先级：`priority = S × (1 + α·E_sub) × criticality`，默认 α=1
6. 若 Top-k 传感器跨多个子系统，则按误差占比加权求和。

### M10 告警卡片（Jinja2 模板，输出 Markdown/HTML）
每张卡片包含以下字段：
- 告警 ID、起止时间、持续时长、异常分数 / 阈值
- Top-k 异常传感器及误差占比
- 推断受影响的子系统及其业务关键度
- 可能的入侵路径（沿 edges 回溯：historian → hmi_main → plc_p1）
- 路径上资产的高危漏洞（按 r_v 排序，标注 KEV/EPSS）
- 建议动作：优先排查的资产、OpenVAS 给出的修复建议
- 优先级分数与排名
- 固定免责声明："资产映射与漏洞数据来自实验环境，仅用于演示"

---

## 8. 数据契约（模块间接口）

- `scores_{model}.npy`：shape (T,)，逐秒异常分数
- `per_sensor_err.npy`：shape (T, D)，逐秒逐传感器误差
- `alerts.json`：列表，每项为 `{alert_id, start, end, max_score, threshold, topk: [{sensor, share}]}`
- `vulns.json`：见 M7
- `enriched_alerts.json`：alerts 加上 `{subsystems, E_sub, priority, path, vulns}`
- 时间戳统一使用 HAI 原始时间字符串，内部转为 pandas Timestamp

---

## 9. 时间安排

| 周 | 任务 | 产出 |
|---|---|---|
| 第 1 周 | 数据加载与预处理、滑窗、PCA/IForest 基线、评估代码 | 基线结果表、评估脚本 |
| 第 2 周 | LSTM-AE、LSTM-VAE、Deep SVDD 训练与评估 | 主结果表、分数曲线图 |
| 第 3 周前半 | 消融实验、传感器归因与命中率 | 消融表、归因评估 |
| 第 3 周后半（1~2 天） | 搭建靶机、OpenVAS 扫描、KEV/EPSS 富化、融合打分、2~3 个案例卡片 | 告警卡片、案例研究章节 |
| 收尾 | 撰写报告 | 最终报告 |

扩展部分的前置准备（安装 OpenVAS、下载靶机镜像）可以在第 1、2 周训练模型的等待时间里完成。

---

## 10. 报告结构建议

1. 引言：工控攻击数据稀缺 → 无监督检测的动机；纵深防御视角
2. 相关工作：ICS 异常检测、HAI 数据集、评估陷阱（point-adjust）
3. 方法：预处理、模型、阈值、归因
4. 实验：主结果、事件级指标、消融、归因命中率
5. 原型扩展：融合告警架构、打分公式、案例研究（明确说明数据为实验构造）
6. 讨论：局限性（单一数据集、映射是人为构造、未验证泛化）、未来工作（自建 OpenPLC 靶场形成
   "漏洞 → 攻击 → 过程异常"闭环）
7. 结论

---

## 11. 给协作 LLM 的工作约定

- 所有路径、超参从 config/*.yaml 读取，不要硬编码。
- 每个脚本提供 CLI 入口（argparse），例如 `python -m src.train --model lstm_ae`。
- 固定随机种子（numpy、torch、python random）。
- 严禁在任何调参、阈值选择代码中读取 test 数据；evaluate.py 是唯一读取 test 标签的地方。
- 评估函数对所有模型通用，输入统一为 (scores, labels, threshold)。
- 代码注释用中文，变量名用英文。
- 出现不确定的数据细节（如 HAI 某版本的列名、标签列名）时，先写检查代码打印实际列名，不要臆测。
- 扩展部分的输出一律带免责声明字段。
