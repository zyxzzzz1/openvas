"""src/vuln/intel.py 的测试：用假 session 模拟 KEV/EPSS 响应，不联网。"""

import json
import os
import time

import pytest
import requests

from src.vuln import intel
from src.vuln.intel import IntelError, enrich, make_batches, read_epss_cache

KEV_URL = "https://kev.example/feed.json"
EPSS_URL = "https://epss.example/v1/epss"
KEV = {
    "catalogVersion": "2026.09.29",
    "dateReleased": "2026-09-29T13:51:33.3852Z",
    "count": 2,
    "vulnerabilities": [{"cveID": "CVE-2015-0240"}, {"cveID": "CVE-2021-44228"}],
}
EPSS_DB = {"CVE-2015-0240": "0.880080000", "CVE-2011-2523": "0.945000000", "CVE-2012-1823": "0.050000000"}


class FakeResp:
    def __init__(self, status: int, body: dict | None = None):
        self.status_code = status
        self._body = body

    def json(self):
        return self._body


class FakeSession:
    """按 URL 分发的假 session；fail 为待消费的失败序列（异常或状态码）。"""

    def __init__(self, fail=()):
        self.calls = []
        self.fail = list(fail)

    def get(self, url, params=None, timeout=None):
        assert timeout is not None, "请求必须设置超时"
        self.calls.append((url, params))
        if self.fail:
            f = self.fail.pop(0)
            if isinstance(f, Exception):
                raise f
            return FakeResp(f)
        if url == KEV_URL:
            return FakeResp(200, KEV)
        cves = params["cve"].split(",")
        data = [{"cve": c, "epss": EPSS_DB[c], "percentile": "0.99", "date": "2026-09-29"}
                for c in cves if c in EPSS_DB]
        return FakeResp(200, {"status": "OK", "total": len(data), "offset": 0,
                              "limit": params["limit"], "data": data})

    def epss_calls(self):
        return [c for c in self.calls if c[0] == EPSS_URL]


@pytest.fixture
def cfg(tmp_path):
    return {
        "kev_url": KEV_URL, "kev_cache": str(tmp_path / "intel" / "kev.json"), "kev_max_age_hours": 24,
        "epss_url": EPSS_URL, "epss_cache": str(tmp_path / "intel" / "epss.csv"),
        "epss_max_param_chars": 2000, "epss_batch_size": 100,
        "timeout_s": 5, "retries": 2, "backoff_s": 0,
    }


def vulns(*cve_lists):
    return {"disclaimer": "x", "stats": {}, "vulns": [
        {"name": f"v{i}", "cvss": 9.0, "cves": list(c)} for i, c in enumerate(cve_lists)]}


def test_enrich_fields(cfg):
    data = vulns(["CVE-2015-0240", "CVE-2012-1823"], ["CVE-2011-2523"], [], ["CVE-1999-0001"])
    out = enrich(data, cfg, session=FakeSession())
    v0, v1, v2, v3 = out["vulns"]
    # 多 CVE：in_kev 任一为真，epss 取最大
    assert v0["in_kev"] is True and v0["kev_cves"] == ["CVE-2015-0240"] and v0["epss"] == pytest.approx(0.88008)
    assert v1["in_kev"] is False and v1["kev_cves"] == [] and v1["epss"] == pytest.approx(0.945)
    # 无 CVE / EPSS 无记录
    assert (v2["in_kev"], v2["epss"], v2["kev_cves"]) == (False, 0.0, [])
    assert v3["epss"] == 0.0
    # 原字段保留，输入不被修改
    assert v0["name"] == "v0" and "in_kev" not in data["vulns"][0]
    info = out["intel"]
    assert info["cves_in_kev"] == ["CVE-2015-0240"]
    assert info["cves_without_epss"] == ["CVE-1999-0001"]
    assert info["epss_dates"] == ["2026-09-29"]
    assert info["kev_catalog_version"] == "2026.09.29"
    assert out["disclaimer"] == intel.DISCLAIMER


def test_epss_cache_written_and_reused(cfg, tmp_path):
    s1 = FakeSession()
    enrich(vulns(["CVE-2015-0240", "CVE-1999-0001"]), cfg, session=s1)
    rows = read_epss_cache(tmp_path / "intel" / "epss.csv")
    assert rows["CVE-2015-0240"]["date"] == "2026-09-29"
    assert rows["CVE-2015-0240"]["fetched_at"]
    assert rows["CVE-1999-0001"]["epss"] == ""  # 无记录也缓存，避免重复查询

    # 第二次：已缓存的不再查询，只查新增的 CVE
    s2 = FakeSession()
    enrich(vulns(["CVE-2015-0240", "CVE-1999-0001", "CVE-2011-2523"]), cfg, session=s2)
    assert [p["cve"] for _, p in s2.epss_calls()] == ["CVE-2011-2523"]
    s3 = FakeSession()
    enrich(vulns(["CVE-2015-0240"]), cfg, session=s3)
    assert s3.epss_calls() == []


def test_batches_respect_limits():
    cves = [f"CVE-2020-{i:05d}" for i in range(1086)]
    for batch in make_batches(cves, 2000, 100):
        assert len(",".join(batch)) <= 2000 and len(batch) <= 100
    assert sum(len(b) for b in make_batches(cves, 2000, 100)) == 1086
    # 字符数先到上限的情况
    small = make_batches(cves, 100, 1000)
    assert all(len(",".join(b)) <= 100 for b in small)
    assert [c for b in small for c in b] == cves


def test_epss_request_batching(cfg):
    cves = [f"CVE-2020-{i:05d}" for i in range(250)]
    s = FakeSession()
    enrich(vulns(cves), cfg, session=s)
    calls = s.epss_calls()
    assert len(calls) == 3
    for _, params in calls:
        n = len(params["cve"].split(","))
        assert n <= 100 and params["limit"] == n and len(params["cve"]) <= 2000


def test_kev_cache_age(cfg, tmp_path):
    s1 = FakeSession()
    enrich(vulns(["CVE-2015-0240"]), cfg, session=s1)
    assert sum(u == KEV_URL for u, _ in s1.calls) == 1
    # 缓存未过期：不下载
    s2 = FakeSession()
    enrich(vulns(["CVE-2015-0240"]), cfg, session=s2)
    assert all(u != KEV_URL for u, _ in s2.calls)
    # 缓存超过 24 小时：重新下载
    kev_path = tmp_path / "intel" / "kev.json"
    old = time.time() - 25 * 3600
    os.utime(kev_path, (old, old))
    s3 = FakeSession()
    enrich(vulns(["CVE-2015-0240"]), cfg, session=s3)
    assert sum(u == KEV_URL for u, _ in s3.calls) == 1


def test_offline_uses_cache_only(cfg, tmp_path):
    enrich(vulns(["CVE-2015-0240"]), cfg, session=FakeSession())
    kev_path = tmp_path / "intel" / "kev.json"
    old = time.time() - 48 * 3600
    os.utime(kev_path, (old, old))  # 即使过期，离线也用缓存
    s = FakeSession()
    out = enrich(vulns(["CVE-2015-0240"]), cfg, session=s, offline=True)
    assert s.calls == [] and out["vulns"][0]["in_kev"] is True


def test_offline_missing_cache_raises(cfg):
    with pytest.raises(IntelError, match="KEV 缓存不存在"):
        enrich(vulns(["CVE-2015-0240"]), cfg, session=FakeSession(), offline=True)
    enrich(vulns(["CVE-2015-0240"]), cfg, session=FakeSession())
    with pytest.raises(IntelError, match="EPSS 缓存缺少 1 个"):
        enrich(vulns(["CVE-2011-2523"]), cfg, session=FakeSession(), offline=True)


def test_retry_then_success(cfg):
    s = FakeSession(fail=[requests.Timeout("t"), 503])
    out = enrich(vulns(["CVE-2015-0240"]), cfg, session=s)
    assert out["vulns"][0]["in_kev"] is True
    assert [u for u, _ in s.calls][:3] == [KEV_URL] * 3


def test_retry_exhausted_raises(cfg):
    s = FakeSession(fail=[requests.ConnectionError("x")] * 3)
    with pytest.raises(IntelError, match="已重试 2 次"):
        enrich(vulns(["CVE-2015-0240"]), cfg, session=s)
    assert len(s.calls) == 3


def test_client_error_not_retried(cfg):
    s = FakeSession(fail=[404])
    with pytest.raises(IntelError, match="HTTP 404"):
        enrich(vulns(["CVE-2015-0240"]), cfg, session=s)
    assert len(s.calls) == 1


def test_epss_truncated_page_raises(cfg):
    class Truncating(FakeSession):
        def get(self, url, params=None, timeout=None):
            r = super().get(url, params, timeout)
            if url == EPSS_URL:
                r._body["total"] = len(r._body["data"]) + 1
            return r

    with pytest.raises(IntelError, match="分页截断"):
        enrich(vulns(["CVE-2015-0240"]), cfg, session=Truncating())
