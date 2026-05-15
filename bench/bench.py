#!/usr/bin/env python3
"""
generate_benchmark.py · SHA Benchmark HTML
#
#
Usage:
    python3 bench.py
    python3 bench.py --input other_name.json --output ma_page.html
"""

import argparse
import json
import sys
from pathlib import Path

# Mapping implementation (bench.sh) / provider key interne
IMPL_TO_PROVIDER = {
    "openssl":     "sw",
    "st_afalg":    "afalg",
    "st_cryptodev":"cryptodev",
    "engine":      "engine",
}

PROVIDER_ORDER = ["afalg", "cryptodev", "engine", "sw"]

PROVIDER_NAMES = {
    "afalg":     "st_afalg",
    "cryptodev": "st_cryptodev",
    "engine":    "engine devcrypto",
    "sw":        "default SW",
}

PROVIDER_COLORS = {
    "afalg":     "#378ADD",
    "cryptodev": "#1D9E75",
    "engine":    "#BA7517",
    "sw":        "#888780",
}

ALGOS = ["sha1", "sha256", "sha512"]

PAGE_CHIP     = "STM32MP257 EV1 · OpenSSL 3.2.6 · AArch64 · Cortex-A35"
PAGE_TITLE    = "SHA Provider Benchmark"
PAGE_SUBTITLE = "Throughput + impact CPU : Provider AF_ALG · Provider Cryptodev · Legacy Engine Cryptodev · software"
PAGE_FOOTER   = "openssl speed -seconds N -bytes N -elapsed -Implementation"

DEFAULT_INPUT  = "bench_results.json"
DEFAULT_OUTPUT = "st_sha_benchmark.html"

# HELPERS
def fmt_bytes_label(b):
    if b >= 1048576:
        v = b / 1048576
        return f"{int(v)}MB" if v == int(v) else f"{v:.1f}MB"
    if b >= 1024:
        v = b / 1024
        return f"{int(v)}KB" if v == int(v) else f"{v:.1f}KB"
    return f"{b}B"

def to_js_array(lst):
    def val(v):
        return "null" if v is None else str(round(v, 4) if isinstance(v, float) else v)
    return "[" + ", ".join(val(v) for v in lst) + "]"

# PARSE bench_results.json

def build_data(results):
    # (provider, block_bytes) ==> block dict
    idx = {}
    for run in results:
        impl     = run.get("implementation", "")
        provider = IMPL_TO_PROVIDER.get(impl, impl)
        for block in run.get("blocks", []):
            idx[(provider, block["block_bytes"])] = block

    sizes     = sorted(set(k[1] for k in idx))
    providers = [p for p in PROVIDER_ORDER if any(k[0] == p for k in idx)]

    # Throughput  data[provider][algo] = [kbps, ...] 
    data = {}
    for p in providers:
        data[p] = {}
        for algo in ALGOS:
            data[p][algo] = [
                (idx.get((p, b)) or {}).get(algo, {}).get("kbps")
                for b in sizes
            ]

    # cpu[provider][algo]{core0,core1,total} = [...] 
    cpu = {}
    for p in providers:
        cpu[p] = {}
        for algo in ALGOS:
            cpu[p][algo] = {"core0": [], "core1": [], "total": []}
            for b in sizes:
                ad = (idx.get((p, b)) or {}).get(algo) or {}
                c0 = ad.get("cpu0")
                c1 = ad.get("cpu1")
                tot = round((c0 + c1) / 2, 2) if c0 is not None and c1 is not None else None
                cpu[p][algo]["core0"].append(c0)
                cpu[p][algo]["core1"].append(c1)
                cpu[p][algo]["total"].append(tot)

    # perf[provider][algo]{ipc,cycles} = [...] 
    has_perf = any(
        (idx.get((p, b)) or {}).get(algo, {}).get("cycles")
        for p in providers for b in sizes for algo in ALGOS
    )
    perf = None
    if has_perf:
        perf = {}
        for p in providers:
            perf[p] = {}
            for algo in ALGOS:
                perf[p][algo] = {"ipc": [], "cycles": []}
                for b in sizes:
                    ad = (idx.get((p, b)) or {}).get(algo) or {}
                    cy = ad.get("cycles")
                    ins = ad.get("instructions")
                    ipc = round(ins / cy, 2) if cy and ins and cy > 0 else None
                    perf[p][algo]["ipc"].append(ipc)
                    perf[p][algo]["cycles"].append(cy)

    return {
        "sizes":     sizes,
        "labels":    [fmt_bytes_label(b) for b in sizes],
        "providers": providers,
        "data":      data,
        "cpu":       cpu,
        "perf":      perf,
        "has_perf":  has_perf,
    }


def build_js_vars(d):
    providers = d["providers"]
    lines = []

    lines.append(f"const sizes      = {json.dumps(d['sizes'])};")
    lines.append(f"const sizeLabels = {json.dumps(d['labels'])};")
    lines.append(f"const providers  = {json.dumps(providers)};")
    lines.append(f"const names      = {json.dumps({p: PROVIDER_NAMES[p]  for p in providers})};")
    lines.append(f"const colors     = {json.dumps({p: PROVIDER_COLORS[p] for p in providers})};")
    lines.append(f"const algos      = {json.dumps(ALGOS)};")
    lines.append(f"const hasPerf    = {'true' if d['has_perf'] else 'false'};")

    # data[provider][algo] = [...]
    lines.append("const data = {")
    for p in providers:
        lines.append(f"  {p}: {{")
        for algo in ALGOS:
            lines.append(f"    {algo}: {to_js_array(d['data'][p][algo])},")
        lines.append("  },")
    lines.append("};")

    # cpuData[provider][algo] = {core0, core1, total}
    lines.append("const cpuData = {")
    for p in providers:
        lines.append(f"  {p}: {{")
        for algo in ALGOS:
            lines.append(f"    {algo}: {{")
            for key in ["core0", "core1", "total"]:
                lines.append(f"      {key}: {to_js_array(d['cpu'][p][algo][key])},")
            lines.append("    },")
        lines.append("  },")
    lines.append("};")

    # perfData[provider][algo] = {ipc, cycles}
    if d["perf"]:
        lines.append("const perfData = {")
        for p in providers:
            lines.append(f"  {p}: {{")
            for algo in ALGOS:
                lines.append(f"    {algo}: {{")
                for key in ["ipc", "cycles"]:
                    lines.append(f"      {key}: {to_js_array(d['perf'][p][algo][key])},")
                lines.append("    },")
            lines.append("  },")
        lines.append("};")
    else:
        lines.append("const perfData = null;")

    return "\n".join(lines)


def generate_html(results):
    d = build_data(results)
    js_vars = build_js_vars(d)
    default_idx = max(0, len(d["sizes"]) - 3)

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{PAGE_TITLE}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600;700&display=swap');

  *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
  :root{{
    --bg:#020617;--bg2:#07111f;--panel:rgba(15,23,42,.68);--panel2:rgba(2,6,23,.78);
    --stroke:rgba(148,163,184,.18);--stroke2:rgba(56,189,248,.35);--text:#eef7ff;--muted:#8aa4b8;
    --cyan:#38bdf8;--green:#34d399;--amber:#f59e0b;--violet:#a78bfa;--red:#fb7185;
    --radius:26px;--shadow:0 28px 90px rgba(0,0,0,.55);
  }}
  html{{scroll-behavior:smooth;}}
  body{{
    min-height:100vh;color:var(--text);
    font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
    background:
      radial-gradient(circle at 14% 12%,rgba(56,189,248,.24),transparent 28%),
      radial-gradient(circle at 88% 18%,rgba(167,139,250,.22),transparent 30%),
      radial-gradient(circle at 50% 95%,rgba(52,211,153,.12),transparent 35%),
      linear-gradient(135deg,#020617 0%,#08111f 45%,#020617 100%);
    background-size:140% 140%,130% 130%,150% 150%,100% 100%;
    animation:bgDrift 22s ease-in-out infinite alternate;
    overflow-x:hidden;padding:28px;
  }}
  body::before{{
    content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
    background-image:linear-gradient(rgba(56,189,248,.055) 1px,transparent 1px),linear-gradient(90deg,rgba(56,189,248,.055) 1px,transparent 1px);
    background-size:44px 44px;mask-image:linear-gradient(to bottom,rgba(0,0,0,.75),transparent 85%);animation:gridMove 18s linear infinite;
  }}
  body::after{{content:"";position:fixed;inset:0;pointer-events:none;z-index:30;background:linear-gradient(rgba(255,255,255,.025) 50%,rgba(0,0,0,.025) 50%);background-size:100% 4px;mix-blend-mode:overlay;opacity:.35;}}
  .bg-circuit{{
    position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.72;
    background-image:
      linear-gradient(90deg,transparent 0 48%,rgba(56,189,248,.34) 49%,transparent 51% 100%),
      linear-gradient(0deg,transparent 0 48%,rgba(52,211,153,.24) 49%,transparent 51% 100%);
    background-size:150px 100px,190px 130px;
    mask-image:radial-gradient(circle at 50% 35%,black 0 45%,transparent 82%);
    animation:circuitFlow 16s linear infinite;
  }}
  @keyframes gridMove{{to{{background-position:44px 44px;}}}}
  @keyframes bgDrift{{
    0%{{background-position:0% 0%,100% 0%,50% 100%,0 0;}}
    50%{{background-position:12% 8%,86% 18%,45% 82%,0 0;}}
    100%{{background-position:24% 14%,72% 8%,56% 72%,0 0;}}
  }}
  @keyframes circuitFlow{{
    0%{{background-position:0 0,0 0;opacity:.18;}}
    50%{{opacity:.34;}}
    100%{{background-position:180px 120px,-180px 80px;opacity:.18;}}
  }}
  @keyframes pulseGlow{{0%,100%{{opacity:.55;transform:scale(1)}}50%{{opacity:1;transform:scale(1.05)}}}}
  @keyframes sweep{{0%{{transform:translateX(-120%)}}100%{{transform:translateX(120%)}}}}
  #particle-canvas{{position:fixed;inset:0;z-index:1;pointer-events:none;opacity:.98;mix-blend-mode:screen;}}
  .wrap{{max-width:1480px;margin:0 auto;position:relative;z-index:2;}}
  .hero{{
    position:relative;overflow:hidden;min-height:330px;border:1px solid var(--stroke2);
    border-radius:34px;padding:34px;margin-bottom:22px;
    background:linear-gradient(135deg,rgba(15,23,42,.86),rgba(2,6,23,.58)),radial-gradient(circle at 25% 20%,rgba(56,189,248,.26),transparent 36%),radial-gradient(circle at 88% 14%,rgba(167,139,250,.2),transparent 30%);
    box-shadow:var(--shadow),inset 0 1px 0 rgba(255,255,255,.08);
  }}
  .hero::before{{content:"";position:absolute;inset:-2px;background:linear-gradient(90deg,transparent,rgba(56,189,248,.28),transparent);animation:sweep 6s ease-in-out infinite;}}
  .hero-inner{{position:relative;z-index:1;display:grid;grid-template-columns:minmax(0,1.2fr) 420px;gap:26px;align-items:stretch;}}
  @media(max-width:1050px){{.hero-inner{{grid-template-columns:1fr;}}body{{padding:16px;}}}}
  .chiprow{{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:22px;}}
  .chip{{display:inline-flex;align-items:center;gap:8px;border:1px solid rgba(56,189,248,.28);background:rgba(14,165,233,.09);color:#bae6fd;border-radius:999px;padding:8px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;box-shadow:0 0 28px rgba(56,189,248,.12);}}
  .chip .dot{{width:8px;height:8px;border-radius:999px;background:var(--green);box-shadow:0 0 16px var(--green);animation:pulseGlow 1.8s infinite;}}
  h1{{font-size:clamp(38px,7vw,86px);line-height:.92;font-weight:900;letter-spacing:-.075em;margin-bottom:18px;background:linear-gradient(110deg,#fff 0%,#7dd3fc 32%,#c4b5fd 65%,#fff 100%);-webkit-background-clip:text;background-clip:text;color:transparent;}}
  .subtitle{{max-width:760px;color:#b8c7d7;font-size:17px;line-height:1.7;}}
  .hero-actions{{display:flex;gap:12px;flex-wrap:wrap;margin-top:26px;}}
  .pill{{border:1px solid var(--stroke);border-radius:999px;background:rgba(255,255,255,.04);padding:10px 14px;color:#dbeafe;font-family:'JetBrains Mono',monospace;font-size:12px;}}
  .terminal{{position:relative;border-radius:24px;border:1px solid rgba(56,189,248,.2);background:rgba(2,6,23,.86);box-shadow:0 24px 70px rgba(0,0,0,.38),0 0 50px rgba(56,189,248,.08);overflow:hidden;min-height:260px;}}
  .termbar{{height:42px;display:flex;align-items:center;gap:8px;padding:0 14px;border-bottom:1px solid rgba(148,163,184,.14);background:rgba(255,255,255,.035);}}
  .led{{width:11px;height:11px;border-radius:50%;background:var(--red);box-shadow:0 0 14px currentColor;}}.led.y{{background:var(--amber)}}.led.g{{background:var(--green)}}
  .term-body{{padding:18px;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.75;color:#b6e7ff;}}
  .prompt{{color:#34d399}}.cmd{{color:#e0f2fe}}.comment{{color:#64748b}}.cursor{{display:inline-block;width:9px;height:16px;background:#38bdf8;vertical-align:-3px;animation:pulseGlow .9s infinite;}}
  .controls{{
    position:sticky;top:14px;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;
    margin-bottom:22px;padding:14px;border:1px solid var(--stroke);border-radius:24px;background:rgba(2,6,23,.72);
    backdrop-filter:blur(22px);box-shadow:0 14px 60px rgba(0,0,0,.28);
  }}
  .ctrl-group{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}}
  .ctrl-label{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#7dd3fc;text-transform:uppercase;letter-spacing:.12em;}}
  .btn-group{{display:flex;gap:6px;flex-wrap:wrap;}}
  .btn{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#94a3b8;border:1px solid rgba(148,163,184,.18);background:linear-gradient(180deg,rgba(255,255,255,.055),rgba(255,255,255,.015));border-radius:14px;padding:9px 11px;cursor:pointer;transition:transform .18s ease,border-color .18s ease,box-shadow .18s ease,color .18s ease;}}
  .btn:hover{{transform:translateY(-2px);color:#fff;border-color:rgba(56,189,248,.44);box-shadow:0 0 24px rgba(56,189,248,.12);}}
  .btn.active{{color:#020617;background:linear-gradient(135deg,#38bdf8,#a78bfa);border-color:transparent;box-shadow:0 0 30px rgba(56,189,248,.32);}}
  .kpi-grid{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-bottom:22px;}}
  @media(max-width:1100px){{.kpi-grid{{grid-template-columns:repeat(2,1fr);}}}}@media(max-width:620px){{.kpi-grid{{grid-template-columns:1fr;}}}}
  .kpi{{position:relative;overflow:hidden;border-radius:26px;border:1px solid var(--stroke);background:linear-gradient(180deg,rgba(15,23,42,.75),rgba(2,6,23,.72));padding:22px;box-shadow:0 18px 70px rgba(0,0,0,.3);min-height:165px;transition:transform .25s ease,border-color .25s ease,box-shadow .25s ease;}}
  .kpi:hover{{transform:translateY(-6px);border-color:var(--kpi-color);box-shadow:0 24px 90px rgba(0,0,0,.42),0 0 42px color-mix(in srgb,var(--kpi-color),transparent 70%);}}
  .kpi::after{{content:"";position:absolute;width:150px;height:150px;right:-55px;top:-55px;border-radius:50%;background:var(--kpi-color);opacity:.12;filter:blur(10px);}}
  .kpi-name{{font-family:'JetBrains Mono',monospace;font-size:12px;color:#9fb6ca;margin-bottom:18px;}}
  .kpi-main{{font-size:31px;font-weight:900;letter-spacing:-.04em;color:#fff;margin-bottom:8px;}}
  .kpi-sub{{font-family:'JetBrains Mono',monospace;color:#7890a4;font-size:11px;}}
  .rank{{position:absolute;right:18px;bottom:18px;font-family:'JetBrains Mono',monospace;color:var(--kpi-color);font-weight:700;font-size:12px;}}
  .main-grid{{display:grid;grid-template-columns:1.05fr .95fr;gap:18px;margin-bottom:18px;align-items:start;}}
  .wide-grid{{display:grid;grid-template-columns:1fr;gap:18px;margin-bottom:18px;}}
  .dual-grid{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px;}}
  .cpu-wide-grid{{display:grid;grid-template-columns:1fr;gap:18px;margin-bottom:18px;}}
  .cpu-wide-grid .chart-box.lg{{height:430px;}}
  @media(max-width:1050px){{.main-grid{{grid-template-columns:1fr;}}.dual-grid{{grid-template-columns:1fr;}}}}
  .panel{{position:relative;overflow:hidden;border-radius:28px;border:1px solid var(--stroke);background:rgba(15,23,42,.60);backdrop-filter:blur(18px);box-shadow:0 20px 85px rgba(0,0,0,.35);padding:22px;}}
  .panel::before{{content:"";position:absolute;inset:0;background:radial-gradient(circle at 20% 0%,rgba(56,189,248,.12),transparent 28%);pointer-events:none;}}
  .panel-head{{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:16px;}}
  .panel-title{{font-size:16px;font-weight:800;letter-spacing:-.02em;}}
  .panel-sub{{margin-top:4px;color:#7890a4;font-family:'JetBrains Mono',monospace;font-size:11px;}}
  .panel-tag{{border:1px solid rgba(56,189,248,.25);color:#7dd3fc;border-radius:999px;padding:7px 10px;font-family:'JetBrains Mono',monospace;font-size:11px;background:rgba(56,189,248,.08);white-space:nowrap;}}
  .chart-box{{position:relative;height:330px;display:flex;align-items:flex-start;}}
  .chart-box canvas{{width:100%!important;height:100%!important;}}
  .chart-box.sm{{height:255px;}}
  .chart-box.lg{{height:390px;}}
  .gauge-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;}}
  @media(max-width:620px){{.gauge-grid{{grid-template-columns:1fr;}}}}
  .gauge-card{{position:relative;border:1px solid rgba(148,163,184,.16);background:rgba(2,6,23,.42);border-radius:24px;padding:16px;min-height:250px;}}
  .gauge-provider{{display:flex;align-items:center;justify-content:space-between;gap:10px;font-weight:800;color:#fff;margin-bottom:14px;}}
  .gauge-provider .g-dot{{width:10px;height:10px;border-radius:50%;background:var(--gcol);box-shadow:0 0 18px var(--gcol);display:inline-block;margin-right:8px;}}
  .gauge-row{{display:grid;grid-template-columns:1fr 1fr;gap:12px;align-items:start;}}
  .mini-gauge-box{{border:1px solid rgba(148,163,184,.12);background:rgba(15,23,42,.32);border-radius:18px;padding:12px 8px;text-align:center;}}
  .gauge{{--val:0;--col:#38bdf8;width:118px;height:118px;border-radius:50%;margin:0 auto 10px;display:grid;place-items:center;background:conic-gradient(var(--col) calc(var(--val)*1%),rgba(148,163,184,.12) 0);box-shadow:0 0 35px color-mix(in srgb,var(--col),transparent 74%);position:relative;}}
  .gauge::before{{content:"";width:84px;height:84px;border-radius:50%;background:#07111f;border:1px solid rgba(255,255,255,.08);position:absolute;}}
  .gauge span{{position:relative;z-index:1;font-size:22px;font-weight:900;}}
  .gauge-title{{font-family:'JetBrains Mono',monospace;font-size:11px;color:#91a8ba;text-align:center;text-transform:uppercase;letter-spacing:.05em;}}
  .gauge-total{{margin-top:12px;border:1px solid rgba(148,163,184,.13);border-radius:16px;background:rgba(2,6,23,.36);padding:10px 12px;display:flex;justify-content:space-between;align-items:center;font-family:'JetBrains Mono',monospace;color:#91a8ba;font-size:11px;}}
  .gauge-total strong{{font-size:15px;color:#e5f4ff;}}
  .providers-panel{{border:1px solid rgba(56,189,248,.36);border-radius:10px;background:linear-gradient(180deg,rgba(2,6,23,.56),rgba(2,6,23,.38));box-shadow:0 0 36px rgba(56,189,248,.08),inset 0 1px 0 rgba(255,255,255,.04);padding:18px;margin-bottom:18px;}}
  .providers-head{{display:flex;align-items:baseline;gap:8px;margin-bottom:16px;font-family:'JetBrains Mono',monospace;text-transform:uppercase;letter-spacing:.08em;color:#eaf6ff;font-weight:800;font-size:18px;}}
  .providers-head small{{font-size:11px;color:#93c5fd;letter-spacing:.04em;}}
  .provider-strip{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:18px;}}
  @media(max-width:1100px){{.provider-strip{{grid-template-columns:repeat(2,1fr);}}}}@media(max-width:640px){{.provider-strip{{grid-template-columns:1fr;}}}}
  .provider-card{{border:1px solid color-mix(in srgb,var(--pcol),transparent 46%);background:linear-gradient(180deg,rgba(15,23,42,.64),rgba(2,6,23,.66));border-radius:10px;padding:18px;position:relative;overflow:hidden;min-height:280px;transition:transform .22s ease,border-color .22s ease,box-shadow .22s ease;}}
  .provider-card:hover{{transform:translateY(-5px);border-color:var(--pcol);box-shadow:0 22px 70px rgba(0,0,0,.38),0 0 34px color-mix(in srgb,var(--pcol),transparent 70%);}}
  .provider-card::after{{content:"";position:absolute;inset:auto -40px -55px auto;width:190px;height:190px;border-radius:50%;background:var(--pcol);opacity:.11;filter:blur(10px);}}
  .provider-top{{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;position:relative;z-index:1;}}
  .p-left{{display:flex;align-items:center;gap:9px;min-width:0;}}
  .p-name{{font-size:16px;font-weight:800;color:#f8fbff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
  .p-dot{{width:12px;height:12px;border-radius:50%;background:var(--pcol);box-shadow:0 0 18px var(--pcol);flex-shrink:0;}}
  .p-dot.dim{{opacity:.25;filter:grayscale(1);}}
  .p-value{{font-size:28px;font-weight:900;letter-spacing:-.04em;color:#fff;margin:22px 0 4px;position:relative;z-index:1;}}
  .p-value .unit{{font-size:20px;font-weight:500;color:#cfefff;margin-left:4px;}}
  .p-ratio{{position:absolute;right:18px;top:84px;font-size:24px;font-weight:900;color:var(--pcol);z-index:1;}}
  .p-ratio small{{display:block;font-size:11px;font-family:'JetBrains Mono',monospace;color:#8fa4b8;text-align:right;margin-top:4px;font-weight:500;}}
  .p-label{{font-family:'JetBrains Mono',monospace;color:#8bc7d7;font-size:11px;text-transform:uppercase;margin-top:6px;position:relative;z-index:1;}}
  .p-metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:26px;position:relative;z-index:1;}}
  .p-metric{{border-left:1px solid rgba(148,163,184,.16);padding-left:10px;}}
  .p-metric:first-child{{border-left:0;padding-left:0;}}
  .p-metric span{{display:block;font-family:'JetBrains Mono',monospace;font-size:10px;color:#83a0b4;text-transform:uppercase;}}
  .p-metric strong{{display:block;margin-top:7px;color:#eef7ff;font-size:18px;font-weight:500;}}
  .p-badge{{display:inline-flex;align-items:center;gap:6px;border:1px solid color-mix(in srgb,var(--pcol),transparent 46%);background:color-mix(in srgb,var(--pcol),transparent 86%);color:var(--pcol);border-radius:999px;padding:5px 8px;font-family:'JetBrains Mono',monospace;font-weight:800;font-size:10px;position:relative;z-index:1;}}
  .spark{{height:56px;margin-top:22px;position:relative;z-index:1;}}
  .spark svg{{width:100%;height:100%;display:block;filter:drop-shadow(0 0 8px color-mix(in srgb,var(--pcol),transparent 52%));}}
  .p-footer{{margin:12px -18px -18px;padding:12px 18px;text-align:center;font-family:'JetBrains Mono',monospace;text-transform:uppercase;font-size:12px;color:var(--pcol);background:linear-gradient(180deg,transparent,color-mix(in srgb,var(--pcol),transparent 92%));position:relative;z-index:1;}}
  footer{{margin:34px 0 10px;text-align:center;color:#64748b;font-family:'JetBrains Mono',monospace;font-size:12px;}}
</style>
</head>
<body>
<canvas id="particle-canvas"></canvas>
<div class="bg-circuit"></div>
<div class="wrap">
  <section class="hero">
    <div class="hero-inner">
      <div>
        <div class="chiprow">
          <div class="chip"><span class="dot"></span>{PAGE_CHIP}</div>
          <div class="chip">JSON REPORT</div>
        </div>
        <h1>Crypto Hash<br>Benchmark </h1>
        <p class="subtitle">{PAGE_SUBTITLE}</p>
        <div class="hero-actions">
          <div class="pill">selected: <span id="heroSelected">—</span></div>
          <div class="pill">best provider: <span id="heroBest">—</span></div>
          <div class="pill">runs: <span id="heroRuns">—</span></div>
          <div class="pill">sizes: <span id="termSizes">—</span></div>
        </div>
      </div>
      <div class="terminal">
        <div class="termbar"><span class="led"></span><span class="led y"></span><span class="led g"></span></div>
        <div class="term-body">
          <div><span class="prompt">maho@stm32mp257</span>:<span class="cmd">~/bench</span>$ ./bench.sh </div>
          <div class="comment"># Starting benchmark for </div>
          <div class="comment"># Software implementation (OpenSSL)</div>
          <div class="comment"># ST provider via AF_ALG interface</div>
          <div class="comment"># ST provider via Cryptodev interface</div>
          <div class="comment"># Legacy Engine (devcrypto)</div>
          <div>&gt; bytes sweep: <span id="termSizes2">—</span></div>
          <div>&gt; run <span class="cursor"></span></div>
        </div>
      </div>
    </div>
  </section>

  <div class="controls">
    <div class="ctrl-group"><span class="ctrl-label">Block size</span><div class="btn-group" id="btnBytes"></div></div>
    <div class="ctrl-group"><span class="ctrl-label">Algorithm</span><div class="btn-group" id="btnAlgo"></div></div>
  </div>

  <section class="kpi-grid" id="metrics"></section>

  <section class="providers-panel">
    <div class="providers-head">Providers Overview <small>(real data)</small></div>
    <div class="provider-strip" id="providerStrip"></div>
  </section>

  <section class="main-grid">
    <div class="panel race-panel">
      <div class="panel-head"><div><div class="panel-title">Throughput Race</div><div class="panel-sub" id="sub1">—</div></div><div class="panel-tag">KB/s</div></div>
      <div class="chart-box"><canvas id="c1"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">CPU Pressure Gauges</div><div class="panel-sub" id="subGauge">Core 0 / Core 1</div></div><div class="panel-tag">JSON avg</div></div>
      <div class="gauge-grid" id="gauges"></div>
    </div>
  </section>

  <section class="main-grid">
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">Ratio vs Software</div><div class="panel-sub" id="sub2">—</div></div><div class="panel-tag">%</div></div>
      <div class="chart-box sm"><canvas id="c2"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">Core Usage Split</div><div class="panel-sub" id="sub3">—</div></div><div class="panel-tag">dual core</div></div>
      <div class="chart-box sm"><canvas id="c3"></canvas></div>
    </div>
  </section>

  <section class="wide-grid">
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">Throughput Evolution by Block Size</div><div class="panel-sub" id="sub4">—</div></div><div class="panel-tag">performance curve</div></div>
      <div class="chart-box lg"><canvas id="c4"></canvas></div>
    </div>
  </section>

  <section class="cpu-wide-grid">
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">CPU Evolution · Core 0</div><div class="panel-sub" id="sub5">—</div></div><div class="panel-tag">core 0</div></div>
      <div class="chart-box lg"><canvas id="c5"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">CPU Evolution · Core 1</div><div class="panel-sub" id="sub6">—</div></div><div class="panel-tag">core 1</div></div>
      <div class="chart-box lg"><canvas id="c6"></canvas></div>
    </div>
    <div class="panel">
      <div class="panel-head"><div><div class="panel-title">CPU Evolution · Average Core 0 / Core 1</div><div class="panel-sub" id="sub7">—</div></div><div class="panel-tag">avg cpu</div></div>
      <div class="chart-box lg"><canvas id="c7"></canvas></div>
    </div>
  </section>

  <footer>{PAGE_FOOTER}</footer>
</div>

<script>
{js_vars}
let selBytes = {default_idx};
let selAlgo = 1;
const ALGO_LABELS = {{sha1:'SHA-1', sha256:'SHA-256', sha512:'SHA-512'}};
let c1,c2,c3,c4,c5,c6,c7;

function fmtKbs(v){{ if(v===null||v===undefined) return '—'; return v>=1000?(v/1000).toFixed(1)+' MB/s':v.toFixed(0)+' KB/s'; }}
function fmtPct(v){{ return (v===null||v===undefined)?'—':v.toFixed(1)+'%'; }}
function alpha(hex,a){{ const r=parseInt(hex.slice(1,3),16),g=parseInt(hex.slice(3,5),16),b=parseInt(hex.slice(5,7),16); return `rgba(${{r}},${{g}},${{b}},${{a}})`; }}
function tickStyle(size=11){{ return {{color:'#8aa4b8',font:{{family:'JetBrains Mono',size}}}}; }}
function gridOpts(){{ return {{color:'rgba(148,163,184,.08)'}}; }}
function chartBase(){{ return {{responsive:true,maintainAspectRatio:false,animation:{{duration:900,easing:'easeOutQuart'}},plugins:{{legend:{{labels:{{color:'#b8c7d7',font:{{family:'JetBrains Mono',size:11}}}}}},tooltip:{{backgroundColor:'rgba(2,6,23,.92)',borderColor:'rgba(56,189,248,.35)',borderWidth:1,titleColor:'#fff',bodyColor:'#cbd5e1',padding:12}}}}}}; }}

function getCpu(p,algo,bi,key){{ return cpuData?.[p]?.[algo]?.[key]?.[bi] ?? null; }}
function getPerf(p,algo,bi,key){{ return perfData?.[p]?.[algo]?.[key]?.[bi] ?? null; }}

function bestProvider(algo,bi){{
  let best=null,val=-Infinity;
  providers.forEach(p=>{{ const v=data[p][algo][bi]||0; if(v>val){{val=v;best=p;}} }});
  return {{provider:best,value:val}};
}}
function sparkPath(vals,w=260,h=52){{
  const clean=vals.map(v=>v||0);
  const max=Math.max(...clean,1),min=Math.min(...clean),span=Math.max(max-min,1);
  return clean.map((v,i)=>{{
    const x=clean.length<=1?0:(i/(clean.length-1))*w;
    const y=h-((v-min)/span)*(h-8)-4;
    return `${{i===0?'M':'L'}} ${{x.toFixed(1)}} ${{y.toFixed(1)}}`;
  }}).join(' ');
}}
function providerFooter(p){{
  if(p==='afalg') return 'Hardware accelerated';
  if(p==='cryptodev') return 'Cryptodev accelerated';
  if(p==='engine') return 'Engine accelerated';
  return 'Software implementation';
}}

function buildButtons(){{
  const bEl=document.getElementById('btnBytes');
  sizeLabels.forEach((lbl,i)=>{{ const b=document.createElement('button');b.className='btn'+(i===selBytes?' active':'');b.textContent=lbl;b.onclick=()=>{{selBytes=i;document.querySelectorAll('#btnBytes .btn').forEach((x,j)=>x.classList.toggle('active',j===i));update();}};bEl.appendChild(b); }});
  const aEl=document.getElementById('btnAlgo');
  algos.forEach((a,i)=>{{ const b=document.createElement('button');b.className='btn'+(i===selAlgo?' active':'');b.textContent=ALGO_LABELS[a];b.onclick=()=>{{selAlgo=i;document.querySelectorAll('#btnAlgo .btn').forEach((x,j)=>x.classList.toggle('active',j===i));update();}};aEl.appendChild(b); }});
}}

function buildProviderStrip(){{
  const algo=algos[selAlgo],bi=selBytes;
  const swVal=data.sw?data.sw[algo][bi]:null;
  const best=bestProvider(algo,bi).provider;
  document.getElementById('providerStrip').innerHTML=providers.map(p=>{{
    const vals=data[p][algo].map(v=>v||0);
    const throughput=data[p][algo][bi];
    const cpuTotal=getCpu(p,algo,bi,'total');
    const core0=getCpu(p,algo,bi,'core0');
    const core1=getCpu(p,algo,bi,'core1');
    const ipc=getPerf(p,algo,bi,'ipc');
    const ratio=(throughput&&swVal)?(throughput/swVal*100):null;
    const ratioText=p==='sw'?'—':(ratio===null?'—':(ratio-100>=0?'+':'')+(ratio-100).toFixed(0)+'%');
    const badge=p===best?'BEST PERFORMANCE':'MEASURED · JSON';
    const path=sparkPath(vals);
    const selectedX=vals.length<=1?0:(bi/(vals.length-1))*260;
    return `<div class="provider-card" style="--pcol:${{colors[p]}}">
      <div class="provider-top"><div class="p-left"><div class="p-dot"></div><div class="p-name">${{names[p]}}</div></div><div class="p-dot dim"></div></div>
      <div class="p-badge">${{badge}}</div>
      <div class="p-value">${{fmtKbs(throughput).replace(' MB/s','<span class="unit">MB/s</span>').replace(' KB/s','<span class="unit">KB/s</span>')}}</div>
      <div class="p-ratio">${{ratioText}}<small>${{p==='sw'?'baseline':'vs software'}}</small></div>
      <div class="p-label">Throughput</div>
      <div class="p-metrics">
        <div class="p-metric"><span>CPU total (avg)</span><strong>${{fmtPct(cpuTotal)}}</strong></div>
        <div class="p-metric"><span>Core 0</span><strong>${{fmtPct(core0)}}</strong></div>
        <div class="p-metric"><span>Core 1</span><strong>${{fmtPct(core1)}}</strong></div>
      </div>
      <div class="spark">
        <svg viewBox="0 0 260 56" preserveAspectRatio="none">
          <path d="${{path}} L 260 56 L 0 56 Z" fill="${{alpha(colors[p],.18)}}"></path>
          <path d="${{path}}" fill="none" stroke="${{colors[p]}}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"></path>
          <line x1="${{selectedX.toFixed(1)}}" y1="0" x2="${{selectedX.toFixed(1)}}" y2="56" stroke="rgba(255,255,255,.25)" stroke-width="1"></line>
        </svg>
      </div>
      <div class="p-footer">${{providerFooter(p)}}</div>
    </div>`;
  }}).join('');
}}

function buildMetrics(){{
  const algo=algos[selAlgo],bi=selBytes,best=bestProvider(algo,bi);
  document.getElementById('heroSelected').textContent=`${{ALGO_LABELS[algo]}} · ${{sizeLabels[bi]}}`;
  document.getElementById('heroBest').textContent=best.provider?`${{names[best.provider]}} · ${{fmtKbs(best.value)}}`:'—';
  document.getElementById('heroRuns').textContent=providers.length*sizeLabels.length;
  document.getElementById('termSizes').textContent=`${{sizeLabels[0]}} → ${{sizeLabels[sizeLabels.length-1]}}`;
  document.getElementById('termSizes2').textContent=`${{sizeLabels[0]}} → ${{sizeLabels[sizeLabels.length-1]}}`;
  const ranked=[...providers].sort((a,b)=>(data[b][algo][bi]||0)-(data[a][algo][bi]||0));
  document.getElementById('metrics').innerHTML=ranked.map((p,i)=>{{
    const v=data[p][algo][bi];
    const cpu=getCpu(p,algo,bi,'total');
    const ipc=getPerf(p,algo,bi,'ipc');
    return `<div class="kpi" style="--kpi-color:${{colors[p]}}"><div class="kpi-name">${{names[p]}}</div><div class="kpi-main">${{fmtKbs(v)}}</div><div class="kpi-sub">CPU total ${{fmtPct(cpu)}} · IPC ${{ipc??'—'}}</div><div class="rank">#${{i+1}}</div></div>`;
  }}).join('');
}}

function buildGauges(){{
  const algo=algos[selAlgo],bi=selBytes;
  document.getElementById('gauges').innerHTML=providers.map(p=>{{
    const c0=getCpu(p,algo,bi,'core0')||0;
    const c1=getCpu(p,algo,bi,'core1')||0;
    const total=getCpu(p,algo,bi,'total')||0;
    return `<div class="gauge-card" style="--gcol:${{colors[p]}}">
      <div class="gauge-provider"><span><span class="g-dot"></span>${{names[p]}}</span><span style="font-family:JetBrains Mono,monospace;color:#91a8ba;font-size:11px">JSON avg</span></div>
      <div class="gauge-row">
        <div class="mini-gauge-box"><div class="gauge" style="--val:${{c0}};--col:${{colors[p]}}"><span>${{c0.toFixed(0)}}%</span></div><div class="gauge-title">Core 0</div></div>
        <div class="mini-gauge-box"><div class="gauge" style="--val:${{c1}};--col:${{colors[p]}}"><span>${{c1.toFixed(0)}}%</span></div><div class="gauge-title">Core 1</div></div>
      </div>
      <div class="gauge-total"><span>AVG TOTAL</span><strong>${{fmtPct(total)}}</strong></div>
    </div>`;
  }}).join('');
}}

function buildC1(){{
  if(c1) c1.destroy();
  const algo=algos[selAlgo],bi=selBytes;
  document.getElementById('sub1').textContent=`${{ALGO_LABELS[algo]}} · ${{sizeLabels[bi]}} · provider battle`;
  c1=new Chart(document.getElementById('c1'),{{
    type:'bar',
    data:{{labels:providers.map(p=>names[p]),datasets:[{{label:'Throughput',data:providers.map(p=>data[p][algo][bi]),backgroundColor:providers.map(p=>alpha(colors[p],.58)),borderColor:providers.map(p=>colors[p]),borderWidth:2,borderRadius:14,hoverBorderWidth:3}}]}},
    options:{{...chartBase(),layout:{{padding:{{top:0,bottom:0,left:0,right:0}}}},scales:{{x:{{ticks:tickStyle(),grid:gridOpts()}},y:{{ticks:{{...tickStyle(),callback:v=>fmtKbs(v)}},grid:gridOpts()}}}},plugins:{{...chartBase().plugins,legend:{{display:false}},tooltip:{{callbacks:{{label:c=>' '+fmtKbs(c.parsed.y)}}}}}}}}
  }});
}}

function buildC2(){{
  if(c2) c2.destroy();
  const algo=algos[selAlgo],bi=selBytes,sw=data.sw?data.sw[algo][bi]:null;
  document.getElementById('sub2').textContent=`${{ALGO_LABELS[algo]}} · baseline default SW = 100%`;
  const ratios=providers.map(p=>{{const v=data[p][algo][bi];return (v&&sw)?+(v/sw*100).toFixed(1):null;}});
  c2=new Chart(document.getElementById('c2'),{{
    type:'bar',
    data:{{labels:providers.map(p=>names[p]),datasets:[{{label:'vs SW',data:ratios,backgroundColor:providers.map(p=>alpha(colors[p],.52)),borderColor:providers.map(p=>colors[p]),borderWidth:2,borderRadius:12}}]}},
    options:{{...chartBase(),indexAxis:'y',scales:{{x:{{ticks:{{...tickStyle(),callback:v=>v+'%'}},grid:gridOpts()}},y:{{ticks:tickStyle(),grid:gridOpts()}}}},plugins:{{...chartBase().plugins,legend:{{display:false}},tooltip:{{callbacks:{{label:c=>' '+(c.parsed.x??0).toFixed(1)+'% du software'}}}}}}}}
  }});
}}

function buildC3(){{
  if(c3) c3.destroy();
  const algo=algos[selAlgo],bi=selBytes;
  document.getElementById('sub3').textContent=`${{ALGO_LABELS[algo]}} · average CPU usage · ${{sizeLabels[bi]}}`;
  c3=new Chart(document.getElementById('c3'),{{
    type:'bar',
    data:{{
      labels:providers.map(p=>names[p]),
      datasets:[
        {{label:'Core 0',data:providers.map(p=>getCpu(p,algo,bi,'core0')),backgroundColor:providers.map(p=>alpha(colors[p],.78)),borderColor:providers.map(p=>colors[p]),borderWidth:2,borderRadius:10}},
        {{label:'Core 1',data:providers.map(p=>getCpu(p,algo,bi,'core1')),backgroundColor:providers.map(p=>alpha(colors[p],.25)),borderColor:providers.map(p=>alpha(colors[p],.55)),borderWidth:2,borderRadius:10}}
      ]
    }},
    options:{{...chartBase(),layout:{{padding:{{top:0,bottom:0,left:0,right:0}}}},scales:{{x:{{ticks:tickStyle(),grid:gridOpts()}},y:{{max:100,ticks:{{...tickStyle(),callback:v=>v+'%'}},grid:gridOpts()}}}},plugins:{{...chartBase().plugins,tooltip:{{callbacks:{{label:c=>' '+c.dataset.label+': '+fmtPct(c.parsed.y)}}}}}}}}
  }});
}}

function buildC4(){{
  if(c4) c4.destroy();
  const algo=algos[selAlgo];
  document.getElementById('sub4').textContent=`${{ALGO_LABELS[algo]}} · block-size sweep`;
  c4=new Chart(document.getElementById('c4'),{{
    type:'line',
    data:{{labels:sizeLabels,datasets:providers.map(p=>({{label:names[p],data:data[p][algo],borderColor:colors[p],backgroundColor:alpha(colors[p],.10),fill:true,borderWidth:3,pointRadius:4,pointHoverRadius:7,pointBackgroundColor:colors[p],tension:.42,spanGaps:true}}))}},
    options:{{...chartBase(),interaction:{{mode:'index',intersect:false}},scales:{{x:{{ticks:{{...tickStyle(10),maxRotation:45}},grid:gridOpts()}},y:{{ticks:{{...tickStyle(),callback:v=>fmtKbs(v)}},grid:gridOpts()}}}},plugins:{{...chartBase().plugins,tooltip:{{callbacks:{{label:c=>' '+c.dataset.label+': '+fmtKbs(c.parsed.y)}}}}}}}}
  }});
}}

function buildC5(){{
  if(c5) c5.destroy();
  const algo=algos[selAlgo];
  document.getElementById('sub5').textContent=`${{ALGO_LABELS[algo]}} · Core 0 usage across block sizes`;
  c5=new Chart(document.getElementById('c5'),{{
    type:'line',
    data:{{
      labels:sizeLabels,
      datasets:providers.map(p=>({{
        label:names[p],
        data:cpuData[p][algo].core0,
        borderColor:colors[p],
        backgroundColor:alpha(colors[p],.10),
        fill:true,borderWidth:3,pointRadius:4,pointHoverRadius:7,
        pointBackgroundColor:colors[p],tension:.42,spanGaps:true
      }}))
    }},
    options:{{...chartBase(),interaction:{{mode:'index',intersect:false}},scales:{{x:{{ticks:{{...tickStyle(10),maxRotation:45}},grid:gridOpts()}},y:{{min:0,max:100,ticks:{{...tickStyle(),callback:v=>v+'%'}},grid:gridOpts()}}}},plugins:{{...chartBase().plugins,tooltip:{{callbacks:{{label:c=>' '+c.dataset.label+': '+fmtPct(c.parsed.y)}}}}}}}}
  }});
}}

function buildC6(){{
  if(c6) c6.destroy();
  const algo=algos[selAlgo];
  document.getElementById('sub6').textContent=`${{ALGO_LABELS[algo]}} · Core 1 usage across block sizes`;
  c6=new Chart(document.getElementById('c6'),{{
    type:'line',
    data:{{
      labels:sizeLabels,
      datasets:providers.map(p=>({{
        label:names[p],
        data:cpuData[p][algo].core1,
        borderColor:colors[p],
        backgroundColor:alpha(colors[p],.10),
        fill:true,borderWidth:3,pointRadius:4,pointHoverRadius:7,
        pointBackgroundColor:colors[p],tension:.42,spanGaps:true
      }}))
    }},
    options:{{...chartBase(),interaction:{{mode:'index',intersect:false}},scales:{{x:{{ticks:{{...tickStyle(10),maxRotation:45}},grid:gridOpts()}},y:{{min:0,max:100,ticks:{{...tickStyle(),callback:v=>v+'%'}},grid:gridOpts()}}}},plugins:{{...chartBase().plugins,tooltip:{{callbacks:{{label:c=>' '+c.dataset.label+': '+fmtPct(c.parsed.y)}}}}}}}}
  }});
}}

function buildC7(){{
  if(c7) c7.destroy();
  const algo=algos[selAlgo];
  document.getElementById('sub7').textContent=`${{ALGO_LABELS[algo]}} · average CPU = (Core 0 + Core 1) / 2 across block sizes`;
  c7=new Chart(document.getElementById('c7'),{{
    type:'line',
    data:{{
      labels:sizeLabels,
      datasets:providers.map(p=>({{
        label:names[p],
        data:cpuData[p][algo].total,
        borderColor:colors[p],
        backgroundColor:alpha(colors[p],.10),
        fill:true,borderWidth:3,pointRadius:4,pointHoverRadius:7,
        pointBackgroundColor:colors[p],tension:.42,spanGaps:true
      }}))
    }},
    options:{{...chartBase(),interaction:{{mode:'index',intersect:false}},scales:{{x:{{ticks:{{...tickStyle(10),maxRotation:45}},grid:gridOpts()}},y:{{min:0,max:100,ticks:{{...tickStyle(),callback:v=>v+'%'}},grid:gridOpts()}}}},plugins:{{...chartBase().plugins,tooltip:{{callbacks:{{label:c=>' '+c.dataset.label+': '+fmtPct(c.parsed.y)}}}}}}}}
  }});
}}

function update(){{ buildMetrics(); buildProviderStrip(); buildGauges(); buildC1(); buildC2(); buildC3(); buildC4(); buildC5(); buildC6(); buildC7(); }}

const canvas=document.getElementById('particle-canvas'),ctx=canvas.getContext('2d');let W,H,particles=[],traces=[],tick=0;
function makeTrace(){{
  const y=Math.random()*H, x=-80-Math.random()*W*.25;
  return {{x,y,len:80+Math.random()*180,speed:.55+Math.random()*1.35,alpha:.28+Math.random()*.36,turn:Math.random()>.55}};
}}
function resize(){{
  W=canvas.width=innerWidth;H=canvas.height=innerHeight;
  particles=Array.from({{length:Math.min(190,Math.floor(W*H/9000))}},()=>({{x:Math.random()*W,y:Math.random()*H,vx:(Math.random()-.5)*.42,vy:(Math.random()-.5)*.42,r:Math.random()*1.7+.45,p:Math.random()*Math.PI*2}}));
  traces=Array.from({{length:Math.min(34,Math.floor(W/55))}},()=>makeTrace());
}}
function drawTrace(t){{
  ctx.save();
  ctx.globalAlpha=t.alpha;
  const grad=ctx.createLinearGradient(t.x,t.y,t.x+t.len,t.y);
  grad.addColorStop(0,'rgba(56,189,248,0)');
  grad.addColorStop(.45,'rgba(56,189,248,.9)');
  grad.addColorStop(1,'rgba(52,211,153,0)');
  ctx.shadowColor='rgba(56,189,248,.75)';ctx.shadowBlur=14;ctx.strokeStyle=grad;ctx.lineWidth=2.1;ctx.beginPath();ctx.moveTo(t.x,t.y);ctx.lineTo(t.x+t.len,t.y);
  if(t.turn){{ctx.lineTo(t.x+t.len+42,t.y+34);}}
  ctx.stroke();
  ctx.restore();
}}
function loop(){{
  tick+=.01;ctx.clearRect(0,0,W,H);
  for(const t of traces){{t.x+=t.speed;if(t.x>W+160)Object.assign(t,makeTrace());drawTrace(t);}}
  for(const p of particles){{
    p.x+=p.vx;p.y+=p.vy;p.p+=.035;
    if(p.x<0||p.x>W)p.vx*=-1;if(p.y<0||p.y>H)p.vy*=-1;
    const glow=.42+.24*Math.sin(p.p);
    ctx.beginPath();ctx.arc(p.x,p.y,p.r,0,Math.PI*2);ctx.shadowColor='rgba(125,211,252,.8)';ctx.shadowBlur=8;ctx.fillStyle=`rgba(125,211,252,${{glow}})`;ctx.fill();ctx.shadowBlur=0;
  }}
  for(let i=0;i<particles.length;i++)for(let j=i+1;j<particles.length;j++){{
    const a=particles[i],b=particles[j],dx=a.x-b.x,dy=a.y-b.y,dist=Math.hypot(dx,dy);
    if(dist<135){{ctx.strokeStyle=`rgba(56,189,248,${{(1-dist/135)*.26}})`;ctx.lineWidth=1;ctx.beginPath();ctx.moveTo(a.x,a.y);ctx.lineTo(b.x,b.y);ctx.stroke();}}
  }}
  requestAnimationFrame(loop);
}}
addEventListener('resize',resize);resize();loop();
buildButtons();update();
</script>
</body>
</html>"""


def main():
    ap = argparse.ArgumentParser(description="STM32MP257 — génère la page HTML benchmark")
    ap.add_argument("--input",  default=DEFAULT_INPUT,  help=f"JSON source (défaut: {DEFAULT_INPUT})")
    ap.add_argument("--output", default=DEFAULT_OUTPUT, help=f"HTML de sortie (défaut: {DEFAULT_OUTPUT})")
    args = ap.parse_args()

    src = Path(args.input)
    if not src.exists():
        print(f"✗ Fichier introuvable : {src}")
        sys.exit(1)

    results = json.loads(src.read_text())
    if not results:
        print("✗ bench_results.json est vide.")
        sys.exit(1)

    html = generate_html(results)

    out = Path(args.output)
    out.write_text(html, encoding="utf-8")

    providers_found = sorted(set(IMPL_TO_PROVIDER.get(r["implementation"], r["implementation"]) for r in results))
    sizes_found     = sorted(set(b["block_bytes"] for r in results for b in r.get("blocks", [])))
    print(f"{out}  ({out.stat().st_size//1024} KB)")
    print(f"  Providers : {providers_found}")
    print(f"  Runs      : {len(results)}")

if __name__ == "__main__":
    main()
