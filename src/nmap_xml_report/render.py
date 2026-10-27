"""Text, Markdown and CSV presentation of untrusted values."""

from collections import Counter
import csv
import html
import io
import json


def plain(value):
    text = str(value) if value is not None else "unknown"
    return "".join(c if c.isprintable() else f"\\u{ord(c):04x}" for c in text)


def markdown(value):
    return "".join(
        f"&#{ord(char)};" if char in "\\`*_{}[]()#+-.!|~" else html.escape(char, quote=True)
        for char in plain(value)
    )


def summary(report):
    lines = [f"Hosts: {len(report['hosts'])}", f"Scan: {plain(report['scan'])}", report["notice"]]
    for host in report["hosts"]:
        lines.append(f"Host {plain(host['addresses'])} names={plain(host['hostnames'])} status={plain(host['status'])}")
        counts = Counter(p["state"] for p in host["ports"])
        lines.append(f"  Explicit port states: {plain(dict(counts))}")
        for port in host["ports"]:
            lines.append("  " + " ".join(f"{key}={plain(value)}" for key, value in port.items()))
        for extra in host["extraports"]:
            lines.append(f"  Grouped ports: {plain(extra)}")
    lines.extend("WARNING: " + plain(warning) for warning in report["warnings"])
    return "\n".join(lines) + "\n"


def csv_cell(value):
    text = "" if value is None else str(value)
    # Prevent spreadsheet formulas, including whitespace-prefixed payloads.
    if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
        text = "'" + text
    return text


def render(report, format):
    if format == "json":
        return json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if format == "markdown":
        lines = ["# Nmap XML summary", "", markdown(report["notice"]), "", "## Scan", ""]
        lines.extend(f"- {key}: {markdown(value)}" for key, value in report["scan"].items())
        lines += ["", "## Warnings", ""] + ["- " + markdown(w) for w in report["warnings"]]
        for index, host in enumerate(report["hosts"], 1):
            lines += ["", f"## Host {index}", "", f"Addresses: {markdown(host['addresses'])}", "",
                      f"Hostnames: {markdown(host['hostnames'])}; status: {markdown(host['status'])}", "",
                      "| Protocol | Port | State | Service | Product | Version | Extra info |",
                      "| --- | --- | --- | --- | --- | --- | --- |"]
            lines.extend("| " + " | ".join(markdown(p[k]) for k in ("protocol", "port", "state", "service", "product", "version", "extra_info")) + " |" for p in host["ports"])
            lines.extend("\nGrouped ports: " + markdown(e) for e in host["extraports"])
        return "\n".join(lines) + "\n"
    if format != "csv":
        raise ValueError("Unsupported export format")
    stream = io.StringIO(newline="")
    writer = csv.writer(stream)
    writer.writerow(["record_type", "host_index", "addresses_json", "hostnames_json", "host_status", "protocol", "port", "state", "service", "product", "version", "extra_info", "group_count", "scan_json", "warnings_json"])
    def row(values):
        writer.writerow([csv_cell(v) for v in values])
    row(["scan"] + [""] * 12 + [json.dumps(report["scan"], ensure_ascii=False), json.dumps(report["warnings"], ensure_ascii=False)])
    for index, host in enumerate(report["hosts"], 1):
        base = [index, json.dumps(host["addresses"], ensure_ascii=False), json.dumps(host["hostnames"], ensure_ascii=False), host["status"]]
        row(["host"] + base + [""] * 10)
        for port in host["ports"]:
            row(["port"] + base + [port[k] for k in ("protocol", "port", "state", "service", "product", "version", "extra_info")] + ["", "", ""])
        for extra in host["extraports"]:
            row(["extraports"] + base + ["", "", extra["state"], "", "", "", "", extra["count"], "", ""])
    return stream.getvalue()
