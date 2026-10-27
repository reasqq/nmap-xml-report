"""Bounded XML parsing. No networking, process execution or XSL evaluation."""

from pathlib import Path
import io
import re
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException

MAX_BYTES = 20 * 1024 * 1024
MAX_DEPTH = 64
MAX_ELEMENTS = 200_000


class ReportError(ValueError):
    """Invalid, unsafe, oversized or unsupported input."""


def attrs(parent, path):
    element = parent.find(path)
    return element.attrib if element is not None else {}


def parse_report(path, max_bytes=MAX_BYTES):
    if not 1 <= max_bytes <= MAX_BYTES:
        raise ReportError(f"Size limit must be between 1 and {MAX_BYTES} bytes")
    source = Path(path)
    if not source.is_file():
        raise ReportError("Input must be a regular XML file")
    with source.open("rb") as stream:
        data = stream.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ReportError(f"XML exceeds size limit ({max_bytes} bytes)")
    try:
        # Accept the inert declaration emitted by Nmap. All other DTDs are forbidden.
        # Decode first so UTF-16 cannot bypass the same DTD policy.
        if data.startswith((b"\xff\xfe", b"\xfe\xff")) or b"\x00" in data[:100]:
            raise ReportError("Unsupported XML encoding: use UTF-8")
        document = data.decode("utf-8-sig")
        declaration = re.match(r'\s*<\?xml\s+[^?]*encoding=[\'"]([^\'"]+)', document)
        if declaration and declaration[1].lower() not in ("utf-8", "utf8", "us-ascii"):
            raise ReportError("Unsupported XML encoding: use UTF-8")
        document = re.sub(r"<!DOCTYPE\s+nmaprun\s*>", "", document, count=1)
        # Event parsing enforces depth and node limits before building the full tree.
        depth = count = 0
        iterator = ElementTree.iterparse(
            io.StringIO(document), events=("start", "end"),
            forbid_dtd=True, forbid_entities=True, forbid_external=True,
        )
        for event, _element in iterator:
            if event == "start":
                depth += 1
                count += 1
                if depth > MAX_DEPTH or count > MAX_ELEMENTS:
                    raise ReportError("XML exceeds depth or element limit")
            else:
                depth -= 1
        root = iterator.root
    except (ParseError, DefusedXmlException, UnicodeError) as exc:
        raise ReportError(f"Malformed or unsafe XML ({type(exc).__name__})") from exc
    if root.tag != "nmaprun" or root.get("scanner", "nmap") != "nmap":
        raise ReportError("Unsupported document: expected Nmap nmaprun root")
    warnings = []
    finished = attrs(root, "runstats/finished")
    scan = {
        "start": root.get("start"), "start_text": root.get("startstr"),
        "end": finished.get("time"), "end_text": finished.get("timestr"),
        "elapsed_seconds": finished.get("elapsed"), "exit": finished.get("exit"),
    }
    if not root.get("start") or not finished.get("time") or finished.get("exit") != "success":
        warnings.append("Scan timing/completion is missing or scan did not finish successfully.")
    hosts = []
    for index, element in enumerate(root.findall("host"), 1):
        host = {
            "addresses": [dict(a.attrib) for a in element.findall("address")],
            "hostnames": [h.get("name") for h in element.findall("hostnames/hostname") if h.get("name")],
            "status": attrs(element, "status").get("state", "unknown"),
            "ports": [], "extraports": [],
        }
        if not host["addresses"] or host["status"] == "unknown":
            warnings.append(f"Host {index}: address or status missing.")
        for port in element.findall("ports/port"):
            service = attrs(port, "service")
            item = {
                "protocol": port.get("protocol"), "port": port.get("portid"),
                "state": attrs(port, "state").get("state") or "unknown",
                "service": service.get("name"), "product": service.get("product"),
                "version": service.get("version"), "extra_info": service.get("extrainfo"),
            }
            if not item["protocol"] or not item["port"] or item["state"] == "unknown":
                warnings.append(f"Host {index}: port protocol, number or state missing.")
            host["ports"].append(item)
        for extra in element.findall("ports/extraports"):
            host["extraports"].append({"state": extra.get("state") or "unknown", "count": extra.get("count")})
            warnings.append(f"Host {index}: grouped ports have no individual port numbers.")
        if not host["ports"] and not host["extraports"]:
            warnings.append(f"Host {index}: no port data recorded.")
        hosts.append(host)
    totals = attrs(root, "runstats/hosts")
    if totals.get("total") is not None:
        try:
            if int(totals["total"]) != len(hosts):
                warnings.append("Scan host total differs from the number of host records; some records may be omitted.")
        except ValueError:
            warnings.append("Scan host total is invalid.")
    if not hosts:
        warnings.append("No host records in report; this does not establish that no hosts exist.")
    return {"schema_version": 1, "scan": scan, "warnings": warnings, "hosts": hosts,
            "notice": "Service versions are observations, not proof of vulnerability."}
