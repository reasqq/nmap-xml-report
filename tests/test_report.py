import contextlib
import csv
import io
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from nmap_xml_report import ReportError, parse_report
from nmap_xml_report.cli import main
from nmap_xml_report.render import markdown, render, summary

FIXTURE = Path(__file__).resolve().parents[1] / "examples" / "lab.xml"


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def xml(self, text):
        path = self.folder / "input.xml"
        path.write_text(text, encoding="utf-8")
        return path

    def invoke(self, args):
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return main(args)

    def test_multiple_hosts_states_and_versions(self):
        report = parse_report(FIXTURE)
        self.assertEqual(len(report["hosts"]), 3)
        host = report["hosts"][0]
        self.assertEqual(len(host["addresses"]), 2)
        self.assertEqual(host["hostnames"], ["alpha.example.test"])
        self.assertEqual([p["state"] for p in host["ports"]], ["open", "closed", "filtered", "open|filtered"])
        self.assertEqual(host["ports"][0]["version"], "1.0-lab")
        self.assertEqual(host["extraports"], [{"state": "closed", "count": "10"}])
        self.assertEqual(report["scan"]["elapsed_seconds"], "5.0")
        self.assertIn("1700000000", summary(report))

    def test_missing_fields_are_unknown(self):
        report = parse_report(self.xml('<nmaprun><host><ports><port/></ports></host></nmaprun>'))
        host = report["hosts"][0]
        self.assertEqual(host["status"], "unknown")
        self.assertEqual(host["ports"][0]["state"], "unknown")
        self.assertIsNone(host["ports"][0]["version"])
        self.assertGreaterEqual(len(report["warnings"]), 3)

    def test_malformed_and_unsupported(self):
        for text in ('<nmaprun>', '', '<html/>', '<nmaprun scanner="other"/>', '<nmaprun xmlns="urn:other"/>'):
            with self.subTest(text=text), self.assertRaises(ReportError):
                parse_report(self.xml(text))

    def test_malicious_dtd_and_entities_rejected_without_io(self):
        payloads = [
            '<!DOCTYPE nmaprun SYSTEM "https://example.test/evil.dtd"><nmaprun/>',
            '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///nonexistent-secret">]><nmaprun>&x;</nmaprun>',
            '<!DOCTYPE nmaprun [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;">]><nmaprun>&b;</nmaprun>',
            '<!DOCTYPE nmaprun [<!ENTITY % a SYSTEM "https://example.test/e">%a;]><nmaprun/>',
        ]
        for text in payloads:
            path = self.xml(text)
            with self.subTest(text=text), patch.object(socket, "socket", side_effect=AssertionError("network")), self.assertRaises(ReportError):
                parse_report(path)

    def test_commands_scripts_and_xsl_are_inert(self):
        path = self.xml('''<?xml-stylesheet href="https://example.test/evil.xsl"?>
        <nmaprun args="touch SHOULD_NOT_EXIST"><host><hostscript>
        <script id="exec" output="touch SHOULD_NOT_EXIST"/></hostscript></host></nmaprun>''')
        with patch.object(socket, "socket", side_effect=AssertionError("network")), patch.object(subprocess, "Popen", side_effect=AssertionError("process")):
            parse_report(path)
        self.assertFalse((self.folder / "SHOULD_NOT_EXIST").exists())

    def test_limits(self):
        path = self.xml('<nmaprun>' + '<a>' * 65 + '</a>' * 65 + '</nmaprun>')
        with self.assertRaises(ReportError):
            parse_report(path)
        with self.assertRaises(ReportError):
            parse_report(FIXTURE, 10)
        for limit in (0, -1, 21 * 1024 * 1024):
            with self.assertRaises(ReportError):
                parse_report(FIXTURE, limit)
        with patch("nmap_xml_report.parser.MAX_ELEMENTS", 2), self.assertRaises(ReportError):
            parse_report(FIXTURE)

    def test_encoding(self):
        path = self.folder / "utf16.xml"
        path.write_bytes('<nmaprun/>'.encode("utf-16"))
        with self.assertRaises(ReportError):
            parse_report(path)
        with self.assertRaises(ReportError):
            parse_report(self.xml('<?xml version="1.0" encoding="iso-8859-1"?><nmaprun/>'))

    def test_incomplete_scan_and_host_count(self):
        for total in ("5", "invalid"):
            report = parse_report(self.xml(f'<nmaprun start="1"><host><ports/></host><runstats><finished time="2" exit="error"/><hosts total="{total}"/></runstats></nmaprun>'))
            self.assertTrue(any("completion" in w for w in report["warnings"]))
            self.assertTrue(any("no port data" in w for w in report["warnings"]))
            self.assertTrue(any("host total" in w for w in report["warnings"]))

    def test_hardlink_cannot_replace_input(self):
        path = self.xml('<nmaprun/>')
        alias = self.folder / "alias.xml"
        try:
            alias.hardlink_to(path)
        except OSError:
            self.skipTest("Hardlinks unavailable on this filesystem")
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="yes"):
            self.assertEqual(self.invoke(["export", str(path), "--format", "json", "--output", str(alias)]), 2)
        self.assertEqual(path.read_text(), '<nmaprun/>')

    def test_symlink_cannot_be_overwritten(self):
        target = self.folder / "keep.json"
        target.write_text("keep", encoding="utf-8")
        link = self.folder / "link.json"
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest("Symlinks unavailable without OS permission")
        self.assertEqual(self.invoke(["export", str(FIXTURE), "--format", "json", "--output", str(link)]), 2)
        self.assertEqual(target.read_text(), "keep")

    def test_all_formats_preserve_information(self):
        report = parse_report(FIXTURE)
        self.assertEqual(json.loads(render(report, "json")), report)
        rows = list(csv.DictReader(io.StringIO(render(report, "csv"))))
        self.assertEqual(len([r for r in rows if r["record_type"] == "host"]), 3)
        self.assertEqual(len([r for r in rows if r["record_type"] == "port"]), 5)
        self.assertEqual(json.loads(rows[0]["scan_json"]), report["scan"])
        self.assertTrue(all(None not in r for r in rows))
        md = render(report, "markdown")
        for value in ("192", "filtered", "Version", "Warnings", "Scan", "unknown"):
            self.assertIn(value, md)

    def test_markdown_terminal_and_csv_injection(self):
        self.assertEqual(markdown("[x]|<b>"), "&#91;x&#93;&#124;&lt;b&gt;")
        report = parse_report(self.xml('''<nmaprun><host><address addr="192.0.2.1"/>
        <hostnames><hostname name="&lt;script&gt;[click](https://example.test)|`x`"/></hostnames>
        <ports><port protocol="tcp" portid="1"><service name="=1+1" version="&#27;"/></port></ports>
        </host></nmaprun>'''.replace('version="&#27;"', 'version="test"')))
        md = render(report, "markdown")
        self.assertNotIn("<script>", md)
        self.assertNotIn("[click]", md)
        self.assertNotIn("`x`", md)
        rows = list(csv.DictReader(io.StringIO(render(report, "csv"))))
        self.assertEqual(rows[-1]["service"], "'=1+1")
        report["hosts"][0]["status"] = "\x1b[31m"
        self.assertNotIn("\x1b", summary(report))

    def test_cli_parse_summary_export(self):
        for command in ("parse", "summary"):
            self.assertEqual(self.invoke([command, str(FIXTURE)]), 0)
        for format in ("json", "csv", "markdown"):
            out = self.folder / f"result.{format}"
            self.assertEqual(self.invoke(["export", str(FIXTURE), "--format", format, "--output", str(out)]), 0)
            self.assertTrue(out.read_text(encoding="utf-8"))

    def test_no_overwrite_without_confirmation(self):
        out = self.folder / "report.json"
        out.write_text("keep me", encoding="utf-8")
        args = ["export", str(FIXTURE), "--format", "json", "--output", str(out)]
        with patch("sys.stdin.isatty", return_value=False):
            self.assertEqual(self.invoke(args), 2)
        self.assertEqual(out.read_text(), "keep me")
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="no"):
            self.assertEqual(self.invoke(args), 2)
        self.assertEqual(out.read_text(), "keep me")
        with patch("sys.stdin.isatty", return_value=True), patch("builtins.input", return_value="yes"):
            self.assertEqual(self.invoke(args), 0)
        self.assertEqual(json.loads(out.read_text())["schema_version"], 1)

    def test_input_protection_missing_paths_and_errors(self):
        path = self.xml('<nmaprun/>')
        self.assertEqual(self.invoke(["export", str(path), "--format", "json", "--output", str(path)]), 2)
        self.assertEqual(path.read_text(), '<nmaprun/>')
        self.assertEqual(self.invoke(["parse", str(self.folder / "absent")]), 2)
        self.assertEqual(self.invoke(["parse", str(self.folder)]), 2)
        self.assertEqual(self.invoke(["export", str(path), "--format", "csv", "--output", str(self.folder / "missing" / "out.csv")]), 2)


if __name__ == "__main__":
    unittest.main()
