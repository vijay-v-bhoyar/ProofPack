"""Pure fixture/stub checks; no installed app, browser, Java or provider execution."""
import copy
import ast
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import warnings
import xml.etree.ElementTree as ET
import zipfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
import capture_support_contracts as capture
import verify_local as verifier
import run_python_suite


@pytest.mark.parametrize("url,expected", [
    ("http://127.0.0.1:8123/", True), ("http://127.0.0.1:8123/path?q=x", True),
    ("https://127.0.0.1:8123/", False), ("http://127.0.0.1:8124/", False),
    ("http://example.test:8123/", False), ("http://127.0.0.1.example.test:8123/", False),
    ("http://user:secret@127.0.0.1:8123/", False), ("http://127.0.0.1:99999/", False),
])
def test_only_exact_owned_transport(url, expected):
    assert capture.owned_endpoint(url, "http://127.0.0.1:8123") is expected


@pytest.mark.parametrize("permitted", [False, True])
def test_compiled_child_hook_blocks_before_stub_transport(permitted):
    tree = ast.parse(capture.CHILD)
    hook = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "local_only")
    calls, counts = [], {"local": 0, "blocked": 0}
    def send(owner, request):
        calls.append((owner, request))
        return "stub-response"
    namespace = {"owned_endpoint": capture.owned_endpoint, "endpoint": "http://127.0.0.1:8123",
                 "counts": counts, "send": send}
    exec(compile(ast.Module(body=[hook], type_ignores=[]), "capture-child-hook", "exec"), namespace)
    request = SimpleNamespace(url="http://127.0.0.1:8123/" if permitted else "https://unowned.example.test/")
    if permitted:
        assert namespace["local_only"]("stub-owner", request) == "stub-response"
        assert calls == [("stub-owner", request)] and counts == {"local": 1, "blocked": 0}
    else:
        with pytest.raises(AssertionError): namespace["local_only"]("stub-owner", request)
        assert not calls and counts == {"local": 0, "blocked": 1}


@pytest.mark.parametrize("fault", [None, "stale_backend", "stale_asset", "extra_python", "extra_native", "pth", "traversal", "duplicate"])
def test_wheel_must_match_current_package_before_install(tmp_path, fault):
    backend = tmp_path / "services/api/proofpack/__init__.py"
    frontend = tmp_path / "apps/web/dist/index.html"
    backend.parent.mkdir(parents=True)
    frontend.parent.mkdir(parents=True)
    backend.write_text("original = True\n")
    frontend.write_text("<html>current</html>")
    members = {"proofpack/__init__.py": backend.read_bytes(), "proofpack/web/index.html": frontend.read_bytes(),
               "proofpack-0.1.0.dist-info/METADATA": b"Name: proofpack\nVersion: 0.1.0\n"}
    if fault == "stale_backend": members["proofpack/__init__.py"] = b"stale"
    if fault == "stale_asset": members["proofpack/web/index.html"] = b"stale"
    if fault == "extra_python": members["proofpack/untracked.py"] = b"extra"
    if fault == "extra_native": members["proofpack/hidden.pyd"] = b"extra"
    if fault == "pth": members["startup.pth"] = b"import untracked"
    if fault == "traversal": members["../escape"] = b"extra"
    wheel = tmp_path / "fixture.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, value in members.items(): archive.writestr(name, value)
            if fault == "duplicate": archive.writestr("proofpack/__init__.py", backend.read_bytes())
    if fault is None:
        manifest = capture.verify_wheel(wheel, tmp_path)
        assert set(manifest) == {"proofpack/__init__.py", "proofpack/web/index.html"}
    else:
        with pytest.raises(ValueError): capture.verify_wheel(wheel, tmp_path)


@pytest.mark.parametrize("fault", [None, "missing_phase", "duplicate_phase", "failed_phase", "skipped_phase",
    "coerced_exit", "wrong_xml", "foreign_origin", "blocked_transport", "no_local_transport", "opencv4", "missing_kind"])
def test_capture_requires_complete_current_evidence(tmp_path, fault):
    target = "tests/unit/test_handoff_models.py"
    nodes = [target + "::test_one", target + "::test_two"]
    collection = {"phase": "COMPLETE", "exit_code": 0, "nodeids": nodes}
    execution = {**copy.deepcopy(collection), "outcomes": [
        {"nodeid": node, "phase": phase, "outcome": "passed"}
        for node in nodes for phase in ("setup", "call", "teardown")]}
    site = tmp_path / "site"
    site.mkdir()
    child = {"exit_code": 0, "installed_modules": {"proofpack": str(site / "proofpack/__init__.py")},
             "local_sdk_sends": 3, "blocked_sdk_sends": 0, "opencv_version": "5.0.0"}
    raw = {"records": [{"kind": kind, "value": {"synthetic": True}} for kind in ("detail", "inbox", "none")]}
    tree = ET.Element("testsuites")
    suite = ET.SubElement(tree, "testsuite")
    for node in nodes:
        ET.SubElement(suite, "testcase", classname="tests.unit.test_handoff_models", name=node.split("::")[-1])
    if fault == "missing_phase": execution["outcomes"].pop()
    if fault == "duplicate_phase": execution["outcomes"].append(copy.deepcopy(execution["outcomes"][0]))
    if fault == "failed_phase": execution["outcomes"][1]["outcome"] = "failed"
    if fault == "skipped_phase": execution["outcomes"][1]["outcome"] = "skipped"
    if fault == "coerced_exit": child["exit_code"] = False
    if fault == "wrong_xml": suite[0].set("name", "different")
    if fault == "foreign_origin": child["installed_modules"]["proofpack"] = str(site / "../outside.py")
    if fault == "blocked_transport": child["blocked_sdk_sends"] = 1
    if fault == "no_local_transport": child["local_sdk_sends"] = 0
    if fault == "opencv4": child["opencv_version"] = "4.99.0"
    if fault == "missing_kind": raw["records"].pop()
    xml = tmp_path / "tests.xml"
    ET.ElementTree(tree).write(xml)
    if fault is None:
        result = capture.validate_bundle(collection, execution, child, raw, xml, site, targets=[target])
        assert result["cases"] == 2 and result["phases"] == 6 and result["capture_records"] == 3
    else:
        with pytest.raises(ValueError): capture.validate_bundle(collection, execution, child, raw, xml, site, targets=[target])


@pytest.mark.parametrize("row,accepted", [
    ({"check": "installed-support-contracts", "status": "PASS", "exit_code": 0}, True),
    ({"check": "installed-wheel", "status": "PASS", "exit_code": 0}, False),
    ({"check": "installed-support-contracts", "status": "FAIL", "exit_code": 1}, False),
    ({"check": "installed-support-contracts", "status": "NOT_RUN", "exit_code": None}, False),
    ({"check": "installed-support-contracts", "status": "PASS", "exit_code": False}, False),
])
def test_browser_needs_its_actual_prerequisite(row, accepted):
    assert verifier.browser_prerequisite_passed([row]) is accepted


@pytest.mark.parametrize("producer_code", [0, 1])
def test_normal_pipeline_orders_capture_and_holds_dependent_browser(tmp_path, monkeypatch, producer_code):
    output = tmp_path / "evidence/local"
    output.mkdir(parents=True)
    for name in ("dependency-wheels.json", "synthetic-evaluation.json", "installed-wheel.json", "dynamodb-local.json"):
        (output / name).write_text("{}")
    monkeypatch.setattr(verifier, "ROOT", tmp_path)
    monkeypatch.setattr(verifier, "OUTPUT", output)
    monkeypatch.setattr(verifier, "source_manifest", lambda: [])
    monkeypatch.setattr(verifier.shutil, "which", lambda _: "stub-npm")
    monkeypatch.setattr(sys, "argv", ["verify_local.py", "--browser"])
    monkeypatch.setattr(run_python_suite, "run_suite", lambda: 0)
    events, timeouts = [], []
    def check(command, log, *, timeout=120, **kwargs):
        timeouts.append((command, timeout))
        if "scripts/capture_support_contracts.py" in command:
            events.append("capture")
            return producer_code
        return 0
    monkeypatch.setattr(verifier, "run_check", check)
    def browser():
        events.append("browser")
        (output / "synthetic-browser").mkdir()
        (output / "browser-suite.json").write_text(json.dumps({"run_directory": "evidence/local/synthetic-browser"}))
        return 0
    monkeypatch.setitem(sys.modules, "run_browser_suite", SimpleNamespace(run_suite=browser))
    with pytest.raises(SystemExit) as stopped:
        verifier.main()
    result = json.loads((output / "verification.json").read_text())
    assert stopped.value.code == producer_code
    assert events == (["capture", "browser"] if producer_code == 0 else ["capture"])
    last = result["checks"][-1]
    assert last["status"] == ("PASS" if producer_code == 0 else "BLOCKED")
    assert last["exit_code"] == (0 if producer_code == 0 else None)
    assert next(limit for command, limit in timeouts if "scripts/capture_support_contracts.py" in command) == 300
    assert next(limit for command, limit in timeouts if "scripts/prove_installed_wheel.py" in command) == 120


@pytest.mark.parametrize("fault", [None, "source_changed", "test_failed", "state_retained"])
def test_producer_lifecycle_and_failed_publication_with_stub_processes(tmp_path, monkeypatch, fault):
    root = tmp_path
    backend = root / "services/api/proofpack/__init__.py"
    asset = root / "apps/web/dist/index.html"
    for path, value in ((backend, b"synthetic=True\n"), (asset, b"<html>stub</html>")):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
    (root / "pyproject.toml").write_text('[project]\nversion="0.1.0"\n')
    (root / "tools").mkdir()
    (root / "tools/dynamodb-local.lock.json").write_text("{}")
    wheels = root / ".runtime/dist"
    wheels.mkdir(parents=True)
    wheel = wheels / "proofpack-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("proofpack/__init__.py", backend.read_bytes())
        archive.writestr("proofpack/web/index.html", asset.read_bytes())
    published = root / "evidence/local/support-ui-installed-contracts.json"
    published.parent.mkdir(parents=True)
    prior = b'{"unit_stub_prior_artifact":true}'
    published.write_bytes(prior)
    monkeypatch.setattr(capture, "ROOT", root)
    calls = []
    def manifest():
        calls.append("source-read")
        return ["changed"] if fault == "source_changed" and len(calls) >= 3 else ["synthetic-source"]
    monkeypatch.setattr(verifier, "source_manifest", manifest)
    database = SimpleNamespace()
    @contextmanager
    def local_database():
        out = database.ROOT / "evidence/local"
        started = datetime.now(timezone.utc).isoformat()
        (out / "dynamodb-server.log").write_bytes(b"unit stub; no Java process")
        try:
            yield "http://127.0.0.1:8123"
        finally:
            (out / "dynamodb-local.json").write_text(json.dumps({"started_at": started, "terminated": True,
                "state_removed": fault != "state_retained", "aws_resources_created": False,
                "server_log_sha256": hashlib.sha256(b"unit stub; no Java process").hexdigest()}))
    database.local_database = local_database
    monkeypatch.setitem(sys.modules, "dynamodb_local", database)
    def process(command, **kwargs):
        if "--target" in command:
            site = Path(command[command.index("--target") + 1])
            with zipfile.ZipFile(wheel) as archive:
                for name in archive.namelist():
                    path = site / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(archive.read(name))
            return SimpleNamespace(returncode=0)
        site, mode, out = Path(command[4]), command[-2], Path(command[-1])
        if mode == "run" and fault == "test_failed":
            raise capture.subprocess.CalledProcessError(1, command)
        nodes = [target + "::test_unit_stub" for target in capture.TARGETS]
        value = {"phase": "COMPLETE", "exit_code": 0, "nodeids": nodes, "outcomes": []}
        if mode == "run":
            value["outcomes"] = [{"nodeid": node, "phase": phase, "outcome": "passed"}
                for node in nodes for phase in ("setup", "call", "teardown")]
            tree = ET.Element("testsuites")
            suite = ET.SubElement(tree, "testsuite")
            for target in capture.TARGETS:
                ET.SubElement(suite, "testcase", classname=target.removesuffix(".py").replace("/", "."), name="test_unit_stub")
            ET.ElementTree(tree).write(out / "tests.xml")
            (out / "contracts.json").write_text(json.dumps({"records": [
                {"kind": kind, "value": {"unit_stub": True}} for kind in ("detail", "inbox", "none")]}))
        (out / ("collection.json" if mode == "collect" else "execution.json")).write_text(json.dumps(value))
        (out / (mode + "-child.json")).write_text(json.dumps({"exit_code": 0,
            "installed_modules": {"proofpack": str(site / "proofpack/__init__.py")},
            "local_sdk_sends": 1, "blocked_sdk_sends": 0, "opencv_version": "5.0.0"}))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(capture.subprocess, "run", process)
    code = capture.main()
    receipts = list((root / "evidence/local/support-capture-runs").glob("*/process.json"))
    assert len(receipts) == 1
    report = json.loads(receipts[0].read_text())
    assert code == (0 if fault is None else 1)
    assert report["status"] == ("PASS" if fault is None else "FAIL")
    assert report["temporary_installation_removed"] is True
    if fault in {"test_failed", "state_retained"}:
        assert published.read_bytes() == prior
    elif fault == "source_changed":
        assert report["source_unchanged"] is False
        assert (receipts[0].parent / "evidence/local/previous-support-ui-installed-contracts.json").read_bytes() == prior
    else:
        assert report["cases"] == 6 and report["phases"] == 18
        assert json.loads(published.read_text())["records"]
