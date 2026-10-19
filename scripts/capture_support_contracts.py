"""Offline installed-service capture for the browser contract; synthetic inputs only."""
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import tomllib
from urllib.parse import urlsplit
from uuid import uuid4
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TARGETS = (
    "tests/integration/test_policy_factory_flow.py",
    "tests/integration/test_inspection_handoffs.py",
    "tests/integration/test_handoff_http.py",
    "tests/integration/test_handoff_composition.py",
    "tests/unit/test_handoff_models.py",
    "tests/unit/test_handoff_host.py",
)
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
read = lambda path: json.loads(path.read_text(encoding="utf-8"))


def owned_endpoint(request_url, endpoint):
    try:
        actual, expected = urlsplit(request_url), urlsplit(endpoint)
        return (expected.scheme == "http" and expected.hostname == "127.0.0.1"
                and type(expected.port) is int and 0 < expected.port < 65536
                and actual.username is None and actual.password is None
                and expected.username is None and expected.password is None
                and (actual.scheme, actual.hostname, actual.port) ==
                    (expected.scheme, expected.hostname, expected.port))
    except (TypeError, ValueError, AttributeError):
        return False


def verify_wheel(wheel, root):
    backend = {p.relative_to(root / "services/api").as_posix(): p
               for p in (root / "services/api/proofpack").rglob("*.py")}
    assets = {"proofpack/web/" + p.relative_to(root / "apps/web/dist").as_posix(): p
              for p in (root / "apps/web/dist").rglob("*") if p.is_file()}
    if not backend or "proofpack/web/index.html" not in assets:
        raise ValueError("current backend and built frontend required")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or any(
                PurePosixPath(n).is_absolute() or ".." in PurePosixPath(n).parts
                or ":" in n or "\\" in n or n.endswith(".pth") for n in names):
            raise ValueError("unsafe or duplicate wheel member")
        if {n for n in names if n.endswith(".py")} != set(backend):
            raise ValueError("wheel backend inventory differs from current source")
        if {n for n in names if n.startswith("proofpack/web/")} != set(assets):
            raise ValueError("wheel frontend inventory differs from current build")
        if any(n not in backend and n not in assets
               and not re.fullmatch(r"proofpack-[^/]+\.dist-info/[^/]+", n) for n in names):
            raise ValueError("unexpected executable or payload outside the current package inventory")
        for name, path in (backend | assets).items():
            if archive.read(name) != path.read_bytes():
                raise ValueError("stale wheel member: " + name)
    return {name: sha(path) for name, path in (backend | assets).items()}


def validate_bundle(collection, execution, child, capture, xml_path, site, *, targets=TARGETS):
    nodes = collection["nodeids"]
    if (collection["phase"] != "COMPLETE" or type(collection["exit_code"]) is not int
            or collection["exit_code"] != 0 or not nodes or len(nodes) != len(set(nodes))
            or {n.split("::", 1)[0] for n in nodes} != set(targets)):
        raise ValueError("complete distinct collection for every target required")
    if (type(child["exit_code"]) is not int or type(execution["exit_code"]) is not int
            or child["exit_code"] != 0 or execution["exit_code"] != 0):
        raise ValueError("successful integer process outcomes required")
    from run_python_suite import coverage_errors
    if coverage_errors(nodes, [{"exit_code": child["exit_code"], "execution": execution,
                               "expected_nodeids": nodes}]):
        raise ValueError("failed, skipped or incomplete installed execution")
    desired = []
    for node in nodes:
        path, *names = node.split("::")
        desired.append((".".join([path.removesuffix(".py").replace("/", "."), *names[:-1]]), names[-1]))
    cases = ET.parse(xml_path).findall(".//testcase")
    if (Counter(desired) != Counter((c.attrib["classname"], c.attrib["name"]) for c in cases)
            or any(c.find(tag) is not None for c in cases for tag in ("failure", "error", "skipped"))):
        raise ValueError("JUnit identities or outcomes differ")
    modules = child["installed_modules"]
    if (not modules or any(not Path(path).resolve().is_relative_to(site.resolve()) for path in modules.values())
            or type(child["blocked_sdk_sends"]) is not int or child["blocked_sdk_sends"] != 0
            or type(child["local_sdk_sends"]) is not int or child["local_sdk_sends"] < 1
            or child["opencv_version"].split(".")[0] != "5"):
        raise ValueError("installed origins, local transport and OpenCV 5 required")
    records = capture["records"]
    if (not records or any(set(row) != {"kind", "value"} or not isinstance(row["value"], dict) for row in records)
            or {row["kind"] for row in records} != {"detail", "inbox", "none"}):
        raise ValueError("actual detail, inbox and no-request returns required")
    return {"cases": len(nodes), "phases": len(execution["outcomes"]), "capture_records": len(records),
            "installed_modules": len(modules), "local_sdk_sends": child["local_sdk_sends"]}


CHILD = r'''
import copy,json,os,sys
from pathlib import Path
site,root=Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve()
endpoint,mode,out=sys.argv[3],sys.argv[4],Path(sys.argv[5])
sys.path[:0]=[str(site),str(root/'scripts'),str(root/'tests/integration'),str(root/'tests/unit')]
from capture_support_contracts import TARGETS,owned_endpoint
import botocore.httpsession
send=botocore.httpsession.URLLib3Session.send
counts={'local':0,'blocked':0}
def local_only(self,request):
    if not owned_endpoint(request.url,endpoint):
        counts['blocked']+=1
        raise AssertionError('external SDK transport prohibited')
    counts['local']+=1
    return send(self,request)
botocore.httpsession.URLLib3Session.send=local_only
import proofpack.app
assert Path(proofpack.app.__file__).resolve().is_relative_to(site)
from proofpack.stations.handoffs import InspectionHandoffs
public=[]
original=InspectionHandoffs._deliver
def capture_delivery(self,*args,**kwargs):
    result=original(self,*args,**kwargs)
    kind='detail' if 'request' in result else 'inbox' if 'requests' in result else 'none'
    public.append({'kind':kind,'value':copy.deepcopy(result)})
    return result
if mode=='run':InspectionHandoffs._deliver=capture_delivery
import pytest
args=['-q','-o','pythonpath=','-p','pytest_evidence']
if mode=='collect':args.append('--collect-only')
args.extend(str(root/target) for target in TARGETS)
if mode=='run':args.append('--junitxml='+str(out/'tests.xml'))
code=pytest.main(args)
modules={name:str(Path(module.__file__).resolve()) for name,module in tuple(sys.modules.items())
         if (name=='proofpack' or name.startswith('proofpack.')) and getattr(module,'__file__',None)}
assert modules and all(Path(path).is_relative_to(site) for path in modules.values())
import cv2
(out/(mode+'-child.json')).write_text(json.dumps({'exit_code':code,'installed_modules':modules,
    'local_sdk_sends':counts['local'],'blocked_sdk_sends':counts['blocked'],
    'opencv_version':cv2.__version__},indent=2)+'\n')
if mode=='run':(out/'contracts.json').write_text(json.dumps({'scope':'actual installed public returns; synthetic identities/data',
    'records':public},indent=2,allow_nan=False)+'\n')
raise SystemExit(code)
'''


def main():
    from verify_local import source_manifest
    import dynamodb_local
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    wheels = list((ROOT / ".runtime/dist").glob("proofpack-" + version + "-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError("one current built wheel required")
    wheel = wheels[0]
    members = verify_wheel(wheel, ROOT)
    before = source_manifest()
    output = (ROOT / "evidence/local").resolve()
    if not output.is_relative_to(ROOT.resolve()):
        raise ValueError("owned project evidence directory required")
    base = output / "support-capture-runs" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid4().hex)
    out = base / "evidence/local"
    out.mkdir(parents=True)
    (base / "tools").mkdir()
    shutil.copyfile(ROOT / "tools/dynamodb-local.lock.json", base / "tools/dynamodb-local.lock.json")
    dynamodb_local.ROOT = base
    dynamodb_local.CACHE = ROOT / ".runtime/dynamodb"
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AWS_", "PROOFPACK_", "PYTEST_")) and key != "PYTHONPATH"}
    env.update(AWS_ACCESS_KEY_ID="localtest", AWS_SECRET_ACCESS_KEY="localtest", AWS_DEFAULT_REGION="us-east-1",
        AWS_EC2_METADATA_DISABLED="true", AWS_CONFIG_FILE=os.devnull, AWS_SHARED_CREDENTIALS_FILE=os.devnull,
        PIP_NO_INDEX="1", HTTP_PROXY="", HTTPS_PROXY="", ALL_PROXY="", http_proxy="", https_proxy="", all_proxy="",
        NO_PROXY="*", no_proxy="*")
    # Java also receives fake-only AWS configuration. This script is its own process.
    for key in list(os.environ):
        if key.startswith("AWS_"):
            del os.environ[key]
    os.environ.update({key: value for key, value in env.items() if key.startswith("AWS_") or key in
                       {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy", "NO_PROXY", "no_proxy"}})
    report = {"scope": "installed local synthetic support contracts only", "status": "IN_PROGRESS",
              "started_at": datetime.now(timezone.utc).isoformat(), "source_manifest": before,
              "wheel_sha256": sha(wheel), "commands": [], "parent_complete": False, "beta_decision": "NO_GO"}
    receipt = base / "process.json"
    receipt.write_text(json.dumps(report, indent=2) + "\n")
    site = None
    code = 1
    try:
        with TemporaryDirectory(prefix="installed-site-", dir=base) as folder:
            site = Path(folder).resolve()
            assert site.parent == base.resolve()
            command = [sys.executable, "-m", "pip", "install", "--no-index", "--no-deps", "--target", str(site), str(wheel)]
            report["commands"].append(command)
            with (out / "install.log").open("wb") as log:
                subprocess.run(command, cwd=site, env=env, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=45)
            assert all(sha(site / name) == digest for name, digest in members.items())
            with dynamodb_local.local_database() as endpoint:
                for mode, limit in (("collect", 45), ("run", 120)):
                    command = [sys.executable, "-I", "-c", CHILD, str(site), str(ROOT), endpoint, mode, str(out)]
                    report["commands"].append(command)
                    with (out / (mode + ".log")).open("wb") as log:
                        subprocess.run(command, cwd=site, env={**env, "PROOFPACK_TEST_DYNAMO_URL": endpoint,
                            "PROOFPACK_PYTEST_EVIDENCE_PATH": str(out / ("collection.json" if mode == "collect" else "execution.json"))},
                            stdout=log, stderr=subprocess.STDOUT, check=True, timeout=limit)
            report.update(validate_bundle(read(out / "collection.json"), read(out / "execution.json"),
                read(out / "run-child.json"), read(out / "contracts.json"), out / "tests.xml", site))
            assert all(sha(site / name) == digest for name, digest in members.items())
            report["installed_site"] = str(site)
        database = read(out / "dynamodb-local.json")
        assert (database["terminated"] is True and database["state_removed"] is True
                and database["aws_resources_created"] is False
                and datetime.fromisoformat(database["started_at"]) >= datetime.fromisoformat(report["started_at"])
                and sha(out / "dynamodb-server.log") == database["server_log_sha256"])
        assert not site.exists() and before == source_manifest() and sha(wheel) == report["wheel_sha256"]
        capture = output / "support-ui-installed-contracts.json"
        provenance = capture.with_suffix(".provenance.json")
        for previous in (capture, provenance):
            if previous.exists():
                shutil.copyfile(previous, out / ("previous-" + previous.name))
        shutil.copyfile(out / "contracts.json", capture)
        provenance.write_text(json.dumps({"scope": report["scope"], "process_receipt": str(receipt),
            "capture_sha256": sha(capture), "wheel_sha256": report["wheel_sha256"],
            "source_manifest_sha256": hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest()}, indent=2) + "\n")
        report.update(status="PASS", capture_sha256=sha(capture), database_terminated=True,
                      database_state_removed=True, temporary_installation_removed=True)
        code = 0
    except Exception as error:
        report.update(status="FAIL", error_type=type(error).__name__, error=str(error))
    finally:
        source_same = before == source_manifest()
        if not source_same:
            code = 1
            report.update(status="FAIL", error_type="SourceChanged", error="source changed during capture")
        report.update(exit_code=code, ended_at=datetime.now(timezone.utc).isoformat(),
                      source_unchanged=source_same,
                      temporary_installation_removed=site is not None and not site.exists())
        receipt.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"status": report["status"], "scope": report["scope"], "receipt": str(receipt)}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
