"""Repeatable local component/build checks; never sets product evidence PASS."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "evidence/local"


def run_check(command, log_path: Path, *, timeout: float = 120,env=None) -> int:
    """Bound our own process tree; child-held pipes cannot hang timeout cleanup."""
    with log_path.open("wb") as log:
        process = subprocess.Popen(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,env=env,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0,
            start_new_session=sys.platform != "win32")
        try:
            return process.wait(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            if sys.platform == "win32":
                subprocess.run(["taskkill","/PID",str(process.pid),"/T","/F"],
                               stdout=log,stderr=subprocess.STDOUT,timeout=10,check=False)
            else:
                os.killpg(process.pid,signal.SIGKILL)
            process.wait(timeout=10)
            if isinstance(exc,KeyboardInterrupt):
                raise
            log.write(b"\nVerification command timed out; owned process tree terminated.\n")
            return 124


def source_manifest():
    paths = set()
    for directory, suffixes in (("services/api/proofpack", {".py"}), ("tests", {".py", ".ts"}),
                                ("apps/web/src", {".ts", ".tsx", ".css"}), ("scripts", {".py"})):
        paths.update(p for p in (ROOT / directory).rglob("*") if p.suffix in suffixes and "__pycache__" not in p.parts)
    paths.update(p for p in (ROOT/'fixtures/synthetic').rglob('*') if p.is_file())
    paths.update(ROOT / name for name in ("README.md", "pyproject.toml", "setup.py", "MANIFEST.in", "requirements.in", "requirements.txt", "requirements-dev.txt", "requirements-windows.lock",
        "package.json", "package-lock.json", "apps/web/package.json", "apps/web/tsconfig.json",
        "tools/dynamodb-local.lock.json",
        "apps/web/vite.config.ts", "apps/web/playwright.config.ts", "apps/web/index.html", "docs/controls.yaml"))
    return [{"path":p.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(paths) if p.exists()]


def browser_prerequisite_passed(results):
    return any(row.get("check") == "installed-support-contracts"
               and row.get("status") == "PASS"
               and type(row.get("exit_code")) is int and row["exit_code"] == 0
               for row in results)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--browser", action="store_true", help="Also check an owned loopback server using Chrome")
    args = parser.parse_args()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    npm = shutil.which("npm.cmd" if sys.platform == "win32" else "npm")
    if not npm:
        raise SystemExit("npm is required")
    before = source_manifest()
    # Mark an interrupted run honestly and make the documented receipt path
    # available before the structural link check. This is not a PASS receipt.
    (OUTPUT / "verification.json").write_text(json.dumps({"scope":"local_components_and_foundation_only",
        "status":"IN_PROGRESS","recorded_at":datetime.now(timezone.utc).isoformat(),
        "source_manifest":before,"beta_decision":"NO_GO"},indent=2)+"\n",encoding="utf-8")
    commands = [
        ("unit-tests",["in-process", "run_python_suite.run_suite()"]),
        ("opencv-proof",[sys.executable,"scripts/prove_runtime.py"]),
        ("fixture-integrity",[sys.executable,"scripts/generate_fixtures.py","--verify"]),
        ("synthetic-evaluation",[sys.executable,"scripts/evaluate_synthetic.py"]),
        ("controlled-fixture-integrity",[sys.executable,"scripts/generate_controlled_fixtures.py","--verify"]),
        ("controlled-baselines",[sys.executable,"scripts/evaluate_controlled.py","--candidate","fixtures/synthetic/controlled-candidate.json"]),
        ("python-dependencies",[sys.executable,"-m","pip","check"]),
        ("frontend-build",[npm,"run","build"]),
        ("python-build",[sys.executable,"-m","build","--no-isolation","--wheel","--outdir",".runtime/dist"]),
        ("installed-wheel",[sys.executable,"scripts/prove_installed_wheel.py"]),
        ("documentation",[sys.executable,"docs/contracts/validate_documentation.py"]),
    ]
    if args.browser:
        commands.append(("installed-support-contracts",[sys.executable,"scripts/capture_support_contracts.py"]))
        commands.append(("browser-tests",["in-process","run_browser_suite.run_suite()"]))
    results = []
    for name, command in commands:
        start = datetime.now(timezone.utc).isoformat()
        if name == 'browser-tests' and not browser_prerequisite_passed(results):
            (OUTPUT / f'{name}.log').write_text('BLOCKED: installed support capture prerequisite did not pass.\n', encoding='utf-8')
            results.append({'check': name, 'command': command, 'exit_code': None,
                            'started_at': start, 'status': 'BLOCKED', 'log': f'evidence/local/{name}.log'})
            print(f'{name}: BLOCKED', flush=True)
            continue
        if name=='unit-tests':
            from run_python_suite import run_suite
            from contextlib import redirect_stdout
            with (OUTPUT/f'{name}.log').open('w',encoding='utf-8') as log,redirect_stdout(log):code=run_suite()
        elif name=='browser-tests':
            from run_browser_suite import run_suite
            from contextlib import redirect_stdout
            with (OUTPUT/f'{name}.log').open('w',encoding='utf-8') as log,redirect_stdout(log):code=run_suite()
        else:code = run_check(command,OUTPUT / f"{name}.log",timeout=300 if name=='installed-support-contracts' else 620 if name=='controlled-baselines' else 120)
        results.append({"check":name,"command":command,"exit_code":code,"started_at":start,
                        "status":"PASS" if code == 0 else "FAIL","log":f"evidence/local/{name}.log"})
        print(f"{name}: {'PASS' if code == 0 else 'FAIL'}",flush=True)
    after = source_manifest()
    ok = before == after and all(r["exit_code"] == 0 for r in results)
    artifacts = [p for p in OUTPUT.glob("*") if p.suffix in {".log", ".xml", ".png", ".zip"}]
    runtime_file = OUTPUT / "opencv-runtime.json"
    if runtime_file.exists():
        artifacts.append(runtime_file)
    artifacts.extend((ROOT / ".runtime/dist").glob("*.whl"))
    artifacts.append(OUTPUT / "dependency-wheels.json")
    artifacts.append(OUTPUT / "synthetic-evaluation.json")
    controlled=OUTPUT/'controlled-baselines.json'
    if controlled.exists():
        artifacts.append(controlled)
        value=json.loads(controlled.read_text(encoding='utf-8'))
        if 'run_directory' in value:
            directory=(OUTPUT/value['run_directory']).resolve()
            if not directory.is_relative_to((OUTPUT/'controlled-runs').resolve()):raise ValueError('owned controlled evidence directory required')
            artifacts.extend(p for p in directory.rglob('*') if p.is_file())
    artifacts.append(OUTPUT / "installed-wheel.json")
    artifacts.append(OUTPUT / "dynamodb-local.json")
    artifacts.extend(OUTPUT.glob('python-*.json'))
    if args.browser and browser_prerequisite_passed(results):
        if (OUTPUT / 'browser-server.json').exists():artifacts.append(OUTPUT / 'browser-server.json')
        browser_receipt=OUTPUT/'browser-suite.json';artifacts.append(browser_receipt)
        if browser_receipt.exists():
            directory=(ROOT/json.loads(browser_receipt.read_text(encoding='utf-8'))['run_directory']).resolve()
            if not directory.is_relative_to(OUTPUT.resolve()):raise ValueError('owned browser evidence directory required')
            artifacts.extend(p for p in directory.rglob('*') if p.is_file())
    report = {"scope":"local_components_and_foundation_only","status":"PASS" if ok else "FAIL",
        "recorded_at":datetime.now(timezone.utc).isoformat(),"sources_unchanged_during_run":before == after,
        "source_manifest":after,"checks":results,
        "artifacts":[{"path":p.relative_to(ROOT).as_posix(),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}
                     for p in sorted(artifacts)],
        "full_workflows":"NOT_RUN", "aws_live":"NOT_RUN", "physical_qualification":"BLOCKED",
        "human_evaluation":"NOT_RUN", "beta_decision":"NO_GO"}
    (OUTPUT / "verification.json").write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
