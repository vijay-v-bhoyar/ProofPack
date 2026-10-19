import importlib.util
from pathlib import Path
import sys


spec = importlib.util.spec_from_file_location("verification_runner",Path(__file__).resolve().parents[2]/"scripts/verify_local.py")
runner=importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def test_runner_retains_real_exit_code_and_complete_output(tmp_path):
    log=tmp_path/"failure.log"
    assert runner.run_check([sys.executable,"-c","print('expected failure',flush=True); raise SystemExit(7)"],log)==7
    assert b"expected failure" in log.read_bytes()


def test_runner_bounds_owned_process_and_retains_timeout(tmp_path):
    log=tmp_path/"timeout.log"
    assert runner.run_check([sys.executable,"-c","import time; print('started',flush=True); time.sleep(10)"],log,timeout=1)==124
    assert b"timed out" in log.read_bytes()
