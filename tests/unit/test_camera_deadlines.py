"""Actual TypeScript camera helpers with controlled native completion/timer ordering.

This models a delayed browser event loop, not camera hardware or human use.
"""
from pathlib import Path
import shutil
import subprocess

import pytest


SCRIPT = r"""
import assert from 'node:assert/strict';
import {pathToFileURL} from 'node:url';
const camera = await import(pathToFileURL(process.argv[1]).href);
const [kind, fault] = process.argv[2].split(':');
let clock = 100, nextTimer = 0, callback, complete, rejectPlayback;
const timers = new Map(), cancelled = [];
Object.defineProperty(globalThis, 'performance', {value: {now: () => clock}, configurable: true});
globalThis.window = {setTimeout: (fn, ms) => {assert.equal(ms, 750); timers.set(++nextTimer, fn); return nextTimer;},
  clearTimeout: id => timers.delete(id)};
let requests = 0, plays = 0, pauses = 0;
const video = {
  requestVideoFrameCallback: fn => {requests++; callback = fn; return 7;},
  cancelVideoFrameCallback: id => cancelled.push(id),
  play: () => {plays++; if (fault === 'throw') throw new Error('native playback failed');
    return new Promise((resolve, reject) => {complete = resolve; rejectPlayback = reject;});},
  pause: () => {pauses++;},
};
if (fault === 'no_support') video.requestVideoFrameCallback = undefined;
const control = new AbortController();
if (fault === 'abort_before') control.abort();
let abortAdds = 0, abortRemoves = 0;
const add = control.signal.addEventListener.bind(control.signal), remove = control.signal.removeEventListener.bind(control.signal);
control.signal.addEventListener = (...args) => {if(args[0] === 'abort') abortAdds++; return add(...args);};
control.signal.removeEventListener = (...args) => {if(args[0] === 'abort') abortRemoves++; return remove(...args);};
let outcome = 'pending', message = '';
const promise = (kind === 'frame' ? camera.nextFrame(video, control.signal) : camera.startPlayback(video, control.signal))
  .then(() => {outcome = 'resolved';}, error => {outcome = 'rejected'; message = String(error.message);});
const release = () => kind === 'frame' ? callback?.(clock, {}) : complete?.();
if (fault === 'abort_pending') control.abort();
else if (fault === 'timer_first' || fault === 'late_after_timeout') {
  clock = 850; const timer = [...timers.values()][0]; assert.equal(typeof timer, 'function'); timer();
  if (fault === 'late_after_timeout') {clock = 1600; release();}
} else if (!['abort_before', 'no_support', 'throw'].includes(fault)) {
  if (fault === 'reject') rejectPlayback(new Error('native playback failed'));
  else {
    clock = {on_time: 110, edge_before: 849, edge_equal: 850, late_before_timer: 1152, backwards: 99}[fault];
    assert.equal(typeof clock, 'number'); release();
  }
}
await promise;
const expected = ['on_time', 'edge_before'].includes(fault) ? 'resolved' : 'rejected';
assert.equal(outcome, expected, `${kind}/${fault}: ${outcome} must be ${expected}; ${message}`);
assert.equal(timers.size, 0, 'terminal result must remove its original timer');
assert.equal(abortRemoves >= abortAdds, true, 'terminal result must release the abort listener');
if (['edge_equal','late_before_timer','backwards','timer_first','late_after_timeout'].includes(fault))
  assert.match(message, kind === 'frame' ? /Camera frames stopped/ : /Camera playback did not start/);
if (fault === 'abort_before') assert.equal(kind === 'frame' ? requests : plays, 0, 'cancelled work must not register native work');
if (kind === 'playback') assert.equal(pauses, expected === 'resolved' ? 0 : 1);
if (kind === 'frame' && requests) assert.deepEqual(cancelled, [7], 'clean up the exact native callback once');
const pausesBefore = pauses, cancelledBefore = cancelled.length;
clock = 2000; release(); control.abort(); await Promise.resolve();
assert.equal(outcome, expected, 'late completion cannot change the original result');
assert.equal(pauses, pausesBefore, 'terminal cleanup must not repeat');
assert.equal(cancelled.length, cancelledBefore, 'terminal frame cleanup must not repeat');
console.log(JSON.stringify({kind, fault, outcome}));
"""


@pytest.mark.parametrize('kind,fault', [
    (kind, fault)
    for kind, faults in [
        ('frame', ['on_time', 'edge_before', 'edge_equal', 'late_before_timer',
                   'backwards', 'abort_before', 'abort_pending', 'timer_first',
                   'late_after_timeout', 'no_support']),
        ('playback', ['on_time', 'edge_before', 'edge_equal', 'late_before_timer',
                      'backwards', 'abort_before', 'abort_pending', 'timer_first',
                      'late_after_timeout', 'throw', 'reject']),
    ] for fault in faults
])
def test_actual_camera_completion_boundary(kind, fault):
    root = Path(__file__).resolve().parents[2]
    node = shutil.which('node')
    assert node, 'Node runtime is required; missing execution is not a pass'
    result = subprocess.run(
        [node, '--input-type=module', '-e', SCRIPT,
         str(root / 'apps/web/src/camera.ts'), f'{kind}:{fault}'],
        cwd=root, capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stdout + result.stderr
