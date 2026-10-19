import type { Context } from './api';

export function requestCamera(constraints: MediaStreamConstraints, signal: AbortSignal): Promise<MediaStream> {
  return new Promise((resolve, reject) => {
    let finished = false;
    const cancel = () => { finished = true; signal.removeEventListener('abort', cancel); reject(new Error('Camera start cancelled. Recheck required.')); };
    if (signal.aborted) { cancel(); return; }
    signal.addEventListener('abort', cancel, { once: true });
    void navigator.mediaDevices.getUserMedia(constraints).then(media => {
      signal.removeEventListener('abort', cancel);
      if (finished || signal.aborted) { media.getTracks().forEach(track => track.stop()); return; }
      finished = true; resolve(media);
    }, error => { signal.removeEventListener('abort', cancel); if (!finished) { finished = true; reject(error); } });
  });
}

export function startPlayback(video: HTMLVideoElement, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const began = performance.now();
    let finished = false, timer = 0;
    const cleanup = () => { window.clearTimeout(timer); signal.removeEventListener('abort', abort); };
    const fail = (error: unknown) => {
      if (finished) return;
      finished = true; cleanup(); video.pause(); reject(error);
    };
    const abort = () => fail(new Error('Camera playback stopped.'));
    if (signal.aborted) { abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
    timer = window.setTimeout(() => fail(new Error('Camera playback did not start. Check the camera and start preview again.')), 750);
    try {
      void video.play().then(() => {
        if (finished) return;
        const now = performance.now();
        if (now < began || now - began >= 750) {
          fail(new Error('Camera playback did not start. Check the camera and start preview again.')); return;
        }
        finished = true; cleanup(); resolve();
      }, fail);
    } catch (error) { fail(error); }
  });
}

export function drawCapture(video: HTMLVideoElement, canvas: HTMLCanvasElement, context: Context) {
  const w = video.videoWidth, h = video.videoHeight;
  if (video.readyState < 2 || !w || !h) throw new Error('No live camera frame. Restore the camera before checking.');
  const scale = Math.min(w / context.frame_width, h / context.frame_height);
  if (scale < 1) throw new Error('Camera resolution is below the approved profile. Ask the owner.');
  const sw = context.frame_width * scale, sh = context.frame_height * scale;
  if (canvas.width !== context.frame_width) canvas.width = context.frame_width;
  if (canvas.height !== context.frame_height) canvas.height = context.frame_height;
  const drawing = canvas.getContext('2d', { willReadFrequently: true });
  if (!drawing) throw new Error('Camera preview is unavailable.');
  drawing.drawImage(video, (w - sw) / 2, (h - sh) / 2, sw, sh, 0, 0, canvas.width, canvas.height);
  return drawing;
}

export function nextFrame(video: HTMLVideoElement, signal: AbortSignal): Promise<void> {
  if (typeof video.requestVideoFrameCallback !== 'function') return Promise.reject(new Error('Use a supported desktop browser with fresh camera-frame callbacks.'));
  return new Promise((resolve, reject) => {
    const began = performance.now();
    let finished = false, handle: number | null = null, timer = 0;
    const cleanup = () => { window.clearTimeout(timer); signal.removeEventListener('abort', abort); if (handle !== null) video.cancelVideoFrameCallback(handle); };
    const fail = (error: unknown) => { if (!finished) { finished = true; cleanup(); reject(error); } };
    const abort = () => fail(new Error('Camera capture stopped.'));
    if (signal.aborted) { abort(); return; }
    signal.addEventListener('abort', abort, { once: true });
    timer = window.setTimeout(() => fail(new Error('Camera frames stopped. Restore the camera.')), 750);
    try {
      handle = video.requestVideoFrameCallback(() => {
        if (finished) return;
        const now = performance.now();
        if (now < began || now - began >= 750) {
          fail(new Error('Camera frames stopped. Restore the camera.')); return;
        }
        finished = true; cleanup(); resolve();
      });
    } catch (error) { fail(error); }
  });
}

export async function imageBlob(canvas: HTMLCanvasElement): Promise<Blob> {
  const blob = await new Promise<Blob | null>(resolve => canvas.toBlob(resolve, 'image/jpeg', .85));
  if (!blob || blob.type !== 'image/jpeg' || !blob.size || blob.size > 2097152) throw new Error('Captured image exceeds the supported format or size. Ask the owner.');
  return blob;
}
