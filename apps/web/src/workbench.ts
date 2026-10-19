import { createContext, useContext, useEffect, useRef, useState } from 'react';
import { api } from './api';
import type { User } from './api';

export const roles = ['owner', 'operator', 'reviewer'];
export const identifier = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
export const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const sha = /^[0-9a-f]{64}$/;
export const WorkbenchBusy = createContext<(busy: boolean) => void>(() => {});
export const WorkbenchUnconfirmed = createContext<(token: symbol, unresolved: boolean) => void>(() => {});
export function useUnconfirmed(unresolved: boolean) {
  const report = useContext(WorkbenchUnconfirmed), token = useRef(Symbol('panel-intent'));
  useEffect(() => { report(token.current, unresolved); return () => report(token.current, false); }, [report, unresolved]);
}
export async function blobSha256(value: Blob) {
  if (!value.size || value.size > 2097152) throw new Error('Choose a JPEG or PNG no larger than 2 MiB.');
  const hash = await crypto.subtle.digest('SHA-256', await value.arrayBuffer());
  return [...new Uint8Array(hash)].map(byte => byte.toString(16).padStart(2, '0')).join('');
}
export function positive(value: unknown): value is number { return Number.isSafeInteger(value) && Number(value) > 0; }
export function useReviewDeadline() {
  const [deadline, setDeadline] = useState(0), [, repaint] = useState(0);
  const generation = useRef(0);
  useEffect(() => {
    const clear = () => { generation.current++; setDeadline(0); };
    const hidden = () => { if (document.visibilityState !== 'visible') clear(); };
    const tick = window.setInterval(() => repaint(value => value + 1), 100);
    window.addEventListener('offline', clear); document.addEventListener('visibilitychange', hidden);
    return () => { window.clearInterval(tick); window.removeEventListener('offline', clear); document.removeEventListener('visibilitychange', hidden); };
  }, []);
  const bound = (started: number, remaining: number, max: number, token: number) => {
    if (token !== generation.current || document.visibilityState !== 'visible' || !navigator.onLine) throw new Error('Review interrupted. Refresh the current record before acting.');
    if (!positive(remaining) || remaining > max) throw new Error('The review validity is unavailable. Refresh the record.');
    setDeadline(started + remaining);
  };
  return { valid: deadline > performance.now(), clear: () => { generation.current++; setDeadline(0); }, token: () => generation.current, bound };
}
export function member(value: User): User {
  if (!value || !Array.isArray(value.roles) || value.roles.some(role => !roles.includes(role))
    || typeof value.id !== 'string' || typeof value.session_id !== 'string' || typeof value.display_name !== 'string'
    || typeof value.csrf_token !== 'string') throw new Error('Account information is unavailable. Sign in again.');
  return value;
}
export function useTasks(initial: string) {
  const [busy, setBusy] = useState(false), [message, setMessage] = useState(initial);
  const active = useRef(true), locked = useRef(false), controller = useRef(new AbortController());
  const pending = useRef(new Map<string, string>());
  const activity = useContext(WorkbenchBusy);
  const reportUnconfirmed = useContext(WorkbenchUnconfirmed), unresolvedToken = useRef(Symbol('implicit-write'));
  useEffect(() => () => reportUnconfirmed(unresolvedToken.current, false), [reportUnconfirmed]);
  useEffect(() => { activity(busy); return () => activity(false); }, [activity, busy]);
  useEffect(() => {
    active.current = true; controller.current = new AbortController();
    return () => { active.current = false; controller.current.abort(); pending.current.clear(); };
  }, []);
  async function call<T>(path: string, options: Parameters<typeof api<T>>[1] = {}): Promise<T> {
    const method = options.method ?? 'GET';
    if (method === 'GET') return api<T>(path, { ...options, signal: controller.current.signal });
    let body: unknown = options.body ?? null;
    if (options.body instanceof FormData) {
      const parts: unknown[] = [];
      for (const [name, value] of options.body.entries()) {
        if (parts.length >= 4) throw new Error('Too many upload fields.');
        if (typeof value === 'string') {
          if (value.length > 4096) throw new Error('Upload metadata is too long.');
          parts.push([name, value]);
        } else {
          parts.push([name, { length: value.size, type: value.type, sha256: await blobSha256(value) }]);
        }
      }
      body = parts;
    }
    if (!active.current || controller.current.signal.aborted) throw new DOMException('Workspace closed', 'AbortError');
    const signature = JSON.stringify([method, path, options.version ?? null, body]);
    let key = options.idempotencyKey ?? pending.current.get(signature);
    if (!key) {
      if (pending.current.size >= 16) throw new Error('Too many unconfirmed operations. Review current server state before continuing.');
      key = crypto.randomUUID(); pending.current.set(signature, key);
    }
    try {
      const result = await api<T>(path, { ...options, idempotencyKey: key, signal: controller.current.signal });
      pending.current.delete(signature);
      if (!options.idempotencyKey) reportUnconfirmed(unresolvedToken.current, pending.current.size > 0);
      return result;
    } catch (error) {
      if (!options.idempotencyKey && active.current) reportUnconfirmed(unresolvedToken.current, pending.current.size > 0);
      throw error;
    }
  }
  async function perform(task: () => Promise<void>) {
    if (locked.current || !active.current) return;
    locked.current = true; setBusy(true);
    try { await task(); }
    catch (error) { if (active.current) setMessage(error instanceof Error && error.name !== 'AbortError' ? error.message : 'Request interrupted. Its server outcome is unconfirmed; refresh before retrying.'); }
    finally { locked.current = false; if (active.current) setBusy(false); }
  }
  const say = (text: string) => { if (active.current) setMessage(text); };
  async function fresh(user: User, role?: string) {
    const live = member(await call<User>('/me'));
    if (live.id !== user.id || live.session_id !== user.session_id || (role && !live.roles.includes(role)))
      throw new Error('Your account or grant changed. Sign in again and review the current state.');
    return live;
  }
  return { busy, message, call, perform, say, fresh };
}
