// Backend selection: the shared library always lives in the GitHub repo.

import { makeGhApi } from './gh.js';

let active = null;

export async function selectBackend() {
  active = makeGhApi();
  return active;
}

export function backendKind() {
  return 'github';
}

export const api = new Proxy({}, {
  get(_t, prop) {
    if (!active) throw new Error('Backend not ready — call selectBackend() first.');
    return active[prop];
  },
});
