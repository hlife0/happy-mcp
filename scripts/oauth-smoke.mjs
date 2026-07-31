#!/usr/bin/env node
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const configuredPublicUrl = process.env.HAPPY_MCP_SMOKE_URL?.trim();
if (!configuredPublicUrl) throw new Error('HAPPY_MCP_SMOKE_URL is required');
const publicUrl = configuredPublicUrl.replace(/\/+$/, '');
const adminUrl = (process.env.HAPPY_MCP_SMOKE_ADMIN_URL || 'http://127.0.0.1:3021').replace(/\/+$/, '');
const passwordFile = process.env.HAPPY_MCP_ADMIN_PASSWORD_FILE || join(homedir(), 'happy-mcp-data', 'admin-password.txt');
const resource = `${publicUrl}/mcp`;
const redirectUri = 'http://127.0.0.1/callback';
const verifier = randomBytes(48).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const state = randomBytes(16).toString('base64url');
const adminPassword = readFileSync(passwordFile, 'utf8').trim();

const registration = await jsonRequest(`${publicUrl}/register`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    redirect_uris: [redirectUri],
    token_endpoint_auth_method: 'none',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    client_name: `Happy MCP smoke ${new Date().toISOString()}`,
  }),
}, 201);

const authorization = new URL(`${publicUrl}/authorize`);
authorization.search = new URLSearchParams({
  response_type: 'code',
  client_id: registration.client_id,
  redirect_uri: redirectUri,
  code_challenge: challenge,
  code_challenge_method: 'S256',
  scope: 'happy:read happy:control',
  state,
  resource,
}).toString();
const consentPage = await fetchChecked(authorization, { redirect: 'manual' }, 200);
if (!(await consentPage.text()).includes('Authorize Happy MCP')) throw new Error('OAuth consent page was not returned');

const consent = await fetchChecked(`${publicUrl}/authorize`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    response_type: 'code',
    client_id: registration.client_id,
    redirect_uri: redirectUri,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    scope: 'happy:read happy:control',
    state,
    resource,
    admin_password: adminPassword,
    decision: 'allow',
  }),
}, 302);
const callback = new URL(requiredHeader(consent, 'location'));
if (callback.searchParams.get('state') !== state) throw new Error('OAuth state did not round-trip');
const code = callback.searchParams.get('code');
if (!code) throw new Error(`OAuth authorization failed: ${callback.search}`);

const tokens = await jsonRequest(`${publicUrl}/token`, {
  method: 'POST',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: registration.client_id,
    code,
    code_verifier: verifier,
    redirect_uri: redirectUri,
    resource,
  }),
}, 200);

const initialize = await mcpRequest(tokens.access_token, null, {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-11-25',
    capabilities: {},
    clientInfo: { name: 'happy-mcp-smoke', version: '1.0.0' },
  },
});
const sessionId = requiredHeader(initialize.response, 'mcp-session-id');
if (initialize.body.result?.serverInfo?.name !== 'happy-agent-bridge') throw new Error('Unexpected MCP server identity');
const instructions = initialize.body.result?.instructions || '';
for (const required of [
  'Never send more than one instruction to the same session at a time',
  'poll happy_session_history every few seconds',
  'call happy_stop_session',
  'latest turn-start must have a matching turn-end',
]) {
  if (!instructions.includes(required)) throw new Error(`MCP operating instructions are missing: ${required}`);
}
await mcpRequest(tokens.access_token, sessionId, { jsonrpc: '2.0', method: 'notifications/initialized' }, [200, 202, 204]);
const listed = await mcpRequest(tokens.access_token, sessionId, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} });
const toolNames = listed.body.result?.tools?.map((tool) => tool.name) || [];
const expectedTools = [
  'happy_list_machines',
  'happy_list_sessions',
  'happy_session_status',
  'happy_session_history',
  'happy_spawn_session',
  'happy_send_message',
  'happy_wait_session',
  'happy_resume_session',
  'happy_stop_session',
].sort();
if (JSON.stringify([...toolNames].sort()) !== JSON.stringify(expectedTools)) {
  throw new Error(`Unexpected Happy MCP tool surface: ${toolNames.join(', ')}`);
}

const login = await fetchChecked(`${adminUrl}/login`, {
  method: 'POST',
  redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ password: adminPassword }),
}, 303);
const cookie = requiredHeader(login, 'set-cookie').split(';', 1)[0];
const dashboard = await fetchChecked(`${adminUrl}/`, { headers: { cookie } }, 200);
const dashboardHtml = await dashboard.text();
const csrfToken = dashboardHtml.match(/name="csrf_token" value="([^"]+)"/)?.[1];
if (!csrfToken) throw new Error('Admin CSRF token was not found');
await fetchChecked(`${adminUrl}/clients/${encodeURIComponent(registration.client_id)}/revoke`, {
  method: 'POST',
  redirect: 'manual',
  headers: { cookie, 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ csrf_token: csrfToken }),
}, 303);

const revoked = await fetch(resource, {
  method: 'POST',
  headers: mcpHeaders(tokens.access_token),
  body: JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'ping' }),
  signal: AbortSignal.timeout(20_000),
});
if (revoked.status !== 401) throw new Error(`Revoked access token returned HTTP ${revoked.status}`);

console.log(JSON.stringify({
  ok: true,
  oauthClient: registration.client_id,
  mcpSession: sessionId,
  toolCount: toolNames.length,
  revokedTokenStatus: revoked.status,
}));

async function mcpRequest(token, sessionId, body, expectedStatus = 200) {
  const headers = mcpHeaders(token);
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const response = await fetchChecked(resource, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  }, expectedStatus);
  const text = await response.text();
  return { response, body: text ? JSON.parse(text) : {} };
}

function mcpHeaders(token) {
  return {
    authorization: `Bearer ${token}`,
    accept: 'application/json, text/event-stream',
    'content-type': 'application/json',
  };
}

async function jsonRequest(url, options, expectedStatus) {
  const response = await fetchChecked(url, options, expectedStatus);
  return response.json();
}

async function fetchChecked(url, options, expectedStatus) {
  const response = await fetch(url, { ...options, signal: AbortSignal.timeout(20_000) });
  const expected = Array.isArray(expectedStatus) ? expectedStatus : [expectedStatus];
  if (!expected.includes(response.status)) {
    const text = await response.text();
    throw new Error(`${options.method || 'GET'} ${url} returned HTTP ${response.status}: ${text.slice(0, 500)}`);
  }
  return response;
}

function requiredHeader(response, name) {
  const value = response.headers.get(name);
  if (!value) throw new Error(`Response did not contain ${name}`);
  return value;
}
