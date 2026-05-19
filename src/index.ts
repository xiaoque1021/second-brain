/**
 * Second Brain — Cloudflare Worker
 * https://github.com/rahilp/second-brain-cloudflare
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createMcpHandler } from "agents/mcp";
import { z } from "zod";

export interface Env {
  DB: D1Database;
  VECTORIZE: VectorizeIndex;
  AI: Ai;
  AUTH_TOKEN?: string;
}

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization, Accept",
};

const DUPLICATE_BLOCK_THRESHOLD = 0.95;
const DUPLICATE_FLAG_THRESHOLD = 0.85;
const DEFAULT_NAMESPACE = "default";
const ALL_NAMESPACES = "*";
const TOKEN_PREFIX = "sb_";
const TOKEN_BYTES = 32;
const NS_RE = /^(default|shared|codex|claude-code|mobile|project:[a-zA-Z0-9_-]+|[a-zA-Z0-9_-]{1,64})$/;

type Role = "admin" | "user";

interface TokenRow {
  id: string;
  label: string;
  token_hash: string;
  token_ciphertext: string | null;
  role: Role;
  default_namespace: string;
  read_namespaces: string;
  write_namespaces: string;
  delete_namespaces: string;
  created_at: number;
  last_used_at: number | null;
  revoked_at: number | null;
}

interface AuthContext {
  token: string;
  tokenHash: string;
  tokenId: string;
  label: string;
  role: Role;
  defaultNamespace: string;
  readNamespaces: string[];
  writeNamespaces: string[];
  deleteNamespaces: string[];
  isLegacy: boolean;
}

interface VectorizeMatch {
  id: string;
  score: number;
  namespace?: string;
  metadata?: Record<string, unknown>;
}

interface RecallEntry {
  id: string;
  content: string;
  tags: string[];
  source: string;
  namespace: string;
  created_at: number;
  score: number;
  isUpdate?: boolean;
}

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "Content-Type": "application/json", ...CORS_HEADERS },
  });
}

function unauthorized(message = "Unauthorized"): Response {
  return json({ error: message }, 401);
}

function forbidden(message = "Forbidden"): Response {
  return json({ error: message }, 403);
}

function getBearerToken(request: Request): string | null {
  const header = request.headers.get("Authorization") || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

function parseJsonArray(value: string | null | undefined, fallback: string[] = []): string[] {
  if (!value) return fallback;
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((v) => typeof v === "string") : fallback;
  } catch {
    return fallback;
  }
}

function normalizeNamespace(ns: unknown, fallback = DEFAULT_NAMESPACE): string {
  const value = typeof ns === "string" && ns.trim() ? ns.trim() : fallback;
  return NS_RE.test(value) ? value : fallback;
}

function normalizeNamespaceList(value: unknown, fallback: string[]): string[] {
  const raw = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(",").map((v) => v.trim()).filter(Boolean)
      : fallback;
  const normalized = raw
    .filter((v): v is string => typeof v === "string")
    .map((v) => v.trim())
    .filter((v) => v === ALL_NAMESPACES || NS_RE.test(v));
  return normalized.length ? Array.from(new Set(normalized)) : fallback;
}

function namespaceAllowed(namespace: string, allowed: string[]): boolean {
  return allowed.includes(ALL_NAMESPACES) || allowed.some((item) => {
    if (item === namespace) return true;
    if (item.endsWith(":*")) return namespace.startsWith(item.slice(0, -1));
    return false;
  });
}

function authInfo(ctx: AuthContext) {
  const namespaces = ctx.writeNamespaces.includes(ALL_NAMESPACES) ? [ctx.defaultNamespace] : ctx.writeNamespaces;
  return {
    id: ctx.tokenId,
    name: ctx.label,
    label: ctx.label,
    role: ctx.role,
    isAdmin: ctx.role === "admin",
    defaultNamespace: ctx.defaultNamespace,
    namespace: ctx.defaultNamespace,
    namespaces,
    allowedNamespaces: namespaces,
    readNamespaces: ctx.readNamespaces,
    writeNamespaces: ctx.writeNamespaces,
    deleteNamespaces: ctx.deleteNamespaces,
    isLegacy: ctx.isLegacy,
  };
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  bytes.forEach((b) => { binary += String.fromCharCode(b); });
  return btoa(binary);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function generateToken(): string {
  const bytes = new Uint8Array(TOKEN_BYTES);
  crypto.getRandomValues(bytes);
  return TOKEN_PREFIX + bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function deriveTokenKey(adminToken: string, tokenHash: string): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(adminToken),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(`second-brain-token:${tokenHash}`),
      iterations: 120000,
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function encryptTokenForAdmin(token: string, adminToken: string, tokenHash: string): Promise<string> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const key = await deriveTokenKey(adminToken, tokenHash);
  const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(token));
  return `${bytesToBase64(iv)}.${bytesToBase64(new Uint8Array(cipher))}`;
}

async function decryptTokenForAdmin(ciphertext: string | null, adminToken: string, tokenHash: string): Promise<string | null> {
  if (!ciphertext) return null;
  const [ivText, dataText] = ciphertext.split(".");
  if (!ivText || !dataText) return null;
  try {
    const key = await deriveTokenKey(adminToken, tokenHash);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(ivText) }, key, base64ToBytes(dataText));
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

async function initializeDatabase(env: Env): Promise<void> {
  try {
    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS entries (
        id TEXT PRIMARY KEY,
        content TEXT NOT NULL,
        tags TEXT NOT NULL DEFAULT '[]',
        source TEXT NOT NULL DEFAULT 'api',
        created_at INTEGER NOT NULL,
        vector_ids TEXT NOT NULL DEFAULT '[]',
        namespace TEXT NOT NULL DEFAULT 'default'
      );
    `);
    await safeAlter(env, "ALTER TABLE entries ADD COLUMN vector_ids TEXT NOT NULL DEFAULT '[]'");
    await safeAlter(env, "ALTER TABLE entries ADD COLUMN namespace TEXT NOT NULL DEFAULT 'default'");
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_entries_created_at ON entries(created_at DESC)`);
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_entries_source ON entries(source)`);
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_entries_namespace ON entries(namespace)`);
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_entries_namespace_created_at ON entries(namespace, created_at DESC)`);
    await env.DB.exec(`
      CREATE TABLE IF NOT EXISTS auth_tokens (
        id TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        token_ciphertext TEXT,
        role TEXT NOT NULL DEFAULT 'user',
        default_namespace TEXT NOT NULL DEFAULT 'default',
        read_namespaces TEXT NOT NULL DEFAULT '["default"]',
        write_namespaces TEXT NOT NULL DEFAULT '["default"]',
        delete_namespaces TEXT NOT NULL DEFAULT '[]',
        created_at INTEGER NOT NULL,
        last_used_at INTEGER,
        revoked_at INTEGER
      );
    `);
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash ON auth_tokens(token_hash)`);
    await env.DB.exec(`CREATE INDEX IF NOT EXISTS idx_auth_tokens_default_namespace ON auth_tokens(default_namespace)`);
  } catch (e) {
    console.error("Database initialization error (non-fatal):", e);
  }
}

async function safeAlter(env: Env, sql: string): Promise<void> {
  try {
    await env.DB.exec(sql);
  } catch (e) {
    const message = (e as Error).message || "";
    if (!message.includes("duplicate column name")) console.error("Migration warning:", message);
  }
}

async function tokenTableHasRows(env: Env): Promise<boolean> {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS count FROM auth_tokens WHERE revoked_at IS NULL`).first() as any;
  return Number(row?.count || 0) > 0;
}

function rowToAuthContext(row: TokenRow, token: string, tokenHash: string): AuthContext {
  const read = parseJsonArray(row.read_namespaces, [row.default_namespace]);
  const write = parseJsonArray(row.write_namespaces, [row.default_namespace]);
  const del = parseJsonArray(row.delete_namespaces, []);
  return {
    token,
    tokenHash,
    tokenId: row.id,
    label: row.label,
    role: row.role === "admin" ? "admin" : "user",
    defaultNamespace: row.default_namespace || DEFAULT_NAMESPACE,
    readNamespaces: row.role === "admin" ? [ALL_NAMESPACES] : read,
    writeNamespaces: row.role === "admin" ? [ALL_NAMESPACES] : write,
    deleteNamespaces: row.role === "admin" ? [ALL_NAMESPACES] : del,
    isLegacy: false,
  };
}

async function getAuthContext(request: Request, env: Env, options: { allowMissingSetup?: boolean } = {}): Promise<AuthContext | null> {
  const token = getBearerToken(request);
  const hasManagedTokens = await tokenTableHasRows(env);
  if (!token) return null;

  const tokenHash = await sha256Hex(token);
  if (hasManagedTokens) {
    const row = await env.DB.prepare(
      `SELECT * FROM auth_tokens WHERE token_hash = ? AND revoked_at IS NULL`
    ).bind(tokenHash).first() as TokenRow | null;
    if (!row) return null;
    await env.DB.prepare(`UPDATE auth_tokens SET last_used_at = ? WHERE id = ?`).bind(Date.now(), row.id).run();
    return rowToAuthContext(row, token, tokenHash);
  }

  if (env.AUTH_TOKEN && token === env.AUTH_TOKEN) {
    return {
      token,
      tokenHash,
      tokenId: "legacy",
      label: "Legacy Admin",
      role: "admin",
      defaultNamespace: DEFAULT_NAMESPACE,
      readNamespaces: [ALL_NAMESPACES],
      writeNamespaces: [ALL_NAMESPACES],
      deleteNamespaces: [ALL_NAMESPACES],
      isLegacy: true,
    };
  }

  return options.allowMissingSetup ? null : null;
}

function requireWriteNamespace(ctx: AuthContext, requested?: unknown): string | Response {
  const namespace = normalizeNamespace(requested, ctx.defaultNamespace);
  return namespaceAllowed(namespace, ctx.writeNamespaces) ? namespace : forbidden(`No write access to namespace: ${namespace}`);
}

async function embed(text: string, env: Env): Promise<number[]> {
  const result = (await env.AI.run("@cf/baai/bge-small-en-v1.5" as any, { text: [text] })) as any;
  return result.data[0] as number[];
}

function chunkText(text: string, maxChars = 1600, overlapChars = 200): string[] {
  if (text.length <= maxChars) return [text];
  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = start + maxChars;
    if (end < text.length) {
      const lastPeriod = text.lastIndexOf(".", end);
      const lastNewline = text.lastIndexOf("\n", end);
      const breakPoint = Math.max(lastPeriod, lastNewline);
      if (breakPoint > start + maxChars / 2) end = breakPoint + 1;
    }
    chunks.push(text.slice(start, Math.min(end, text.length)).trim());
    start = end - overlapChars;
  }
  return chunks.filter((c) => c.length > 0);
}

function getHalfLifeMs(tags: string[]): number {
  if (tags.includes("task")) return 7 * 24 * 60 * 60 * 1000;
  if (tags.includes("context")) return 180 * 24 * 60 * 60 * 1000;
  if (tags.includes("work")) return 90 * 24 * 60 * 60 * 1000;
  return 30 * 24 * 60 * 60 * 1000;
}

function rerankWithTimeDecay(matches: VectorizeMatch[]): VectorizeMatch[] {
  const now = Date.now();
  return matches
    .map((match) => {
      const meta = match.metadata as any;
      const createdAt = meta?.created_at ?? now;
      const tags: string[] = Array.isArray(meta?.tags) ? meta.tags : [];
      const recencyMultiplier = Math.exp(-(now - createdAt) / getHalfLifeMs(tags));
      return { ...match, score: match.score * recencyMultiplier };
    })
    .sort((a, b) => b.score - a.score);
}

async function checkDuplicate(content: string, env: Env, namespace: string): Promise<
  | { status: "unique" }
  | { status: "blocked"; matchId: string; score: number }
  | { status: "flagged"; matchId: string; score: number }
> {
  const sample = content.length <= 1500
    ? content
    : `${content.slice(0, 500)}\n...\n${content.slice(Math.floor(content.length / 2) - 250, Math.floor(content.length / 2) + 250)}\n...\n${content.slice(-500)}`;
  const values = await embed(sample, env);
  const results = await env.VECTORIZE.query(values, { topK: 1, returnMetadata: "all", namespace } as any);
  if (!results.matches.length) return { status: "unique" };
  const top = results.matches[0];
  const score = top.score;
  const matchId = (top.metadata as any)?.parentId ?? top.id;
  if (score >= DUPLICATE_BLOCK_THRESHOLD) return { status: "blocked", matchId, score };
  if (score >= DUPLICATE_FLAG_THRESHOLD) return { status: "flagged", matchId, score };
  return { status: "unique" };
}

async function storeEntry(
  env: Env,
  id: string,
  content: string,
  tags: string[],
  source: string,
  now: number,
  namespace: string,
  mode: "insert" | "upsert" = "insert",
): Promise<string[]> {
  const chunks = chunkText(content);
  const vectors = await Promise.all(chunks.map(async (chunk, i) => {
    const metadata: Record<string, any> = {
      content: chunk.slice(0, 512),
      parentId: id,
      chunkIndex: i,
      totalChunks: chunks.length,
      tags,
      source,
      namespace,
      created_at: now,
    };
    tags.forEach((t) => { metadata[`tag_${t}`] = true; });
    return {
      id: chunks.length === 1 ? id : `${id}-chunk-${i}`,
      values: await embed(chunk, env),
      namespace,
      metadata,
    };
  }));
  if (mode === "upsert") await env.VECTORIZE.upsert(vectors as any);
  else await env.VECTORIZE.insert(vectors as any);
  const vectorIds = vectors.map((v) => v.id);
  await env.DB.prepare(`UPDATE entries SET vector_ids = ? WHERE id = ?`).bind(JSON.stringify(vectorIds), id).run();
  return vectorIds;
}

async function appendToEntry(
  env: Env,
  id: string,
  existingContent: string,
  addition: string,
  tags: string[],
  source: string,
  namespace: string,
): Promise<void> {
  const separator = `\n\n[Update ${new Date().toLocaleDateString()}]: `;
  await env.DB.prepare(`UPDATE entries SET content = ? WHERE id = ? AND namespace = ?`)
    .bind(existingContent + separator + addition, id, namespace).run();
  const newChunkId = `${id}-update-${Date.now()}`;
  const metadata: Record<string, any> = {
    content: addition.slice(0, 512),
    parentId: id,
    isUpdate: true,
    tags,
    source,
    namespace,
    created_at: Date.now(),
  };
  tags.forEach((t) => { metadata[`tag_${t}`] = true; });
  await env.VECTORIZE.insert([{ id: newChunkId, values: await embed(addition, env), namespace, metadata }] as any);
  const row = await env.DB.prepare(`SELECT vector_ids FROM entries WHERE id = ? AND namespace = ?`)
    .bind(id, namespace).first() as Record<string, any> | null;
  const existing: string[] = JSON.parse(row?.vector_ids ?? "[]");
  await env.DB.prepare(`UPDATE entries SET vector_ids = ? WHERE id = ? AND namespace = ?`)
    .bind(JSON.stringify([...existing, newChunkId]), id, namespace).run();
}

async function readableNamespaces(env: Env, ctx: AuthContext, requestedNamespace?: string | null): Promise<string[]> {
  if (requestedNamespace) {
    const namespace = normalizeNamespace(requestedNamespace, ctx.defaultNamespace);
    return namespaceAllowed(namespace, ctx.readNamespaces) ? [namespace] : [];
  }
  if (!ctx.readNamespaces.includes(ALL_NAMESPACES)) return ctx.readNamespaces;
  const { results } = await env.DB.prepare(`SELECT DISTINCT namespace FROM entries ORDER BY namespace`).all();
  const namespaces = (results as Record<string, any>[]).map((row) => String(row.namespace || DEFAULT_NAMESPACE));
  return namespaces.length ? namespaces : [ctx.defaultNamespace];
}

async function recallEntries(env: Env, ctx: AuthContext, query: string, topK: number, tag?: string, requestedNamespace?: string | null): Promise<RecallEntry[]> {
  const readable = await readableNamespaces(env, ctx, requestedNamespace);
  const values = await embed(query, env);
  const matches: VectorizeMatch[] = [];
  for (const namespace of readable) {
    if (!namespaceAllowed(namespace, ctx.readNamespaces)) continue;
    const results = await env.VECTORIZE.query(values, { topK: topK * 3, returnMetadata: "all", namespace } as any);
    matches.push(...(results.matches as VectorizeMatch[]).map((m) => ({ ...m, namespace })));
  }
  const reranked = rerankWithTimeDecay(matches);
  const seen = new Set<string>();
  const candidates = reranked.filter((m) => {
    const parentId = (m.metadata as any)?.parentId ?? m.id;
    const key = `${m.namespace || DEFAULT_NAMESPACE}:${parentId}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  }).slice(0, topK * 2);
  if (!candidates.length) return [];

  const rows: RecallEntry[] = [];
  for (const candidate of candidates) {
    const parentId = ((candidate.metadata as any)?.parentId ?? candidate.id) as string;
    const namespace = candidate.namespace || ((candidate.metadata as any)?.namespace as string) || DEFAULT_NAMESPACE;
    if (!namespaceAllowed(namespace, ctx.readNamespaces)) continue;
    let sql = `SELECT id, content, tags, source, namespace, created_at FROM entries WHERE id = ? AND namespace = ?`;
    const params: (string | number)[] = [parentId, namespace];
    if (tag) { sql += ` AND tags LIKE ?`; params.push(`%"${tag}"%`); }
    const row = await env.DB.prepare(sql).bind(...params).first() as Record<string, any> | null;
    if (!row) continue;
    rows.push({
      id: row.id as string,
      content: row.content as string,
      tags: parseJsonArray(row.tags as string),
      source: row.source as string,
      namespace: row.namespace as string,
      created_at: row.created_at as number,
      score: candidate.score,
      isUpdate: Boolean((candidate.metadata as any)?.isUpdate),
    });
    if (rows.length >= topK) break;
  }
  return rows;
}

function formatRecallRows(rows: RecallEntry[]): string {
  return rows.map((row, i) => {
    const date = new Date(row.created_at).toLocaleDateString();
    const tagList = row.tags.length ? ` [${row.tags.join(", ")}]` : "";
    const updateLabel = row.isUpdate ? " [updated]" : "";
    return `${i + 1}. [${date} · ${row.source} · ${row.namespace}${tagList}] (${(row.score * 100).toFixed(0)}% match)${updateLabel}\nID: ${row.id}\n${row.content}`;
  }).join("\n\n");
}

async function listEntries(env: Env, ctx: AuthContext, n: number, tag?: string, requestedNamespace?: string | null): Promise<Record<string, any>[]> {
  const namespaces = await readableNamespaces(env, ctx, requestedNamespace);
  if (!namespaces.length) return [];
  const placeholders = namespaces.map(() => "?").join(", ");
  const params: (string | number)[] = [...namespaces];
  let sql = `SELECT id, content, tags, source, namespace, created_at FROM entries WHERE namespace IN (${placeholders})`;
  if (tag) { sql += ` AND tags LIKE ?`; params.push(`%"${tag}"%`); }
  sql += ` ORDER BY created_at DESC LIMIT ?`;
  params.push(n);
  const { results } = await env.DB.prepare(sql).bind(...params).all();
  return results as Record<string, any>[];
}

function buildMcpServer(env: Env, ctx: AuthContext): McpServer {
  const server = new McpServer({ name: "second-brain", version: "1.0.0" });

  server.tool(
    "remember",
    "Store an idea, task, or note in your second brain.",
    {
      content: z.string(),
      tags: z.array(z.string()).optional(),
      source: z.string().optional(),
      namespace: z.string().optional(),
    },
    async ({ content, tags, source, namespace }) => {
      const ns = requireWriteNamespace(ctx, namespace);
      if (ns instanceof Response) return { content: [{ type: "text", text: "No write access to that namespace." }] };
      const c = content.trim();
      const t = tags ?? [];
      const s = source ?? ctx.label;
      const dup = await checkDuplicate(c, env, ns);
      if (dup.status === "blocked") {
        return { content: [{ type: "text", text: `Duplicate detected (${(dup.score * 100).toFixed(0)}% match) — not stored. Existing entry ID: ${dup.matchId}` }] };
      }
      const id = crypto.randomUUID();
      const now = Date.now();
      const finalTags = dup.status === "flagged" ? [...t, "duplicate-candidate"] : t;
      await env.DB.prepare(
        `INSERT INTO entries (id, content, tags, source, created_at, vector_ids, namespace) VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).bind(id, c, JSON.stringify(finalTags), s, now, "[]", ns).run();
      await storeEntry(env, id, c, finalTags, s, now, ns).catch((e) => console.error("Vectorize insert failed:", e));
      return { content: [{ type: "text", text: `Stored. ID: ${id} Namespace: ${ns}` }] };
    },
  );

  server.tool(
    "append",
    "Append new information to an existing entry in your second brain.",
    { id: z.string(), addition: z.string() },
    async ({ id, addition }) => {
      const row = await env.DB.prepare(`SELECT id, content, tags, source, namespace FROM entries WHERE id = ?`).bind(id).first() as Record<string, any> | null;
      if (!row || !namespaceAllowed(row.namespace as string, ctx.writeNamespaces)) {
        return { content: [{ type: "text", text: `No writable entry found with ID: ${id}` }] };
      }
      const a = addition.trim();
      if (!a) return { content: [{ type: "text", text: "Addition cannot be empty." }] };
      await appendToEntry(env, id, row.content as string, a, parseJsonArray(row.tags as string), row.source as string, row.namespace as string);
      return { content: [{ type: "text", text: `Appended to entry ${id}.` }] };
    },
  );

  server.tool(
    "recall",
    "Semantically search your second brain for relevant notes and context.",
    { query: z.string(), topK: z.number().int().min(1).max(20).default(5), tag: z.string().optional(), namespace: z.string().optional() },
    async ({ query, topK, tag, namespace }) => {
      const rows = await recallEntries(env, ctx, query, topK, tag, namespace);
      return { content: [{ type: "text", text: rows.length ? formatRecallRows(rows) : "Nothing found matching that query." }] };
    },
  );

  server.tool(
    "list_recent",
    "List the most recent entries by date from your second brain.",
    { n: z.number().int().min(1).max(50).default(10), tag: z.string().optional() },
    async ({ n, tag }) => {
      const rows = await listEntries(env, ctx, n, tag);
      if (!rows.length) return { content: [{ type: "text", text: "No entries found." }] };
      const text = rows.map((row, i) => {
        const tags = parseJsonArray(row.tags as string);
        const tagStr = tags.length ? ` · ${tags.join(", ")}` : "";
        return `${i + 1}. [${new Date(row.created_at as number).toLocaleDateString()} · ${row.source} · ${row.namespace}${tagStr}]\nID: ${row.id}\n${row.content}`;
      }).join("\n\n");
      return { content: [{ type: "text", text }] };
    },
  );

  server.tool(
    "forget",
    "Permanently delete an entry from your second brain by ID.",
    { id: z.string() },
    async ({ id }) => {
      const row = await env.DB.prepare(`SELECT namespace, vector_ids FROM entries WHERE id = ?`).bind(id).first() as Record<string, any> | null;
      if (!row || !namespaceAllowed(row.namespace as string, ctx.deleteNamespaces)) {
        return { content: [{ type: "text", text: `No deletable entry found with ID: ${id}` }] };
      }
      const vectorIds: string[] = parseJsonArray(row.vector_ids as string);
      await env.DB.prepare(`DELETE FROM entries WHERE id = ? AND namespace = ?`).bind(id, row.namespace).run();
      if (vectorIds.length) await env.VECTORIZE.deleteByIds(vectorIds).catch((e) => console.error("Vectorize delete failed:", e));
      return { content: [{ type: "text", text: `Deleted entry ${id} and ${vectorIds.length} vector(s)` }] };
    },
  );

  return server;
}

function sanitizeTokenRow(row: TokenRow, adminToken?: string) {
  const read = parseJsonArray(row.read_namespaces);
  const write = parseJsonArray(row.write_namespaces);
  const del = parseJsonArray(row.delete_namespaces);
  const namespaces = row.role === "admin" ? [ALL_NAMESPACES] : Array.from(new Set([...read, ...write, ...del]));
  return {
    id: row.id,
    name: row.label,
    label: row.label,
    role: row.role,
    namespace: row.default_namespace,
    namespaces,
    allowedNamespaces: namespaces,
    defaultNamespace: row.default_namespace,
    readNamespaces: read,
    writeNamespaces: write,
    deleteNamespaces: del,
    createdAt: row.created_at,
    expiresAt: null,
    revoked: Boolean(row.revoked_at),
    lastUsedAt: row.last_used_at,
    revokedAt: row.revoked_at,
    tokenAvailable: Boolean(row.token_ciphertext),
    token: adminToken,
  };
}

async function adminListTokens(env: Env, ctx: AuthContext): Promise<Response> {
  const { results } = await env.DB.prepare(`SELECT * FROM auth_tokens ORDER BY created_at DESC`).all();
  const rows = results as unknown as TokenRow[];
  const tokens = await Promise.all(rows.map(async (row) => {
    const out: any = sanitizeTokenRow(row);
    out.token = await decryptTokenForAdmin(row.token_ciphertext, ctx.token, row.token_hash);
    return out;
  }));
  return json({ tokens });
}

async function createToken(env: Env, ctx: AuthContext, body: any, role: Role = "user"): Promise<Response> {
  const token = generateToken();
  const tokenHash = await sha256Hex(token);
  const frontNamespaces = body.namespaces || body.allowedNamespaces;
  const defaultNamespace = normalizeNamespace(body.defaultNamespace || body.default_namespace || body.namespace || frontNamespaces?.[0], DEFAULT_NAMESPACE);
  const frontRole = body.role === "reader" ? "reader" : body.role === "writer" ? "writer" : role;
  const read = role === "admin" ? [ALL_NAMESPACES] : normalizeNamespaceList(body.readNamespaces || body.read_namespaces || frontNamespaces, [defaultNamespace]);
  const write = role === "admin" ? [ALL_NAMESPACES] : frontRole === "reader" ? [] : normalizeNamespaceList(body.writeNamespaces || body.write_namespaces || frontNamespaces, [defaultNamespace]);
  const del = role === "admin" ? [ALL_NAMESPACES] : normalizeNamespaceList(body.deleteNamespaces || body.delete_namespaces, []);
  const cipher = await encryptTokenForAdmin(token, ctx.token, tokenHash);
  const id = crypto.randomUUID();
  const now = Date.now();
  await env.DB.prepare(
    `INSERT INTO auth_tokens (id, label, token_hash, token_ciphertext, role, default_namespace, read_namespaces, write_namespaces, delete_namespaces, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, String(body.label || body.name || "New Token"), tokenHash, cipher, role, defaultNamespace, JSON.stringify(read), JSON.stringify(write), JSON.stringify(del), now).run();
  const record = { id, name: body.label || body.name || "New Token", label: body.label || body.name || "New Token", role, defaultNamespace, namespace: defaultNamespace, namespaces: Array.from(new Set([...read, ...write, ...del])), readNamespaces: read, writeNamespaces: write, deleteNamespaces: del, createdAt: now, expiresAt: null, revoked: false };
  return json({ ...record, token, tokenRecord: record }, 201);
}

async function updateToken(env: Env, id: string, body: any): Promise<Response> {
  const existing = await env.DB.prepare(`SELECT * FROM auth_tokens WHERE id = ?`).bind(id).first() as TokenRow | null;
  if (!existing) return json({ error: "Token not found" }, 404);
  const frontNamespaces = body.namespaces || body.allowedNamespaces;
  const defaultNamespace = normalizeNamespace(body.defaultNamespace || body.default_namespace || body.namespace || frontNamespaces?.[0], existing.default_namespace);
  const role = body.role === "admin" ? "admin" : "user";
  const frontRole = body.role === "reader" ? "reader" : body.role === "writer" ? "writer" : role;
  const read = role === "admin" ? [ALL_NAMESPACES] : normalizeNamespaceList(body.readNamespaces || body.read_namespaces || frontNamespaces, parseJsonArray(existing.read_namespaces, [defaultNamespace]));
  const write = role === "admin" ? [ALL_NAMESPACES] : frontRole === "reader" ? [] : normalizeNamespaceList(body.writeNamespaces || body.write_namespaces || frontNamespaces, parseJsonArray(existing.write_namespaces, [defaultNamespace]));
  const del = role === "admin" ? [ALL_NAMESPACES] : normalizeNamespaceList(body.deleteNamespaces || body.delete_namespaces, parseJsonArray(existing.delete_namespaces, []));
  await env.DB.prepare(
    `UPDATE auth_tokens SET label = ?, role = ?, default_namespace = ?, read_namespaces = ?, write_namespaces = ?, delete_namespaces = ? WHERE id = ?`
  ).bind(String(body.label || body.name || existing.label), role, defaultNamespace, JSON.stringify(read), JSON.stringify(write), JSON.stringify(del), id).run();
  return json({ ok: true });
}

async function reindexEntries(env: Env): Promise<Response> {
  const { results } = await env.DB.prepare(`SELECT id, content, tags, source, namespace, created_at FROM entries ORDER BY created_at ASC`).all();
  let count = 0;
  for (const row of results as Record<string, any>[]) {
    await storeEntry(
      env,
      row.id as string,
      row.content as string,
      parseJsonArray(row.tags as string),
      row.source as string,
      row.created_at as number,
      normalizeNamespace(row.namespace, DEFAULT_NAMESPACE),
      "upsert",
    );
    count++;
  }
  return json({ ok: true, reindexed: count });
}

async function handleApi(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  await initializeDatabase(env);

  if (request.method === "OPTIONS") return new Response(null, { headers: CORS_HEADERS });

  if (url.pathname === "/auth/status" && request.method === "GET") {
    return json({ setupRequired: !(await tokenTableHasRows(env)), legacyAvailable: Boolean(env.AUTH_TOKEN) });
  }

  if (url.pathname === "/auth/setup" && request.method === "POST") {
    if (await tokenTableHasRows(env)) return forbidden("Setup already completed");
    let body: any = {};
    try { body = await request.json(); } catch { }
    const token = String(body.token || generateToken()).trim();
    const tokenHash = await sha256Hex(token);
    const cipher = await encryptTokenForAdmin(token, token, tokenHash);
    const id = crypto.randomUUID();
    const now = Date.now();
    const defaultNamespace = normalizeNamespace(body.defaultNamespace || body.namespace, DEFAULT_NAMESPACE);
    await env.DB.prepare(
      `INSERT INTO auth_tokens (id, label, token_hash, token_ciphertext, role, default_namespace, read_namespaces, write_namespaces, delete_namespaces, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, String(body.label || body.name || "Admin"), tokenHash, cipher, "admin", defaultNamespace, JSON.stringify([ALL_NAMESPACES]), JSON.stringify([ALL_NAMESPACES]), JSON.stringify([ALL_NAMESPACES]), now).run();
    return json({ id, token, name: body.label || body.name || "Admin", label: body.label || body.name || "Admin", role: "admin", isAdmin: true, defaultNamespace, namespace: defaultNamespace, namespaces: [defaultNamespace], readNamespaces: [ALL_NAMESPACES], writeNamespaces: [ALL_NAMESPACES], deleteNamespaces: [ALL_NAMESPACES] }, 201);
  }

  const auth = await getAuthContext(request, env);
  if (!auth) return unauthorized();

  if (url.pathname === "/auth/me" && request.method === "GET") return json(authInfo(auth));

  if (url.pathname === "/admin/tokens" && request.method === "GET") {
    if (auth.role !== "admin") return forbidden();
    return adminListTokens(env, auth);
  }
  if (url.pathname === "/admin/tokens" && request.method === "POST") {
    if (auth.role !== "admin") return forbidden();
    let body: any;
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
    return createToken(env, auth, body, body.role === "admin" ? "admin" : "user");
  }
  const tokenPath = url.pathname.match(/^\/admin\/tokens\/([^/]+)(?:\/(revoke))?$/);
  if (tokenPath) {
    if (auth.role !== "admin") return forbidden();
    const id = tokenPath[1];
    if ((request.method === "PUT" || request.method === "PATCH") && !tokenPath[2]) {
      let body: any;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
      return updateToken(env, id, body);
    }
    if ((request.method === "POST" && tokenPath[2] === "revoke") || (request.method === "DELETE" && !tokenPath[2])) {
      await env.DB.prepare(`UPDATE auth_tokens SET revoked_at = ? WHERE id = ?`).bind(Date.now(), id).run();
      return json({ ok: true });
    }
  }
  if (url.pathname === "/admin/reindex" && request.method === "POST") {
    if (auth.role !== "admin") return forbidden();
    return reindexEntries(env);
  }

  if (url.pathname === "/capture" && request.method === "POST") {
    let body: { content?: string; tags?: string[]; source?: string; namespace?: string };
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
    if (!body.content?.trim()) return json({ error: "content is required" }, 400);
    const ns = requireWriteNamespace(auth, body.namespace);
    if (ns instanceof Response) return ns;
    const c = body.content.trim();
    const t = body.tags ?? [];
    const s = body.source ?? auth.label ?? "api";
    const dup = await checkDuplicate(c, env, ns);
    if (dup.status === "blocked") {
      return json({ ok: false, duplicate: true, matchId: dup.matchId, score: parseFloat((dup.score * 100).toFixed(1)), message: "Near-exact duplicate detected — not stored" });
    }
    const id = crypto.randomUUID();
    const now = Date.now();
    const finalTags = dup.status === "flagged" ? [...t, "duplicate-candidate"] : t;
    await env.DB.prepare(
      `INSERT INTO entries (id, content, tags, source, created_at, vector_ids, namespace) VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, c, JSON.stringify(finalTags), s, now, "[]", ns).run();
    ctx.waitUntil(storeEntry(env, id, c, finalTags, s, now, ns).catch((e) => console.error("Async embed failed:", e)));
    return json({ ok: true, id, namespace: ns, ...(dup.status === "flagged" ? { warning: "similar", matchId: dup.matchId, score: parseFloat((dup.score * 100).toFixed(1)) } : {}) });
  }

  if (url.pathname === "/append" && request.method === "POST") {
    let body: { id?: string; addition?: string };
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
    if (!body.id?.trim() || !body.addition?.trim()) return json({ error: "id and addition are required" }, 400);
    const row = await env.DB.prepare(`SELECT id, content, tags, source, namespace FROM entries WHERE id = ?`).bind(body.id.trim()).first() as Record<string, any> | null;
    if (!row || !namespaceAllowed(row.namespace as string, auth.writeNamespaces)) return forbidden("No write access to this entry");
    await appendToEntry(env, row.id as string, row.content as string, body.addition.trim(), parseJsonArray(row.tags as string), row.source as string, row.namespace as string);
    return json({ ok: true, id: row.id, namespace: row.namespace });
  }

  if (url.pathname === "/tags" && request.method === "GET") {
    const rows = await listEntries(env, auth, 1000, undefined, url.searchParams.get("namespace"));
    const tags = new Set<string>();
    rows.forEach((row) => parseJsonArray(row.tags as string).forEach((tag) => tags.add(tag)));
    return json([...tags].sort());
  }

  if (url.pathname === "/list" && request.method === "GET") {
    const n = Math.min(parseInt(url.searchParams.get("n") ?? "20", 10), 100);
    const tag = url.searchParams.get("tag") || undefined;
    return json(await listEntries(env, auth, n, tag, url.searchParams.get("namespace")));
  }

  if (url.pathname === "/mcp") {
    const server = buildMcpServer(env, auth);
    return createMcpHandler(server)(request, env, ctx);
  }

  if (url.pathname === "/chat" && request.method === "POST") {
    let body: { query?: string; memories?: string; namespace?: string };
    try { body = await request.json(); } catch { return json({ error: "Invalid JSON" }, 400); }
    if (!body.query?.trim()) return json({ error: "query is required" }, 400);
    const chatNamespaces = await readableNamespaces(env, auth, body.namespace);
    if (!chatNamespaces.length) return forbidden("No read access for chat");
    const systemPrompt = `You are a personal memory assistant. Answer the user's question using ONLY the memories provided. Be concise.`;
    const stream = await env.AI.run("@cf/meta/llama-4-scout-17b-16e-instruct" as any, {
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: `Question: ${body.query}\n\nRelevant memories:\n${body.memories}` },
      ],
      stream: true,
    });
    return new Response(stream as ReadableStream, { headers: { "Content-Type": "text/event-stream", ...CORS_HEADERS } });
  }

  return new Response("Not found", { status: 404 });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    return handleApi(request, env, ctx);
  },
};
