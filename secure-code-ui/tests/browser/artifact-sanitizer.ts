import { spawnSync } from "node:child_process";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { basename, dirname, extname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { SUBMITTED_SOURCE_SECRET } from "./support";

const OUTPUT_DIR = resolve("test-results/browser-artifacts");
const TRACE_TEXT_EXTENSIONS = new Set([".trace", ".network", ".stacks", ".json", ".txt"]);

function secretValues(): string[] {
  return [
    process.env.SCCAP_BROWSER_EMAIL,
    process.env.SCCAP_BROWSER_PASSWORD,
    SUBMITTED_SOURCE_SECRET,
    "ephemeral-browser-fixture-key",
  ].filter((value): value is string => Boolean(value));
}

function replaceKnownBytes(buffer: Buffer): Buffer {
  const output = Buffer.from(buffer);
  for (const secret of secretValues()) {
    const needle = Buffer.from(secret);
    let offset = output.indexOf(needle);
    while (offset >= 0) {
      output.fill(42, offset, offset + needle.length);
      offset = output.indexOf(needle, offset + needle.length);
    }
  }
  return output;
}

function looksTextual(buffer: Buffer, path: string): boolean {
  if (TRACE_TEXT_EXTENSIONS.has(extname(path))) return true;
  if (buffer.includes(0)) return false;
  const sample = buffer.subarray(0, Math.min(buffer.length, 4096));
  if (sample.length === 0) return true;
  let printable = 0;
  for (const byte of sample) {
    if (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126)) {
      printable += 1;
    }
  }
  return printable / sample.length > 0.9;
}

function redactFile(path: string): void {
  const original = readFileSync(path);
  let redacted = replaceKnownBytes(original);
  if (looksTextual(redacted, path)) {
    let text = redacted.toString("utf8");
    text = text
      .replace(/Bearer\s+[A-Za-z0-9._~-]+/g, "Bearer <redacted>")
      .replace(/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "<redacted-jwt>")
      .replace(/("accessToken"\s*:\s*")[^"]+("?)/g, "$1<redacted>$2")
      .replace(/SecureCodePlatformRefresh=[^;"\s]+/g, "SecureCodePlatformRefresh=<redacted>");
    redacted = Buffer.from(text);
  }
  writeFileSync(path, redacted);
}

function walkFiles(root: string): string[] {
  if (!existsSync(root)) return [];
  const files: string[] = [];
  for (const entry of readdirSync(root)) {
    const path = join(root, entry);
    if (statSync(path).isDirectory()) files.push(...walkFiles(path));
    else files.push(path);
  }
  return files;
}

function sanitizeTrace(tracePath: string): void {
  const temp = mkdtempSync(join(tmpdir(), "sccap-browser-trace-"));
  const unpacked = join(temp, "trace");
  const replacement = join(temp, "trace.zip");
  try {
    const unzip = spawnSync("unzip", ["-qq", tracePath, "-d", unpacked]);
    if (unzip.status !== 0) throw new Error(`could not unpack ${basename(tracePath)}`);
    for (const file of walkFiles(unpacked)) redactFile(file);
    const zip = spawnSync("zip", ["-qr", replacement, "."], { cwd: unpacked });
    if (zip.status !== 0) throw new Error(`could not repack ${basename(tracePath)}`);
    renameSync(replacement, tracePath);
  } catch (error) {
    rmSync(tracePath, { force: true });
    writeFileSync(
      join(dirname(tracePath), "trace-redaction-failed.txt"),
      `${error instanceof Error ? error.message : "trace redaction failed"}\nTrace removed to fail closed.\n`,
    );
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

export function sanitizeBrowserArtifacts(): void {
  if (!existsSync(OUTPUT_DIR)) return;
  const traces = walkFiles(OUTPUT_DIR).filter((path) => basename(path) === "trace.zip");
  for (const trace of traces) sanitizeTrace(trace);
  for (const file of walkFiles(OUTPUT_DIR)) {
    if (basename(file) !== "trace.zip" && looksTextual(readFileSync(file), file)) {
      redactFile(file);
    }
  }
  writeFileSync(
    join(OUTPUT_DIR, "credential-safety.txt"),
    "Failure artifacts were sanitized for fixture credentials, submitted-source markers, bearer tokens, refresh cookies, and JWTs.\n",
  );
}
