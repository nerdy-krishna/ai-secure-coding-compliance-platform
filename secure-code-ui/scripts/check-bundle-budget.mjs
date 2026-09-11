import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const DIST = new URL("../dist/", import.meta.url);
const KIB = 1024;
const LIMITS = Object.freeze({
  entryJavaScript: 360 * KIB,
  asyncJavaScript: 315 * KIB,
  // Pentesting adds lazy cockpit, report, governance, tool-observation,
  // finding-lifecycle, threat-model, durable work-ledger and protocol/state views. Keep the per-entry and
  // per-async caps unchanged while reserving their measured aggregate footprint.
  // Dedicated Pentesting project/settings/submission pages and shared run management are lazy-loaded.
  // Tenant network selection and terminal failure details add less than 2 KiB.
  // Collected-artifact detail viewer adds about 2 KiB in the lazy cockpit.
  // Unified observations, per-row validation history and evidence links add about 4 KiB.
  // Visible stop controls with stale-attempt protection add about 1.4 KiB.
  // Credential login settings and encrypted-session management add about 4 KiB.
  // MFA request controls and explicit SSO destinations add about 3 KiB.
  // Live authentication browser controls add about 3.4 KiB to the lazy cockpit.
  // Evidence-derived workflow review adds about 4 KiB in the lazy cockpit.
  totalJavaScript: 1_312 * KIB,
  stylesheet: 64 * KIB,
});

const manifest = JSON.parse(
  await readFile(new URL(".vite/manifest.json", DIST), "utf8"),
);
const entryFiles = new Set(
  Object.values(manifest)
    .filter((chunk) => chunk.isEntry)
    .map((chunk) => chunk.file),
);
const assetsDir = new URL("assets/", DIST);
const assetsPath = fileURLToPath(assetsDir);
const assets = await readdir(assetsDir);
let totalJavaScript = 0;
const violations = [];

function check(label, bytes, limit) {
  if (bytes > limit) {
    violations.push(`${label}: ${(bytes / KIB).toFixed(1)} KiB > ${(limit / KIB).toFixed(1)} KiB`);
  }
}

for (const name of assets.sort()) {
  const bytes = (await stat(join(assetsPath, name))).size;
  const relative = `assets/${name}`;
  if (name.endsWith(".js")) {
    totalJavaScript += bytes;
    const isEntry = entryFiles.has(relative);
    check(
      isEntry ? `entry ${name}` : `async ${name}`,
      bytes,
      isEntry ? LIMITS.entryJavaScript : LIMITS.asyncJavaScript,
    );
  } else if (name.endsWith(".css")) {
    check(`stylesheet ${name}`, bytes, LIMITS.stylesheet);
  }
}
check("total JavaScript", totalJavaScript, LIMITS.totalJavaScript);

if (violations.length) {
  console.error("Bundle budget exceeded:\n" + violations.map((item) => `- ${item}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(
    `Bundle budget passed: ${(totalJavaScript / KIB).toFixed(1)} KiB JavaScript; ` +
      `${entryFiles.size} entry chunk(s).`,
  );
}
