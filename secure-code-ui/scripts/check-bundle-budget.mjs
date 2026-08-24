import { readFile, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const DIST = new URL("../dist/", import.meta.url);
const KIB = 1024;
const LIMITS = Object.freeze({
  entryJavaScript: 360 * KIB,
  asyncJavaScript: 315 * KIB,
  totalJavaScript: 1_200 * KIB,
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
