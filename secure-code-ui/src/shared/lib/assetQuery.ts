// secure-code-ui/src/shared/lib/assetQuery.ts
//
// A query language for the asset list, the way an operator actually searches.
//
// Dropdowns answer "show me web apps in production". They cannot answer "show me anything on
// port 5432 that is unreachable and owned by the dba team". A one-line query can, and it is
// faster to type than four selects and two mousemoves.
//
// Grammar (all terms are ANDed; `-` negates; quotes group words):
//
//   port=5432 host=internal env=production unreachable -kind=database db
//
// Recognised fields: name, owner, kind, env (environment), host, port, tech (technology),
// status (up|filtered|down|never), reachable/unreachable as shorthands. An unqualified term
// searches every text field. Unknown fields fall back to free text, so a typo degrades into a
// broader search instead of returning nothing.

import type { Asset } from "../api/assetsService";

export interface ParsedQuery {
  terms: Array<{ field: string; value: string; negated: boolean }>;
  freeText: string[];
}

const FIELDS = new Set([
  "name",
  "owner",
  "kind",
  "env",
  "environment",
  "host",
  "port",
  "tech",
  "technology",
  "status",
  "reachable",
  "unreachable",
]);

/** Split on whitespace, keeping quoted phrases together. */
function tokenize(input: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quoted = false;
  for (const char of input) {
    if (char === '"') {
      quoted = !quoted;
      continue;
    }
    if (!quoted && /\s/.test(char)) {
      if (current) tokens.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  if (current) tokens.push(current);
  return tokens;
}

export function parseAssetQuery(input: string): ParsedQuery {
  const parsed: ParsedQuery = { terms: [], freeText: [] };
  for (const raw of tokenize(input || "")) {
    let token = raw;
    let negated = false;
    if (token.startsWith("-")) {
      negated = true;
      token = token.slice(1);
    }
    const match = /^([a-z]+)[:=](.+)$/i.exec(token);
    if (match && FIELDS.has(match[1].toLowerCase())) {
      parsed.terms.push({ field: match[1].toLowerCase(), value: match[2], negated });
    } else if (token === "reachable" || token === "unreachable" || token === "filtered") {
      parsed.terms.push({ field: "status", value: token, negated });
    } else if (token) {
      parsed.freeText.push(negated ? `-${token}` : token);
    }
  }
  return parsed;
}

function stateOf(asset: Asset): string {
  if (asset.reachable === true) return "up";
  if (asset.reachable === false) {
    return asset.unreachable_reason === "filtered" ? "filtered" : "down";
  }
  return "never";
}

function matchesTerm(asset: Asset, field: string, value: string): boolean {
  const needle = value.toLowerCase();
  switch (field) {
    case "name":
      return asset.name.toLowerCase().includes(needle);
    case "owner":
      return (asset.owner ?? "").toLowerCase().includes(needle);
    case "kind":
      return asset.kind.toLowerCase() === needle || asset.kind.toLowerCase().includes(needle);
    case "env":
    case "environment":
      return (asset.environment ?? "").toLowerCase().includes(needle);
    case "host":
      return (asset.hosts ?? []).some((host) => host.toLowerCase().includes(needle));
    case "port":
      return (asset.ports ?? []).some((port) => String(port) === needle);
    case "tech":
    case "technology":
      return (asset.technology_names ?? []).some((tech) => tech.toLowerCase().includes(needle));
    case "status":
      return stateOf(asset) === needle;
    case "reachable":
      return asset.reachable === true;
    case "unreachable":
      return asset.reachable === false;
    default:
      return true;
  }
}

export function filterByQuery(assets: Asset[], input: string): Asset[] {
  const query = parseAssetQuery(input);
  if (!query.terms.length && !query.freeText.length) return assets;
  const freePositives = query.freeText.filter((term) => !term.startsWith("-")).map((t) => t.toLowerCase());
  const freeNegatives = query.freeText
    .filter((term) => term.startsWith("-"))
    .map((term) => term.slice(1).toLowerCase());

  return assets.filter((asset) => {
    for (const term of query.terms) {
      const hit = matchesTerm(asset, term.field, term.value);
      if (term.negated ? hit : !hit) return false;
    }
    const haystack = [
      asset.name,
      asset.owner ?? "",
      asset.kind,
      asset.environment ?? "",
      ...(asset.hosts ?? []),
      ...(asset.ports ?? []).map(String),
      ...(asset.technology_names ?? []),
    ]
      .join(" ")
      .toLowerCase();
    if (freePositives.some((term) => !haystack.includes(term))) return false;
    if (freeNegatives.some((term) => haystack.includes(term))) return false;
    return true;
  });
}

/** What the search box offers as the operator types. */
export const QUERY_HINTS = [
  "port=5432",
  "env=production",
  "status=unreachable",
  "tech=nginx",
  "owner=dba",
  "-kind=database",
  "host=internal",
];
