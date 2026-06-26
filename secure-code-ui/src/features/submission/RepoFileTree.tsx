// secure-code-ui/src/features/submission/RepoFileTree.tsx
//
// File-tree picker used by SubmitPage after the user pastes a git URL
// (POST /scans/preview-git) or drops an archive (POST /scans/preview-
// archive). Both endpoints return a flat `string[]` of paths; this
// component builds a hierarchical view and lets the user pick which
// files to include in the eventual scan.
//
// Selection model:
// - Files are selected by default (matches the prior behaviour of
//   "submit everything" so the picker is opt-out, not opt-in).
// - A folder checkbox toggles every descendant file. We do NOT model
//   tri-state ("some children selected"); the visual is a plain
//   checked / unchecked. Computing tri-state cleanly across deep
//   trees added enough complexity that we punted on it for the first
//   pass — the per-folder summary "(3/12)" gives the same signal.
// - Search filter is path-substring only; folders that contain a
//   match stay visible so the user keeps context.

import React, { useEffect, useMemo, useState } from "react";
import { Icon } from "../../shared/ui/Icon";

export interface RepoFile {
  path: string;
  /** Language inferred from extension, or "unknown" */
  language?: string;
  /** Whether this file can be scanned (has a supported extension) */
  supported?: boolean;
}

export interface RepoFileTreeProps {
  files: (string | RepoFile)[];
  /** Subset of `files` that is currently selected (controlled). */
  selected: Set<string>;
  /** Called whenever the selection changes. */
  onChange: (next: Set<string>) => void;
  /** Optional max height for the scroll area. */
  maxHeight?: number | string;
}

// Normalise mixed input to RepoFile objects.
function normaliseFiles(files: (string | RepoFile)[]): RepoFile[] {
  return files.map((f) =>
    typeof f === "string"
      ? { path: f, language: undefined, supported: true }
      : f,
  );
}

// Internal tree shape. Each node is either a folder (children populated)
// or a file (children is undefined).
interface Node {
  name: string;
  path: string;
  children?: Map<string, Node>;
}

function buildTree(paths: string[]): Node {
  const root: Node = { name: "", path: "", children: new Map() };
  for (const p of paths) {
    if (!p) continue;
    const segments = p.split("/").filter(Boolean);
    let cursor = root;
    for (let i = 0; i < segments.length; i++) {
      const seg = segments[i];
      const isLeaf = i === segments.length - 1;
      const childPath = segments.slice(0, i + 1).join("/");
      cursor.children = cursor.children ?? new Map();
      let next = cursor.children.get(seg);
      if (!next) {
        next = {
          name: seg,
          path: childPath,
          children: isLeaf ? undefined : new Map(),
        };
        cursor.children.set(seg, next);
      }
      cursor = next;
    }
  }
  return root;
}

function collectFilesUnder(node: Node): string[] {
  if (!node.children) return [node.path];
  const out: string[] = [];
  for (const child of node.children.values()) {
    out.push(...collectFilesUnder(child));
  }
  return out;
}

function nodeMatchesQuery(node: Node, q: string): boolean {
  if (!q) return true;
  if (node.path.toLowerCase().includes(q)) return true;
  if (!node.children) return false;
  for (const child of node.children.values()) {
    if (nodeMatchesQuery(child, q)) return true;
  }
  return false;
}

interface RowProps {
  node: Node;
  depth: number;
  selected: Set<string>;
  expanded: Set<string>;
  query: string;
  supportedMap: Map<string, boolean>;
  toggleSelect: (paths: string[], select: boolean) => void;
  toggleExpand: (path: string) => void;
}

const TreeRow: React.FC<RowProps> = ({
  node,
  depth,
  selected,
  expanded,
  query,
  supportedMap,
  toggleSelect,
  toggleExpand,
}) => {
  const isFolder = !!node.children;
  const filesUnder = useMemo(
    () => (isFolder ? collectFilesUnder(node) : [node.path]),
    [node, isFolder],
  );
  const isUnsupported = !isFolder && supportedMap.get(node.path) === false;
  const selectedCount = filesUnder.filter((p) => selected.has(p)).length;
  const isChecked = selectedCount > 0 && selectedCount === filesUnder.length;
  const isOpen = expanded.has(node.path) || query.length > 0;

  return (
    <>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "20px 16px 16px 1fr auto",
          alignItems: "center",
          gap: 6,
          padding: "4px 8px",
          paddingLeft: 8 + depth * 16,
          fontSize: 12.5,
          color: "var(--fg)",
          borderRadius: 4,
          cursor: isFolder ? "pointer" : "default",
        }}
        onClick={(e) => {
          // Click on row body toggles folder open; clicks on the
          // checkbox or its label propagate via stopPropagation in
          // their own handlers.
          if (isFolder && (e.target as HTMLElement).tagName !== "INPUT") {
            toggleExpand(node.path);
          }
        }}
      >
        <span style={{ width: 16, height: 16, display: "inline-flex" }}>
          {isFolder ? (
            <Icon.ChevronR
              size={11}
              // Naive rotation via inline style; using transform.
              {...({
                style: {
                  transform: isOpen ? "rotate(90deg)" : "rotate(0deg)",
                  transition: "transform .1s var(--ease)",
                  color: "var(--fg-muted)",
                },
              } as object)}
            />
          ) : null}
        </span>
        <input
          type="checkbox"
          checked={isChecked}
          disabled={isUnsupported}
          onChange={(e) => {
            e.stopPropagation();
            toggleSelect(filesUnder, e.target.checked);
          }}
          onClick={(e) => e.stopPropagation()}
          style={{
            cursor: isUnsupported ? "not-allowed" : "pointer",
            accentColor: "var(--primary)",
            opacity: isUnsupported ? 0.4 : 1,
          }}
        />
        <span style={{ color: "var(--fg-muted)" }}>
          {isFolder ? <Icon.Folder size={12} /> : <Icon.File size={12} />}
        </span>
        <span
          style={{
            fontFamily: isFolder ? "inherit" : "var(--font-mono)",
            fontWeight: isFolder ? 500 : 400,
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
            color: isUnsupported ? "var(--fg-subtle)" : "var(--fg)",
            opacity: isUnsupported ? 0.6 : 1,
          }}
        >
          {node.name}
          {isUnsupported && (
            <span
              style={{
                fontSize: 10,
                color: "var(--warning)",
                marginLeft: 6,
                fontWeight: 400,
              }}
            >
              unsupported
            </span>
          )}
        </span>
        {isFolder && (
          <span
            style={{
              fontSize: 11,
              color: "var(--fg-subtle)",
              fontVariantNumeric: "tabular-nums",
            }}
          >
            {selectedCount}/{filesUnder.length}
          </span>
        )}
      </div>
      {isFolder && isOpen && node.children && (
        <>
          {[...node.children.values()]
            .filter((c) => nodeMatchesQuery(c, query.toLowerCase()))
            // Folders first, then files; alphabetic within each.
            .sort((a, b) => {
              const af = !!a.children;
              const bf = !!b.children;
              if (af !== bf) return af ? -1 : 1;
              return a.name.localeCompare(b.name);
            })
            .map((child) => (
              <TreeRow
                key={child.path}
                node={child}
                depth={depth + 1}
                selected={selected}
                expanded={expanded}
                query={query}
                supportedMap={supportedMap}
                toggleSelect={toggleSelect}
                toggleExpand={toggleExpand}
              />
            ))}
        </>
      )}
    </>
  );
};

export const RepoFileTree: React.FC<RepoFileTreeProps> = ({
  files,
  selected,
  onChange,
  maxHeight = 360,
}) => {
  const normalised = useMemo(() => normaliseFiles(files), [files]);
  const paths = useMemo(() => normalised.map((f) => f.path), [normalised]);
  const supportedMap = useMemo(
    () => new Map(normalised.map((f) => [f.path, f.supported ?? true])),
    [normalised],
  );
  const root = useMemo(() => buildTree(paths), [paths]);
  const [expanded, setExpanded] = useState<Set<string>>(new Set([""]));
  const [query, setQuery] = useState("");

  // Default-select only supported files
  useEffect(() => {
    const supportedPaths = normalised
      .filter((f) => f.supported !== false)
      .map((f) => f.path);
    onChange(new Set(supportedPaths));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [files]);

  const toggleExpand = (path: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const toggleSelect = (paths: string[], select: boolean) => {
    const next = new Set(selected);
    for (const p of paths) {
      // Cannot select unsupported files
      if (select && supportedMap.get(p) === false) continue;
      if (select) next.add(p);
      else next.delete(p);
    }
    onChange(next);
  };

  const totalCount = paths.length;
  const supportedCount = paths.filter((p) => supportedMap.get(p) !== false).length;
  const unsupportedCount = totalCount - supportedCount;
  const selectedCount = paths.filter((f) => selected.has(f)).length;

  return (
    <div style={{ display: "grid", gap: 8 }}>
      <div
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          flexWrap: "wrap",
        }}
      >
        <div className="input-with-icon" style={{ flex: 1, minWidth: 200 }}>
          <Icon.Search size={12} />
          <input
            className="sccap-input"
            placeholder="Filter by path…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{ paddingLeft: 28, fontSize: 12.5 }}
          />
        </div>
        <button
          type="button"
          className="sccap-btn sccap-btn-sm sccap-btn-ghost"
          onClick={() => onChange(new Set(paths.filter((p) => supportedMap.get(p) !== false)))}
        >
          Select all
        </button>
        <button
          type="button"
          className="sccap-btn sccap-btn-sm sccap-btn-ghost"
          onClick={() => onChange(new Set())}
        >
          Clear
        </button>
        <span
          style={{
            fontSize: 11.5,
            color: "var(--fg-muted)",
            marginLeft: "auto",
            fontVariantNumeric: "tabular-nums",
          }}
        >
          {selectedCount} / {supportedCount}
          {unsupportedCount > 0 && (
            <span style={{ color: "var(--fg-subtle)", marginLeft: 4 }}>
              ({unsupportedCount} unsupported)
            </span>
          )}
        </span>
      </div>
      <div
        style={{
          maxHeight,
          overflowY: "auto",
          border: "1px solid var(--border)",
          borderRadius: 8,
          background: "var(--bg-soft)",
          padding: 6,
        }}
      >
        {root.children && root.children.size > 0 ? (
          [...root.children.values()]
            .filter((c) => nodeMatchesQuery(c, query.toLowerCase()))
            .sort((a, b) => {
              const af = !!a.children;
              const bf = !!b.children;
              if (af !== bf) return af ? -1 : 1;
              return a.name.localeCompare(b.name);
            })
            .map((child) => (
              <TreeRow
                key={child.path}
                node={child}
                depth={0}
                selected={selected}
                expanded={expanded}
                query={query}
                supportedMap={supportedMap}
                toggleSelect={toggleSelect}
                toggleExpand={toggleExpand}
              />
            ))
        ) : (
          <div
            style={{
              padding: 18,
              textAlign: "center",
              color: "var(--fg-muted)",
              fontSize: 12.5,
            }}
          >
            No files to show.
          </div>
        )}
      </div>
    </div>
  );
};

export default RepoFileTree;
