// secure-code-ui/src/pages/submission/SubmitPage.tsx
//
// SCCAP-styled submission flow. Port of the design bundle's Submit.jsx,
// fully on SCCAP primitives — no antd. Native HTML5 drag-and-drop is
// used for the file / archive dropzones; file state is plain File[].
//
// The file-exclusion tree is still deferred to a later pass; by default
// all staged files are submitted. If selective exclusion is needed before
// that lands, a lightweight tree can be added here.

import React, { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useLocation, useNavigate } from "react-router-dom";
import { frameworkService } from "../../shared/api/frameworkService";
import { llmConfigService } from "../../shared/api/llmConfigService";
import { scanService } from "../../shared/api/scanService";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import type {
  FrameworkRead,
  LLMConfiguration,
  ProjectHistoryItem,
  ScanCoverageResponse,
} from "../../shared/types/api";
import { useAuth } from "../../shared/hooks/useAuth";
import { RepoFileTree } from "../../features/submission/RepoFileTree";
import ScanReadinessPanel from "../../features/semgrep/ScanReadinessPanel";
import ScanCoverageWizard from "../../features/semgrep/ScanCoverageWizard";

interface SubmitNavState {
  projectName?: string;
  projectId?: string;
  repoUrl?: string | null;
}

type SubmissionMode = "upload" | "git" | "archive";
type ScanType = "AUDIT" | "SUGGEST" | "REMEDIATE";

interface ScanTypeOption {
  id: ScanType;
  name: string;
  desc: string;
  recommended?: boolean;
}

const SCAN_TYPES: ScanTypeOption[] = [
  {
    id: "AUDIT",
    name: "Audit",
    desc: "Find vulnerabilities; no fix suggestions.",
    recommended: true,
  },
  {
    id: "SUGGEST",
    name: "Audit + Suggest",
    desc: "Find vulnerabilities and propose fixes for review.",
  },
  {
    id: "REMEDIATE",
    name: "Audit + Remediate",
    desc: "Find, fix, and apply patches to a new code snapshot.",
  },
];

const TAB_DEFS: { id: SubmissionMode; icon: React.ReactNode; label: string }[] = [
  { id: "upload", icon: <Icon.Upload size={14} />, label: "Upload files" },
  { id: "git", icon: <Icon.Github size={14} />, label: "Connect git" },
  { id: "archive", icon: <Icon.Folder size={14} />, label: "Upload archive" },
];

const ARCHIVE_ACCEPT = ".zip,.tar,.tar.gz,.tgz";

// V05.1.1 / V05.2.1 size caps (enforced at drop-time and again in handleSubmit)
const MAX_FILE_BYTES = 50_000_000;     // 50 MB per file
const MAX_TOTAL_BYTES = 200_000_000;   // 200 MB aggregate upload
const MAX_ARCHIVE_BYTES = 500_000_000; // 500 MB compressed archive

// V05.2.2 allowed source-code extensions for upload mode
const ALLOWED_UPLOAD_EXTENSIONS = new Set([
  ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php",
  ".cs", ".c", ".cpp", ".h", ".hpp", ".swift", ".kt", ".yml", ".yaml",
  ".json", ".toml", ".md", ".rs", ".scala", ".sh", ".bash", ".zsh",
  ".css", ".scss", ".html", ".xml", ".sql", ".tf", ".hcl",
]);

const Dropzone: React.FC<{
  onFiles: (files: File[]) => void | Promise<void>;
  multiple?: boolean;
  accept?: string;
  hint: string;
  helper: string;
}> = ({ onFiles, multiple = false, accept, hint, helper }) => {
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <div
      onDragOver={(e) => {
        e.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDragging(false);
        const files = Array.from(e.dataTransfer.files ?? []);
        if (files.length) onFiles(files);
      }}
      onClick={() => inputRef.current?.click()}
      role="button"
      tabIndex={0}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          inputRef.current?.click();
        }
      }}
      style={{
        background: dragging ? "var(--primary-weak)" : "var(--bg-soft)",
        border:
          "2px dashed " +
          (dragging ? "var(--primary)" : "var(--border-strong)"),
        borderRadius: "var(--r-md)",
        padding: "36px 24px",
        textAlign: "center",
        cursor: "pointer",
        transition: "all .15s var(--ease)",
      }}
    >
      <input
        ref={inputRef}
        type="file"
        multiple={multiple}
        accept={accept}
        style={{ display: "none" }}
        onChange={(e) => {
          const files = Array.from(e.target.files ?? []);
          if (files.length) onFiles(files);
          e.target.value = "";
        }}
      />
      <div style={{ color: "var(--primary)", marginBottom: 8 }}>
        <Icon.Upload size={22} />
      </div>
      <div style={{ fontWeight: 500, color: "var(--fg)" }}>{hint}</div>
      <div style={{ color: "var(--fg-muted)", fontSize: 12.5, marginTop: 4 }}>
        {helper}
      </div>
    </div>
  );
};

// Extension → Semgrep language name mapping
const EXT_TO_LANG: Record<string, string> = {
  ".py": "python",
  ".js": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".jsx": "javascript",
  ".java": "java",
  ".go": "go",
  ".rb": "ruby",
  ".php": "php",
  ".cs": "csharp",
  ".c": "c",
  ".h": "c",
  ".cpp": "cpp",
  ".cc": "cpp",
  ".hpp": "cpp",
};

function detectLanguages(fileNames: string[]): string[] {
  const langs = new Set<string>();
  for (const name of fileNames) {
    const ext = "." + name.split(".").pop()?.toLowerCase();
    const lang = EXT_TO_LANG[ext];
    if (lang) langs.add(lang);
  }
  return Array.from(langs);
}

function coverageKey(languages: string[]): string {
  return "sccap_coverage_dismissed_" + [...languages].sort().join(",");
}

// Language → framework suggestion table (Framework Expansion #63).
// Drives the advisory banner that nudges a developer toward a framework
// their detected languages would benefit from. Advisory only — it never
// alters the framework selection or blocks submission. ISVS has no clean
// client-side language signal, so the table is CWE-Essentials-focused.
const FRAMEWORK_SUGGESTIONS: {
  framework: string;
  label: string;
  languages: string[];
  reason: string;
}[] = [
  {
    framework: "cwe_essentials",
    label: "CWE Essentials",
    languages: ["c", "cpp", "go"],
    reason:
      "Your upload includes systems / native code. CWE Essentials adds " +
      "memory-safety, concurrency, and weakness-class coverage that the " +
      "web-centric frameworks don't.",
  },
];

// Per-(framework, language-mix) sessionStorage key — mirrors coverageKey
// so a dismissal is remembered for the same language mix for the session.
function frameworkSuggestionKey(framework: string, languages: string[]): string {
  return (
    "sccap_fw_suggest_dismissed_" +
    framework +
    ":" +
    [...languages].sort().join(",")
  );
}

const SubmitPage: React.FC = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();
  const { user } = useAuth();
  const navState = (location.state ?? {}) as SubmitNavState;

  const [mode, setMode] = useState<SubmissionMode>("upload");
  const [projectName, setProjectName] = useState<string>(navState.projectName ?? "");
  // null = "Create new project" (free-text input visible). A non-null
  // value is the id of the existing project the user picked from the
  // dropdown — projectName is locked to that project's name.
  const [selectedProjectId, setSelectedProjectId] = useState<string | null>(
    navState.projectId ?? null,
  );
  const [scanType, setScanType] = useState<ScanType>("AUDIT");
  const [llmConfigId, setLlmConfigId] = useState<string>("");
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>([]);
  const [files, setFiles] = useState<File[]>([]);
  const [archiveFile, setArchiveFile] = useState<File | null>(null);
  const [repoUrl, setRepoUrl] = useState<string>(navState.repoUrl ?? "");
  const [submitting, setSubmitting] = useState(false);
  // Preview-tree state. `previewFiles` is the flat list returned by
  // /scans/preview-git or /scans/preview-archive; `selectedFiles` is
  // the user's pick (default: every file).
  const [previewFiles, setPreviewFiles] = useState<string[] | null>(null);
  const [selectedFiles, setSelectedFiles] = useState<Set<string>>(new Set());
  const [previewLoading, setPreviewLoading] = useState(false);
  const [previewError, setPreviewError] = useState<string | null>(null);

  // Semgrep coverage wizard state
  const [coverageWizardOpen, setCoverageWizardOpen] = useState(false);
  const [coverageData, setCoverageData] = useState<ScanCoverageResponse | null>(null);
  const [coverageLanguages, setCoverageLanguages] = useState<string[]>([]);

  const { data: llmConfigs, isLoading: loadingLlms } = useQuery<LLMConfiguration[]>({
    queryKey: ["llmConfigs"],
    queryFn: llmConfigService.getLlmConfigs,
  });

  const { data: frameworks, isLoading: loadingFrameworks } = useQuery<FrameworkRead[]>({
    queryKey: ["frameworks"],
    queryFn: frameworkService.getFrameworks,
  });

  // Existing-project picker: pulls the user's projects so the user
  // doesn't have to re-type a name they've already created. The
  // backend's `get_or_create_project` is idempotent on (user_id, name)
  // so submitting with an existing name lands in the same project
  // either way; the picker just makes that obvious in the UI.
  const { data: projectsList, isLoading: loadingProjects } = useQuery({
    queryKey: ["projects", "submit-picker"],
    queryFn: () => scanService.getProjectHistory(1, 200),
  });
  const projects: ProjectHistoryItem[] = useMemo(
    () => projectsList?.items ?? [],
    [projectsList],
  );

  React.useEffect(() => {
    if (!llmConfigId && llmConfigs && llmConfigs.length > 0) {
      setLlmConfigId(llmConfigs[0].id);
    }
  }, [llmConfigs, llmConfigId]);

  // If the user arrived here via "New scan" on a project page, the
  // navState carries a projectId but the projects list is async — when
  // it lands, sync the projectName so the locked input shows the right
  // value. (Cheap; runs once per projects-load given the dep list.)
  useEffect(() => {
    if (selectedProjectId) {
      const match = projects.find((p) => p.id === selectedProjectId);
      if (match && match.name !== projectName) {
        setProjectName(match.name);
        if (match.repository_url && !repoUrl) {
          setRepoUrl(match.repository_url);
        }
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projects, selectedProjectId]);

  // Reset the preview tree whenever the source it came from changes.
  // For git: a different URL is a different repo. For archive: a
  // different file is a different tree. Stops stale paths from being
  // submitted with the wrong source.
  useEffect(() => {
    setPreviewFiles(null);
    setSelectedFiles(new Set());
    setPreviewError(null);
  }, [mode, repoUrl, archiveFile]);

  const handlePreviewGit = async () => {
    const v = repoUrl.trim();
    if (!v) return;
    try {
      const u = new URL(v);
      if (u.protocol !== "https:") {
        toast.error("Only HTTPS git URLs are accepted");
        return;
      }
    } catch {
      toast.error("Invalid repository URL");
      return;
    }
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const list = await scanService.previewGitRepo(v);
      setPreviewFiles(list);
      setSelectedFiles(new Set(list));
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      const detail =
        e.response?.data?.detail ?? e.message ?? "Could not fetch the repo";
      setPreviewError(typeof detail === "string" ? detail : "Could not fetch the repo");
    } finally {
      setPreviewLoading(false);
    }
  };

  const handlePreviewArchive = async (f: File) => {
    setPreviewLoading(true);
    setPreviewError(null);
    try {
      const list = await scanService.previewArchive(f);
      setPreviewFiles(list);
      setSelectedFiles(new Set(list));
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: string } };
        message?: string;
      };
      const detail =
        e.response?.data?.detail ?? e.message ?? "Could not read archive";
      setPreviewError(typeof detail === "string" ? detail : "Could not read archive");
    } finally {
      setPreviewLoading(false);
    }
  };

  const canSubmit = useMemo(() => {
    if (!projectName.trim()) return false;
    if (!llmConfigId) return false;
    if (selectedFrameworks.length === 0) return false;
    if (mode === "upload") return files.length > 0;
    if (mode === "git") {
      // V12.3.1: only HTTPS git URLs are accepted from the UI
      const v = repoUrl.trim();
      try {
        const u = new URL(v);
        if (u.protocol !== "https:") return false;
      } catch {
        return false;
      }
      // If the user has fetched the tree, require at least one file
      // selected — submitting with everything unchecked would queue
      // an empty scan.
      if (previewFiles && selectedFiles.size === 0) return false;
      return true;
    }
    if (mode === "archive") {
      if (!archiveFile) return false;
      if (previewFiles && selectedFiles.size === 0) return false;
      return true;
    }
    return false;
  }, [
    projectName,
    llmConfigId,
    selectedFrameworks,
    mode,
    files,
    repoUrl,
    archiveFile,
    previewFiles,
    selectedFiles,
  ]);

  const toggleFramework = (name: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(name) ? prev.filter((f) => f !== name) : [...prev, name],
    );
  };

  // --- Advisory framework-suggestion banner (Framework Expansion #63) ---
  // Dismissed suggestion keys. Seeded from sessionStorage so a dismissal
  // survives navigating away from the page and back within the session,
  // and held in state so the suggestion memo reacts to a dismissal.
  const [dismissedSuggestions, setDismissedSuggestions] = useState<Set<string>>(
    () => {
      const keys = new Set<string>();
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (k?.startsWith("sccap_fw_suggest_dismissed_")) keys.add(k);
      }
      return keys;
    },
  );

  // Languages detected from whatever files are currently staged — same
  // file-name sources the coverage check uses, computed reactively.
  const detectedLanguages = useMemo(() => {
    const fileNames =
      mode === "upload"
        ? files.map((f) => f.name)
        : (mode === "archive" || mode === "git") && previewFiles
          ? previewFiles
          : [];
    return detectLanguages(fileNames);
  }, [mode, files, previewFiles]);

  // The framework to nudge toward, or null. A suggestion is shown only
  // when the detected languages match the table, the framework exists on
  // this deployment and is not already selected, and the user has not
  // dismissed it for this language mix.
  const frameworkSuggestion = useMemo(() => {
    if (detectedLanguages.length === 0) return null;
    for (const s of FRAMEWORK_SUGGESTIONS) {
      if (selectedFrameworks.includes(s.framework)) continue;
      if (!frameworks?.some((f) => f.name === s.framework)) continue;
      if (!s.languages.some((l) => detectedLanguages.includes(l))) continue;
      if (dismissedSuggestions.has(frameworkSuggestionKey(s.framework, detectedLanguages)))
        continue;
      return s;
    }
    return null;
  }, [detectedLanguages, selectedFrameworks, frameworks, dismissedSuggestions]);

  const dismissFrameworkSuggestion = () => {
    if (!frameworkSuggestion) return;
    const key = frameworkSuggestionKey(
      frameworkSuggestion.framework,
      detectedLanguages,
    );
    sessionStorage.setItem(key, "1");
    setDismissedSuggestions((prev) => new Set(prev).add(key));
  };

  // Shared submission logic (called after coverage check or on skip)
  const doSubmit = async () => {
    if (!canSubmit) return;

    // V02.2.1: project name length + charset validation
    const trimmedName = projectName.trim();
    if (trimmedName.length > 100) { toast.error("Project name too long (max 100 characters)"); return; }
    if (!/^[A-Za-z0-9 ._-]+$/.test(trimmedName)) { toast.error("Project name has invalid characters (use letters, numbers, spaces, . _ -)"); return; }

    // V02.2.1 / V12.3.1: git URL must be https and within length limit
    if (mode === "git") {
      const v = repoUrl.trim();
      if (v.length > 512) { toast.error("Repository URL too long (max 512 characters)"); return; }
      try { const u = new URL(v); if (u.protocol !== "https:") { toast.error("Only HTTPS git URLs are accepted"); return; } }
      catch { toast.error("Invalid repository URL"); return; }
    }

    // V02.2.1 / V05.2.1: per-file and aggregate size defense-in-depth check
    if (mode === "upload") {
      for (const f of files) {
        if (f.size > MAX_FILE_BYTES) { toast.error(`File "${f.name}" exceeds 50 MB limit`); return; }
      }
      const totalSize = files.reduce((s, f) => s + f.size, 0);
      if (totalSize > MAX_TOTAL_BYTES) { toast.error("Total upload size exceeds 200 MB limit"); return; }
    }

    // V02.2.1 / V05.2.1: archive size defense-in-depth check
    if (mode === "archive" && archiveFile) {
      if (archiveFile.size > MAX_ARCHIVE_BYTES) { toast.error("Archive exceeds 500 MB limit"); return; }
    }

    setSubmitting(true);
    try {
      const payload = new FormData();
      payload.append("project_name", trimmedName);
      payload.append("scan_type", scanType);
      payload.append("reasoning_llm_config_id", llmConfigId);
      // V02.2.1: intersect selectedFrameworks with the loaded allowlist before submitting
      const safeFrameworks = selectedFrameworks.filter((n) => frameworks?.some((f) => f.name === n));
      payload.append("frameworks", safeFrameworks.join(","));
      if (mode === "upload") {
        for (const f of files) payload.append("files", f);
      } else if (mode === "git") {
        payload.append("repo_url", repoUrl.trim());
      } else if (mode === "archive" && archiveFile) {
        payload.append("archive_file", archiveFile);
      }

      if (
        (mode === "git" || mode === "archive") &&
        previewFiles &&
        selectedFiles.size > 0 &&
        selectedFiles.size < previewFiles.length
      ) {
        payload.append(
          "selected_files",
          Array.from(selectedFiles).join(","),
        );
      }

      const response = await scanService.createScan(payload);
      toast.success("Scan submitted. Tracking progress…");
      navigate(`/analysis/scanning/${response.scan_id}`, {
        state: {
          fromLabel: projectName.trim() || "Projects",
          fromPath: selectedProjectId
            ? `/analysis/projects/${selectedProjectId}`
            : "/analysis/results",
        },
      });
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: string | unknown[] } };
        message?: string;
      };
      const detail =
        typeof e.response?.data?.detail === "string"
          ? e.response.data.detail
          : e.message || "Submission failed";
      toast.error(detail);
    } finally {
      setSubmitting(false);
    }
  };

  const handleSubmit = async () => {
    if (!canSubmit) return;

    // Detect languages from uploaded files for coverage check
    const fileNames =
      mode === "upload"
        ? files.map((f) => f.name)
        : mode === "archive" && previewFiles
          ? previewFiles
          : mode === "git" && previewFiles
            ? previewFiles
            : [];

    const langs = detectLanguages(fileNames);
    const key = coverageKey(langs);
    const dismissed = langs.length === 0 || sessionStorage.getItem(key) === "1";

    if (!dismissed && langs.length > 0) {
      try {
        const cov = await ruleSourcesService.checkCoverage(langs);
        const hasUncovered = langs.some((l) => {
          const e = cov.coverage[l];
          return e && !e.covered;
        });
        if (hasUncovered) {
          setCoverageData(cov);
          setCoverageLanguages(langs);
          setCoverageWizardOpen(true);
          return; // Wait for wizard decision
        }
      } catch {
        // Ignore coverage check failures; don't block submission
      }
    }

    await doSubmit();
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20 }}>
      <div>
        <h1 style={{ color: "var(--fg)" }}>New scan</h1>
        <div style={{ color: "var(--fg-muted)", marginTop: 4 }}>
          Submit code via upload, git repo, or archive. SCCAP runs SAST + AI
          triage and (optionally) applies fixes.
        </div>
      </div>

      <div
        style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 20 }}
      >
        <div style={{ display: "grid", gap: 16 }}>
          <div className="surface" style={{ padding: 20 }}>
          <label
            style={{
              display: "block",
              fontSize: 12,
              color: "var(--fg-muted)",
              marginBottom: 6,
              fontWeight: 500,
            }}
          >
            Project
          </label>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 12,
            }}
          >
            <select
              className="sccap-select"
              value={selectedProjectId ?? "__new__"}
              onChange={(e) => {
                const v = e.target.value;
                if (v === "__new__") {
                  setSelectedProjectId(null);
                  setProjectName("");
                } else {
                  setSelectedProjectId(v);
                  const match = projects.find((p) => p.id === v);
                  if (match) {
                    setProjectName(match.name);
                    if (match.repository_url) setRepoUrl(match.repository_url);
                  }
                }
              }}
              disabled={loadingProjects}
            >
              <option value="__new__">+ Create new project</option>
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <input
              className="sccap-input"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              placeholder="e.g., payments-api"
              autoFocus={selectedProjectId === null && !projectName}
              disabled={selectedProjectId !== null}
            />
          </div>
          <div style={{ marginTop: 6, fontSize: 11, color: "var(--fg-subtle)" }}>
            {selectedProjectId
              ? "Scanning into an existing project — name is locked."
              : "Pick an existing project or create a new one. Names are unique per user."}
          </div>
        </div>

        <div className="surface" style={{ padding: 0, overflow: "hidden" }}>
          <div
            className="sccap-tabs"
            style={{ padding: "0 18px", background: "var(--bg-soft)" }}
          >
            {TAB_DEFS.map((t) => (
              <div
                key={t.id}
                className={"sccap-tab " + (mode === t.id ? "active" : "")}
                onClick={() => setMode(t.id)}
              >
                {t.icon} {t.label}
              </div>
            ))}
          </div>

          <div style={{ padding: 20 }}>
            {mode === "upload" && (
              <div>
                <Dropzone
                  multiple
                  onFiles={(next) => {
                    // V05.2.2: extension allowlist
                    const allowed: File[] = [];
                    for (const f of next) {
                      const ext = "." + f.name.split(".").pop()?.toLowerCase();
                      if (!ALLOWED_UPLOAD_EXTENSIONS.has(ext)) {
                        toast.error(`"${f.name}" has an unsupported extension and was skipped`);
                        continue;
                      }
                      // V05.2.1: per-file size cap at drop time
                      if (f.size > MAX_FILE_BYTES) {
                        toast.error(`"${f.name}" exceeds 50 MB and was skipped`);
                        continue;
                      }
                      allowed.push(f);
                    }
                    if (allowed.length === 0) return;
                    setFiles((prev) => {
                      // V05.2.1: aggregate size cap at drop time
                      const currentTotal = prev.reduce((s, f) => s + f.size, 0);
                      const accepted: File[] = [];
                      let running = currentTotal;
                      for (const f of allowed) {
                        if (running + f.size > MAX_TOTAL_BYTES) {
                          toast.error(`Adding "${f.name}" would exceed the 200 MB total limit; it was skipped`);
                          continue;
                        }
                        running += f.size;
                        accepted.push(f);
                      }
                      return [...prev, ...accepted];
                    });
                  }}
                  hint="Drop files here or click to browse"
                  helper="Up to 200 files, 50 MB each, 200 MB total. Supported source-code extensions only. Binary files are ignored; potentially-malicious files are quarantined and reported."
                />
                {files.length > 0 && (
                  <div
                    style={{
                      marginTop: 12,
                      display: "grid",
                      gap: 4,
                      maxHeight: 200,
                      overflowY: "auto",
                    }}
                  >
                    {files.map((f, i) => (
                      <div
                        key={`${f.name}-${i}`}
                        style={{
                          display: "flex",
                          justifyContent: "space-between",
                          fontSize: 12.5,
                          color: "var(--fg-muted)",
                          padding: "4px 0",
                        }}
                      >
                        <span
                          className="mono"
                          style={{
                            overflow: "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace: "nowrap",
                            maxWidth: 360,
                          }}
                        >
                          {f.name}
                        </span>
                        <span
                          onClick={() =>
                            setFiles((prev) => prev.filter((_, j) => j !== i))
                          }
                          style={{
                            cursor: "pointer",
                            color: "var(--fg-subtle)",
                            fontSize: 11,
                          }}
                        >
                          Remove
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {mode === "git" && (
              <div>
                <label
                  style={{
                    display: "block",
                    fontSize: 12,
                    color: "var(--fg-muted)",
                    marginBottom: 6,
                  }}
                >
                  Repository URL
                </label>
                <div className="input-with-icon">
                  <Icon.Github size={14} />
                  <input
                    className="sccap-input"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    placeholder="https://github.com/owner/repo.git"
                    style={{ paddingLeft: 32 }}
                  />
                </div>
                {/* V12.3.1: HTTPS-only gate */}
                {repoUrl.trim().length > 0 && (() => {
                  try { const u = new URL(repoUrl.trim()); if (u.protocol !== "https:") return (
                    <div style={{ marginTop: 6, fontSize: 11.5, color: "var(--danger, #c0392b)" }}>
                      HTTPS git URLs only — http://, git://, and ssh:// are not accepted from the UI.
                    </div>
                  ); } catch { return null; } return null;
                })()}
                <div
                  style={{
                    marginTop: 8,
                    fontSize: 11.5,
                    color: "var(--fg-subtle)",
                  }}
                >
                  Public repos are cloned shallow; private repos require a PAT
                  configured in Admin → LLM settings.
                </div>
                <div
                  style={{
                    display: "flex",
                    gap: 8,
                    marginTop: 12,
                    alignItems: "center",
                  }}
                >
                  <button
                    type="button"
                    className="sccap-btn sccap-btn-sm"
                    onClick={handlePreviewGit}
                    disabled={previewLoading || !repoUrl.trim()}
                  >
                    <Icon.Folder size={12} />{" "}
                    {previewLoading
                      ? "Fetching…"
                      : previewFiles
                        ? "Refresh file tree"
                        : "Fetch file tree"}
                  </button>
                  {previewFiles && (
                    <span style={{ fontSize: 11.5, color: "var(--fg-muted)" }}>
                      {previewFiles.length} file
                      {previewFiles.length === 1 ? "" : "s"} found — pick which
                      to scan.
                    </span>
                  )}
                </div>
                {previewError && (
                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      color: "var(--critical)",
                    }}
                  >
                    {previewError}
                  </div>
                )}
                {previewFiles && (
                  <div style={{ marginTop: 12 }}>
                    <RepoFileTree
                      files={previewFiles}
                      selected={selectedFiles}
                      onChange={setSelectedFiles}
                    />
                  </div>
                )}
              </div>
            )}

            {mode === "archive" && (
              <div>
                {/* V05.2.3: server enforces max uncompressed size (2 GB) and file count (50 000)
                    before extraction; it also rejects archives with a compressed:uncompressed
                    ratio exceeding 1:100 and archives containing symlinks. This client-side
                    check is a UX guard only — backend validation is authoritative. */}
                <Dropzone
                  accept={ARCHIVE_ACCEPT}
                  onFiles={async (next) => {
                    const file = next[0];
                    if (!file) return;
                    // V05.2.1: archive size cap at drop time
                    if (file.size > MAX_ARCHIVE_BYTES) {
                      toast.error("Archive exceeds the 500 MB limit");
                      return;
                    }
                    // V05.2.2: magic-byte validation (zip / gzip / tar)
                    try {
                      const buf = await file.slice(0, 262).arrayBuffer();
                      const bytes = new Uint8Array(buf);
                      const isZip = bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04;
                      const isGzip = bytes[0] === 0x1F && bytes[1] === 0x8B;
                      // ustar marker at offset 257
                      const isTar = buf.byteLength >= 262 &&
                        bytes[257] === 0x75 && bytes[258] === 0x73 && bytes[259] === 0x74 &&
                        bytes[260] === 0x61 && bytes[261] === 0x72;
                      if (!isZip && !isGzip && !isTar) {
                        toast.error("File does not appear to be a valid zip, gzip, or tar archive");
                        return;
                      }
                    } catch {
                      toast.error("Could not read archive header; please try again");
                      return;
                    }
                    setArchiveFile(file);
                    // Auto-fetch the tree as soon as a valid archive
                    // is dropped — the user expects "drop archive →
                    // see files" to be one step, not two.
                    void handlePreviewArchive(file);
                  }}
                  hint="Drop a .zip or .tar.gz"
                  helper="Single .zip/.tar/.tar.gz, up to 500 MB compressed and 2 GB uncompressed. Symlinks are rejected by the server."
                />
                {archiveFile && (
                  <div
                    style={{
                      marginTop: 12,
                      display: "flex",
                      justifyContent: "space-between",
                      fontSize: 12.5,
                      color: "var(--fg-muted)",
                    }}
                  >
                    <span className="mono">{archiveFile.name}</span>
                    <span
                      onClick={() => {
                        setArchiveFile(null);
                        setPreviewFiles(null);
                        setSelectedFiles(new Set());
                      }}
                      style={{
                        cursor: "pointer",
                        color: "var(--fg-subtle)",
                        fontSize: 11,
                      }}
                    >
                      Remove
                    </span>
                  </div>
                )}
                {previewLoading && (
                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      color: "var(--fg-muted)",
                    }}
                  >
                    Reading archive…
                  </div>
                )}
                {previewError && (
                  <div
                    style={{
                      marginTop: 8,
                      fontSize: 12,
                      color: "var(--critical)",
                    }}
                  >
                    {previewError}
                  </div>
                )}
                {previewFiles && (
                  <div style={{ marginTop: 12 }}>
                    <RepoFileTree
                      files={previewFiles}
                      selected={selectedFiles}
                      onChange={setSelectedFiles}
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        <div className="surface" style={{ padding: 20 }}>
          <h3 style={{ marginBottom: 12, color: "var(--fg)" }}>
            Scan configuration
          </h3>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "1fr 1fr",
              gap: 20,
            }}
          >
            <div>
              <label
                style={{
                  display: "block",
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginBottom: 6,
                  fontWeight: 500,
                }}
              >
                Scan mode
              </label>
              <div style={{ display: "grid", gap: 6 }}>
                {SCAN_TYPES.map((o) => {
                  const active = scanType === o.id;
                  return (
                    <label
                      key={o.id}
                      style={{
                        display: "grid",
                        gridTemplateColumns: "auto 1fr",
                        gap: 10,
                        alignItems: "flex-start",
                        padding: 10,
                        border:
                          "1px solid " +
                          (active ? "var(--primary)" : "var(--border)"),
                        background: active
                          ? "var(--primary-weak)"
                          : "var(--bg-elev)",
                        borderRadius: "var(--r-sm)",
                        cursor: "pointer",
                      }}
                    >
                      <input
                        type="radio"
                        name="scan-type"
                        checked={active}
                        onChange={() => setScanType(o.id)}
                        style={{ accentColor: "var(--primary)", marginTop: 3 }}
                      />
                      <div>
                        <div
                          style={{
                            fontSize: 13.5,
                            fontWeight: 500,
                            color: "var(--fg)",
                          }}
                        >
                          {o.name}{" "}
                          {o.recommended && (
                            <span
                              className="chip chip-ai"
                              style={{ marginLeft: 6, fontSize: 10 }}
                            >
                              recommended
                            </span>
                          )}
                        </div>
                        <div
                          style={{ fontSize: 11.5, color: "var(--fg-muted)" }}
                        >
                          {o.desc}
                        </div>
                      </div>
                    </label>
                  );
                })}
              </div>
            </div>

            <div>
              <label
                style={{
                  display: "block",
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginBottom: 6,
                  fontWeight: 500,
                }}
              >
                LLM configuration
              </label>
              <select
                className="sccap-select"
                value={llmConfigId}
                onChange={(e) => setLlmConfigId(e.target.value)}
                disabled={loadingLlms || !llmConfigs?.length}
              >
                {loadingLlms && <option>Loading…</option>}
                {!loadingLlms && !llmConfigs?.length && (
                  <option value="">No LLMs configured — see Admin → LLM</option>
                )}
                {llmConfigs?.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name} · {c.provider}/{c.model_name}
                  </option>
                ))}
              </select>
              <div
                style={{
                  marginTop: 6,
                  fontSize: 11,
                  color: "var(--fg-subtle)",
                }}
              >
                The same config powers utility, fast, and reasoning slots by
                default.
              </div>

              <label
                style={{
                  display: "block",
                  fontSize: 12,
                  color: "var(--fg-muted)",
                  marginTop: 18,
                  marginBottom: 6,
                  fontWeight: 500,
                }}
              >
                Compliance frameworks
              </label>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {loadingFrameworks && (
                  <span style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                    Loading frameworks…
                  </span>
                )}
                {!loadingFrameworks && !frameworks?.length && (
                  <span style={{ fontSize: 12, color: "var(--fg-subtle)" }}>
                    No frameworks configured — see Admin → Frameworks.
                  </span>
                )}
                {frameworks?.map((f) => {
                  const on = selectedFrameworks.includes(f.name);
                  return (
                    <button
                      key={f.id}
                      type="button"
                      onClick={() => toggleFramework(f.name)}
                      className="chip"
                      style={{
                        cursor: "pointer",
                        background: on
                          ? "var(--primary-weak)"
                          : "var(--bg-soft)",
                        color: on ? "var(--primary)" : "var(--fg-muted)",
                        border: "none",
                        padding: "5px 12px",
                      }}
                    >
                      {on && <Icon.Check size={10} />} {f.name}
                    </button>
                  );
                })}
              </div>

              {frameworkSuggestion && (
                <div
                  role="status"
                  style={{
                    display: "flex",
                    alignItems: "flex-start",
                    gap: 10,
                    marginTop: 10,
                    padding: "10px 12px",
                    background: "var(--primary-weak)",
                    border: "1px solid var(--primary)",
                    borderRadius: 8,
                  }}
                >
                  <div
                    style={{
                      color: "var(--primary)",
                      flexShrink: 0,
                      marginTop: 1,
                    }}
                  >
                    <Icon.Sparkle size={16} />
                  </div>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontWeight: 500,
                        color: "var(--fg)",
                        fontSize: 13,
                      }}
                    >
                      Suggested framework: {frameworkSuggestion.label}
                    </div>
                    <div
                      style={{
                        color: "var(--fg-muted)",
                        fontSize: 12,
                        marginTop: 2,
                      }}
                    >
                      {frameworkSuggestion.reason}
                    </div>
                    <button
                      type="button"
                      onClick={() =>
                        toggleFramework(frameworkSuggestion.framework)
                      }
                      className="chip"
                      style={{
                        cursor: "pointer",
                        marginTop: 8,
                        background: "var(--primary)",
                        color: "var(--bg)",
                        border: "none",
                        padding: "5px 12px",
                      }}
                    >
                      Add {frameworkSuggestion.label}
                    </button>
                  </div>
                  <button
                    type="button"
                    aria-label="Dismiss suggestion"
                    onClick={dismissFrameworkSuggestion}
                    style={{
                      cursor: "pointer",
                      background: "none",
                      border: "none",
                      color: "var(--fg-muted)",
                      flexShrink: 0,
                      padding: 2,
                      lineHeight: 0,
                    }}
                  >
                    <Icon.X size={14} />
                  </button>
                </div>
              )}
            </div>
          </div>

          <div className="sccap-divider" />
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div style={{ color: "var(--fg-muted)", fontSize: 12.5 }}>
              You'll approve the cost before the full analysis runs.
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="sccap-btn"
                onClick={() => navigate("/account/dashboard")}
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                className="sccap-btn sccap-btn-primary"
                onClick={handleSubmit}
                disabled={!canSubmit || submitting}
              >
                <Icon.Play size={12} />{" "}
                {submitting ? "Submitting…" : "Start scan"}
              </button>
            </div>
          </div>
        </div>
      </div>

      <aside style={{ display: "grid", gap: 16, alignContent: "start" }}>
        <ScanReadinessPanel />
        <div className="sccap-card">
          <h4 style={{ marginBottom: 10, color: "var(--fg)" }}>
            What we scan for
          </h4>
          <div style={{ display: "grid", gap: 8, fontSize: 12.5 }}>
            {[
              { icon: <Icon.Lock size={12} />, label: "Vulnerabilities (SAST)" },
              {
                icon: <Icon.Box size={12} />,
                label: "Dependencies (where configured)",
              },
              { icon: <Icon.Key size={12} />, label: "Secrets & credentials" },
              {
                icon: <Icon.Shield size={12} />,
                label: "Compliance framework mappings",
              },
              { icon: <Icon.Sparkle size={12} />, label: "AI-suggested fixes" },
            ].map((r, i) => (
              <div
                key={i}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  color: "var(--fg-muted)",
                }}
              >
                <span style={{ color: "var(--primary)" }}>{r.icon}</span>
                {r.label}
              </div>
            ))}
          </div>
        </div>
        <div
          className="sccap-card"
          style={{
            background: "var(--primary-weak)",
            borderColor: "transparent",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              marginBottom: 6,
            }}
          >
            <Icon.Info size={14} color="var(--primary)" />
            <div style={{ fontWeight: 600, color: "var(--primary-strong)" }}>
              Cost approval
            </div>
          </div>
          <div
            style={{
              fontSize: 12.5,
              color: "var(--fg)",
              lineHeight: 1.55,
            }}
          >
            After submission, SCCAP runs a quick cost estimate and pauses for
            your approval before running the full scan. You'll see the estimate
            on the next screen.
          </div>
        </div>
      </aside>
      </div>

      <ScanCoverageWizard
        open={coverageWizardOpen}
        languages={coverageLanguages}
        coverage={coverageData}
        isSuperuser={!!user?.is_superuser}
        onSkip={() => {
          // Mark as dismissed for this set of languages for the session
          sessionStorage.setItem(coverageKey(coverageLanguages), "1");
          setCoverageWizardOpen(false);
          void doSubmit();
        }}
        onProceed={() => {
          setCoverageWizardOpen(false);
          void doSubmit();
        }}
        onClose={() => setCoverageWizardOpen(false)}
      />
    </div>
  );
};

export default SubmitPage;
