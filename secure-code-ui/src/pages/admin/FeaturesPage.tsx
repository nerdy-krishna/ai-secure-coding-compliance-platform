// secure-code-ui/src/pages/admin/FeaturesPage.tsx
//
// Superuser admin surface for the modular-setup feature flags. Lists every
// catalog feature, toggles the app-only ones (container-backed flags are
// read-only here), auto-resolves dependencies in the UI, and persists via
// PUT /admin/features.

import React, { useEffect, useMemo, useState } from "react";
import {
  featureService,
  type AdminFeature,
} from "../../shared/api/featureService";
import { useToast } from "../../shared/ui/Toast";

const FeaturesPage: React.FC = () => {
  const toast = useToast();
  const [features, setFeatures] = useState<AdminFeature[]>([]);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    featureService
      .getAdminFeatures()
      .then((list) => {
        setFeatures(list);
        setEnabled(new Set(list.filter((f) => f.enabled).map((f) => f.name)));
      })
      .catch(() => toast.error("Failed to load feature flags."))
      .finally(() => setLoading(false));
  }, [toast]);

  // depends_on (forward) and the reverse dependents map, for auto-resolve.
  const { depsOf, dependentsOf } = useMemo(() => {
    const deps = new Map<string, string[]>();
    const rev = new Map<string, string[]>();
    for (const f of features) {
      deps.set(f.name, f.depends_on);
      for (const d of f.depends_on) {
        const arr = rev.get(d) ?? [];
        arr.push(f.name);
        rev.set(d, arr);
      }
    }
    return { depsOf: deps, dependentsOf: rev };
  }, [features]);

  const closure = (start: string, map: Map<string, string[]>): string[] => {
    const out = new Set<string>();
    const stack = [start];
    while (stack.length) {
      const n = stack.pop();
      if (n === undefined) break;
      for (const m of map.get(n) ?? []) {
        if (!out.has(m)) {
          out.add(m);
          stack.push(m);
        }
      }
    }
    return [...out];
  };

  const toggle = (f: AdminFeature) => {
    if (f.always_on || f.container_backed) return;
    setEnabled((prev) => {
      const next = new Set(prev);
      if (next.has(f.name)) {
        // Disabling: drop the feature and everything that depends on it.
        next.delete(f.name);
        for (const dep of closure(f.name, dependentsOf)) next.delete(dep);
      } else {
        // Enabling: add the feature and everything it depends on.
        next.add(f.name);
        for (const dep of closure(f.name, depsOf)) next.add(dep);
      }
      return next;
    });
  };

  const save = async () => {
    setSaving(true);
    try {
      const res = await featureService.updateFeatures([...enabled]);
      setFeatures(res.features);
      setEnabled(new Set(res.features.filter((f) => f.enabled).map((f) => f.name)));
      toast.success("Feature flags saved.");
    } catch {
      toast.error("Failed to save feature flags.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div style={{ padding: 24 }}>Loading feature flags…</div>;

  return (
    <div style={{ maxWidth: 720 }}>
      <h2 style={{ marginBottom: 4 }}>Features</h2>
      <p style={{ color: "var(--fg-muted)", fontSize: 13, marginBottom: 16 }}>
        Toggle optional platform features. Dependencies resolve automatically.
        Container-backed features (log stack, tracing) are read-only here —
        change them via <code>COMPOSE_PROFILES</code> and a stack restart.
      </p>

      <div style={{ display: "grid", gap: 8 }}>
        {features.map((f) => {
          const on = enabled.has(f.name);
          const locked = f.always_on || f.container_backed;
          return (
            <div
              key={f.name}
              className="sccap-card"
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: 12,
                opacity: locked ? 0.7 : 1,
              }}
            >
              <div>
                <div style={{ fontWeight: 600, fontSize: 13.5 }}>
                  {f.name}
                  {f.always_on && (
                    <span style={{ color: "var(--fg-subtle)", fontWeight: 400 }}>
                      {" "}
                      · always on
                    </span>
                  )}
                  {f.container_backed && (
                    <span style={{ color: "var(--fg-subtle)", fontWeight: 400 }}>
                      {" "}
                      · container-backed
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: "var(--fg-muted)" }}>
                  {f.description}
                  {f.depends_on.length > 0 && (
                    <> · requires {f.depends_on.join(", ")}</>
                  )}
                </div>
              </div>
              <input
                type="checkbox"
                checked={on}
                disabled={locked}
                onChange={() => toggle(f)}
                aria-label={`Toggle ${f.name}`}
                style={{ accentColor: "var(--primary)", width: 18, height: 18 }}
              />
            </div>
          );
        })}
      </div>

      <button
        className="sccap-btn sccap-btn-primary"
        onClick={save}
        disabled={saving}
        style={{ marginTop: 16 }}
      >
        {saving ? "Saving…" : "Save changes"}
      </button>
    </div>
  );
};

export default FeaturesPage;
