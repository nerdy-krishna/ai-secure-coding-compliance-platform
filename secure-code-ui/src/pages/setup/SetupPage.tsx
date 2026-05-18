// secure-code-ui/src/pages/setup/SetupPage.tsx
//
// SCCAP first-run setup wizard. Step 0 surfaces the installation variant
// chosen in setup.sh — read-only for the presets, a grouped feature picker
// for `custom` (modular setup — #107). The remaining steps (deployment,
// admin account, LLM) are unchanged.
//
// All bounds enforced here are advisory; the backend /setup endpoint MUST
// re-validate every field with the same or stricter constraints.

import React, { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import apiClient from "../../shared/api/apiClient";
import {
  featureService,
  type FeatureCatalogEntry,
} from "../../shared/api/featureService";
import { useAuth } from "../../shared/hooks/useAuth";
import { Icon } from "../../shared/ui/Icon";

type DeploymentType = "local" | "cloud";
type LLMMode = "multi_provider" | "anthropic_optimized";

interface SetupFormValues {
  deployment_type: DeploymentType;
  frontend_url: string;
  admin_email: string;
  admin_password: string;
  llm_optimization_mode: LLMMode;
  llm_provider: string;
  llm_model: string;
  llm_api_key: string;
}

const STEPS = ["Variant", "Deployment", "Admin", "LLM mode", "LLM config"] as const;

const DEFAULTS: SetupFormValues = {
  deployment_type: "local",
  frontend_url: "",
  admin_email: "",
  admin_password: "",
  llm_optimization_mode: "multi_provider",
  llm_provider: "openai",
  llm_model: "gpt-4o",
  llm_api_key: "",
};

// Visual grouping for the custom-variant feature picker.
const FEATURE_GROUPS: { title: string; features: string[] }[] = [
  { title: "Core", features: ["scan"] },
  { title: "Analysis", features: ["chat", "compliance", "mcp"] },
  { title: "Collaboration", features: ["multi_user", "user_groups", "multi_tenant"] },
  { title: "Enterprise auth", features: ["sso", "scim"] },
  { title: "Operations", features: ["email", "log_stack", "tracing", "admin_authoring"] },
];

const SetupPage: React.FC = () => {
  const navigate = useNavigate();
  const { isSetupCompleted, isLoading, checkSetupStatus } = useAuth();

  const [step, setStep] = useState(0);
  const [form, setForm] = useState<SetupFormValues>(DEFAULTS);
  const [stepError, setStepError] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Modular-setup state — variant + catalog from the public /features endpoint.
  const [variant, setVariant] = useState<string>("enterprise");
  const [catalog, setCatalog] = useState<FeatureCatalogEntry[]>([]);
  const [activeProfiles, setActiveProfiles] = useState<string[]>([]);
  const [customEnabled, setCustomEnabled] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (!isLoading && isSetupCompleted) {
      navigate("/login");
    }
  }, [isSetupCompleted, isLoading, navigate]);

  useEffect(() => {
    featureService
      .getFeatures()
      .then((res) => {
        setVariant(res.variant);
        setCatalog(res.catalog);
        setActiveProfiles(res.compose_profiles);
        // custom starts at the always-on floor; the operator ticks up.
        setCustomEnabled(
          new Set(res.catalog.filter((f) => f.always_on).map((f) => f.name)),
        );
      })
      .catch(() => {
        // /features should always answer; fall back to a preset experience.
        setVariant("enterprise");
      });
  }, []);

  useEffect(() => {
    if (form.llm_optimization_mode === "anthropic_optimized") {
      if (form.llm_provider !== "anthropic") {
        setForm((f) => ({
          ...f,
          llm_provider: "anthropic",
          llm_model: "claude-sonnet-4-6",
        }));
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [form.llm_optimization_mode]);

  // Dependency maps for the custom picker's auto-resolve.
  const { depsOf, dependentsOf } = useMemo(() => {
    const deps = new Map<string, string[]>();
    const rev = new Map<string, string[]>();
    for (const f of catalog) {
      deps.set(f.name, f.depends_on);
      for (const d of f.depends_on) {
        const arr = rev.get(d) ?? [];
        arr.push(f.name);
        rev.set(d, arr);
      }
    }
    return { depsOf: deps, dependentsOf: rev };
  }, [catalog]);

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

  const toggleFeature = (entry: FeatureCatalogEntry) => {
    if (entry.always_on) return;
    // A container-backed feature whose stack was not selected in setup.sh
    // cannot be enabled here.
    if (
      entry.container_backed &&
      entry.compose_profile &&
      !activeProfiles.includes(entry.compose_profile)
    ) {
      return;
    }
    setCustomEnabled((prev) => {
      const next = new Set(prev);
      if (next.has(entry.name)) {
        next.delete(entry.name);
        for (const dep of closure(entry.name, dependentsOf)) next.delete(dep);
      } else {
        next.add(entry.name);
        for (const dep of closure(entry.name, depsOf)) next.add(dep);
      }
      return next;
    });
  };

  if (isLoading) {
    return (
      <div
        style={{
          minHeight: "100vh",
          display: "grid",
          placeItems: "center",
          color: "var(--fg-muted)",
        }}
      >
        Loading…
      </div>
    );
  }

  const isCustom = variant === "custom";

  const validateStep = (): boolean => {
    if (step === 1) {
      if (!form.deployment_type) {
        setStepError("Select a deployment environment.");
        return false;
      }
      if (form.deployment_type === "cloud") {
        if (!form.frontend_url || form.frontend_url.length > 512) {
          setStepError("Enter the production frontend URL (max 512 characters).");
          return false;
        }
        const isLocalhost = /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/.*)?$/.test(
          form.frontend_url,
        );
        if (!isLocalhost && !/^https:\/\//i.test(form.frontend_url)) {
          setStepError(
            "Enter the production frontend URL with an https:// scheme. Cloud deployments must terminate TLS.",
          );
          return false;
        }
      }
    }
    if (step === 2) {
      if (!form.admin_email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(form.admin_email)) {
        setStepError("Enter a valid admin email.");
        return false;
      }
      if (form.admin_email.length > 254) {
        setStepError("Admin email must be 254 characters or fewer.");
        return false;
      }
      if (!form.admin_password || form.admin_password.length < 8) {
        setStepError("Admin password must be at least 8 characters.");
        return false;
      }
      if (form.admin_password.length > 256) {
        setStepError("Admin password must be 256 characters or fewer.");
        return false;
      }
    }
    if (step === 4) {
      if (!form.llm_provider || !form.llm_model || !form.llm_api_key) {
        setStepError("LLM provider, model, and API key are required.");
        return false;
      }
      if (form.llm_model.length > 128) {
        setStepError("Model name must be 128 characters or fewer.");
        return false;
      }
      if (!/^[A-Za-z0-9._/:-]+$/.test(form.llm_model)) {
        setStepError(
          "Model name may only contain letters, digits, and the characters . _ / : -",
        );
        return false;
      }
      if (form.llm_api_key.length > 4096) {
        setStepError("API key must be 4096 characters or fewer.");
        return false;
      }
    }
    setStepError(null);
    return true;
  };

  const goNext = () => {
    if (!validateStep()) return;
    setStep((s) => Math.min(s + 1, STEPS.length - 1));
  };
  const goBack = () => setStep((s) => Math.max(s - 1, 0));

  const onSubmit = async () => {
    if (!validateStep()) return;
    setSubmitting(true);
    setError(null);
    try {
      const payload: Record<string, unknown> = { ...form };
      // Only the custom variant sends an explicit feature selection; presets
      // are seeded server-side from SCCAP_VARIANT.
      if (isCustom) {
        payload.enabled_features = [...customEnabled];
      }
      await apiClient.post("/setup", payload);
      await checkSetupStatus();
      navigate("/login");
    } catch (err) {
      const e = err as {
        response?: { data?: { detail?: unknown } };
        message?: string;
      };
      const detail = e.response?.data?.detail;
      const msg =
        typeof detail === "string"
          ? detail
          : detail
            ? JSON.stringify(detail)
            : e.message || "Setup failed. Please try again.";
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        background: "var(--bg)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 24,
      }}
    >
      <div className="surface" style={{ width: "100%", maxWidth: 640, padding: 32 }}>
        <div style={{ textAlign: "center", marginBottom: 14 }}>
          <div
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 10,
              color: "var(--fg)",
              fontSize: 20,
              fontWeight: 600,
            }}
          >
            <Icon.Shield size={22} color="var(--primary)" /> SCCAP setup
          </div>
          <div style={{ color: "var(--fg-muted)", fontSize: 12.5, marginTop: 4 }}>
            Confirm the variant, then configure deployment, the admin account,
            and your LLM provider.
          </div>
        </div>

        <StepsHeader current={step} />

        {error && (
          <div
            className="sccap-card"
            style={{
              padding: 12,
              marginBottom: 14,
              background: "var(--critical-weak)",
              borderColor: "var(--critical)",
              color: "var(--critical)",
              fontSize: 13,
              display: "flex",
              justifyContent: "space-between",
            }}
          >
            <span>{error}</span>
            <button
              className="sccap-btn sccap-btn-icon sccap-btn-ghost"
              onClick={() => setError(null)}
            >
              <Icon.X size={12} />
            </button>
          </div>
        )}

        {stepError && (
          <div style={{ color: "var(--critical)", fontSize: 12, marginBottom: 12 }}>
            {stepError}
          </div>
        )}

        <div style={{ display: "grid", gap: 14 }}>
          {step === 0 && (
            <Field
              label="Installation variant"
              hint={isCustom ? "Pick the features to enable." : "Set by setup.sh."}
            >
              <div
                className="sccap-card"
                style={{ padding: 12, fontSize: 13 }}
              >
                <strong style={{ textTransform: "capitalize" }}>
                  {variant.replace("_", " ")}
                </strong>
                {!isCustom && (
                  <div
                    style={{
                      color: "var(--fg-muted)",
                      fontSize: 12,
                      marginTop: 4,
                    }}
                  >
                    Features for this variant are seeded automatically. Change
                    them later from Admin → Features.
                  </div>
                )}
              </div>
              {isCustom && (
                <FeatureToggles
                  catalog={catalog}
                  enabled={customEnabled}
                  activeProfiles={activeProfiles}
                  onToggle={toggleFeature}
                />
              )}
            </Field>
          )}

          {step === 1 && (
            <>
              <Field label="Deployment environment">
                <RadioCard
                  checked={form.deployment_type === "local"}
                  onChange={() => setForm({ ...form, deployment_type: "local" })}
                  title="Local development"
                  desc="App runs on your machine with default CORS."
                />
                <RadioCard
                  checked={form.deployment_type === "cloud"}
                  onChange={() => setForm({ ...form, deployment_type: "cloud" })}
                  title="Cloud / VPS"
                  desc="Expose via a public URL."
                />
              </Field>
              {form.deployment_type === "cloud" && (
                <Field
                  label="Public frontend URL"
                  hint="Where users will access the UI. HTTPS only."
                >
                  <input
                    className="sccap-input"
                    placeholder="https://yourdomain.com"
                    value={form.frontend_url}
                    onChange={(e) =>
                      setForm({ ...form, frontend_url: e.target.value })
                    }
                  />
                </Field>
              )}
            </>
          )}

          {step === 2 && (
            <>
              <Field label="Admin email">
                <input
                  className="sccap-input"
                  type="email"
                  autoComplete="email"
                  value={form.admin_email}
                  onChange={(e) =>
                    setForm({ ...form, admin_email: e.target.value })
                  }
                />
              </Field>
              <Field label="Admin password" hint="Minimum 8 characters.">
                <input
                  className="sccap-input"
                  type="password"
                  autoComplete="new-password"
                  value={form.admin_password}
                  onChange={(e) =>
                    setForm({ ...form, admin_password: e.target.value })
                  }
                />
              </Field>
            </>
          )}

          {step === 3 && (
            <Field label="LLM optimization mode">
              <RadioCard
                checked={form.llm_optimization_mode === "anthropic_optimized"}
                onChange={() =>
                  setForm({ ...form, llm_optimization_mode: "anthropic_optimized" })
                }
                title="Anthropic optimized (recommended)"
                desc="Prompt caching, tuned prompt variants, tool use. Locks the provider to Anthropic. Typical 70%+ cost drop on repeated-agent-per-file scans."
              />
              <RadioCard
                checked={form.llm_optimization_mode === "multi_provider"}
                onChange={() =>
                  setForm({ ...form, llm_optimization_mode: "multi_provider" })
                }
                title="Multi-provider (generic)"
                desc="Portable prompts across OpenAI, Anthropic, and Google. No caching; broader model choice."
              />
            </Field>
          )}

          {step === 4 && (
            <>
              <Field
                label="LLM provider"
                hint={
                  form.llm_optimization_mode === "anthropic_optimized"
                    ? "Locked to Anthropic by the optimization mode."
                    : undefined
                }
              >
                <select
                  className="sccap-input"
                  value={form.llm_provider}
                  disabled={form.llm_optimization_mode === "anthropic_optimized"}
                  onChange={(e) =>
                    setForm({ ...form, llm_provider: e.target.value })
                  }
                >
                  <option value="openai">OpenAI</option>
                  <option value="anthropic">Anthropic</option>
                  <option value="google">Google Gemini</option>
                  <option value="deepseek">DeepSeek</option>
                  <option value="xai">xAI Grok</option>
                </select>
              </Field>
              <Field label="Model name">
                <input
                  className="sccap-input mono"
                  placeholder="e.g. gpt-4o, claude-sonnet-4-6"
                  pattern="[A-Za-z0-9._/:-]+"
                  maxLength={128}
                  value={form.llm_model}
                  onChange={(e) => setForm({ ...form, llm_model: e.target.value })}
                />
              </Field>
              <Field label="API key">
                <input
                  className="sccap-input mono"
                  type="password"
                  autoComplete="off"
                  value={form.llm_api_key}
                  onChange={(e) =>
                    setForm({ ...form, llm_api_key: e.target.value })
                  }
                />
              </Field>
            </>
          )}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            marginTop: 24,
          }}
        >
          <button
            className="sccap-btn"
            onClick={goBack}
            disabled={step === 0 || submitting}
          >
            <Icon.ChevronL size={12} /> Back
          </button>
          {step < STEPS.length - 1 ? (
            <button className="sccap-btn sccap-btn-primary" onClick={goNext}>
              Next <Icon.ChevronR size={12} />
            </button>
          ) : (
            <button
              className="sccap-btn sccap-btn-primary"
              onClick={onSubmit}
              disabled={submitting}
            >
              {submitting ? "Finishing…" : "Finish setup"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

const FeatureToggles: React.FC<{
  catalog: FeatureCatalogEntry[];
  enabled: Set<string>;
  activeProfiles: string[];
  onToggle: (entry: FeatureCatalogEntry) => void;
}> = ({ catalog, enabled, activeProfiles, onToggle }) => {
  const byName = new Map(catalog.map((f) => [f.name, f]));
  return (
    <div style={{ display: "grid", gap: 12, marginTop: 10 }}>
      {FEATURE_GROUPS.map((group) => {
        const entries = group.features
          .map((n) => byName.get(n))
          .filter((f): f is FeatureCatalogEntry => Boolean(f));
        if (entries.length === 0) return null;
        return (
          <div key={group.title}>
            <div
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: "var(--fg-subtle)",
                textTransform: "uppercase",
                marginBottom: 4,
              }}
            >
              {group.title}
            </div>
            <div style={{ display: "grid", gap: 4 }}>
              {entries.map((f) => {
                const containerMissing =
                  f.container_backed &&
                  !!f.compose_profile &&
                  !activeProfiles.includes(f.compose_profile);
                const locked = f.always_on || containerMissing;
                return (
                  <label
                    key={f.name}
                    onClick={() => onToggle(f)}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      gap: 10,
                      padding: "8px 10px",
                      border: "1px solid var(--border)",
                      borderRadius: "var(--r-sm)",
                      background: "var(--bg-elev)",
                      cursor: locked ? "not-allowed" : "pointer",
                      opacity: locked ? 0.55 : 1,
                    }}
                  >
                    <span>
                      <span style={{ fontSize: 13, fontWeight: 500 }}>
                        {f.name}
                      </span>
                      <span
                        style={{
                          fontSize: 11,
                          color: "var(--fg-muted)",
                          marginLeft: 6,
                        }}
                      >
                        {containerMissing
                          ? "container stack not selected in setup.sh"
                          : f.always_on
                            ? "always on"
                            : f.description}
                      </span>
                    </span>
                    <input
                      type="checkbox"
                      checked={enabled.has(f.name)}
                      disabled={locked}
                      readOnly
                      style={{ accentColor: "var(--primary)" }}
                    />
                  </label>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
};

const StepsHeader: React.FC<{ current: number }> = ({ current }) => (
  <div
    style={{
      display: "grid",
      gridTemplateColumns: `repeat(${STEPS.length}, 1fr)`,
      gap: 4,
      margin: "20px 0 24px",
    }}
  >
    {STEPS.map((label, i) => {
      const active = i === current;
      const done = i < current;
      return (
        <div key={label} style={{ textAlign: "center" }}>
          <div
            style={{
              margin: "0 auto 6px",
              width: 26,
              height: 26,
              borderRadius: 13,
              display: "grid",
              placeItems: "center",
              background: done || active ? "var(--primary)" : "var(--bg-soft)",
              color: done || active ? "white" : "var(--fg-muted)",
              fontSize: 12,
              fontWeight: 600,
            }}
          >
            {done ? <Icon.Check size={13} /> : i + 1}
          </div>
          <div
            style={{
              fontSize: 11,
              color: active
                ? "var(--fg)"
                : done
                  ? "var(--fg-muted)"
                  : "var(--fg-subtle)",
              fontWeight: active ? 600 : 400,
            }}
          >
            {label}
          </div>
        </div>
      );
    })}
  </div>
);

const Field: React.FC<{
  label: string;
  hint?: string;
  children: React.ReactNode;
}> = ({ label, hint, children }) => (
  <label style={{ display: "grid", gap: 6 }}>
    <span style={{ fontSize: 12, color: "var(--fg-muted)", fontWeight: 500 }}>
      {label}
      {hint && (
        <span style={{ marginLeft: 8, color: "var(--fg-subtle)", fontWeight: 400 }}>
          {hint}
        </span>
      )}
    </span>
    {children}
  </label>
);

const RadioCard: React.FC<{
  checked: boolean;
  onChange: () => void;
  title: string;
  desc: string;
}> = ({ checked, onChange, title, desc }) => (
  <label
    onClick={onChange}
    style={{
      display: "grid",
      gridTemplateColumns: "auto 1fr",
      gap: 10,
      padding: 12,
      border: "1px solid " + (checked ? "var(--primary)" : "var(--border)"),
      background: checked ? "var(--primary-weak)" : "var(--bg-elev)",
      borderRadius: "var(--r-sm)",
      cursor: "pointer",
      marginTop: 6,
    }}
  >
    <input
      type="radio"
      checked={checked}
      onChange={onChange}
      style={{ accentColor: "var(--primary)", marginTop: 3 }}
    />
    <div>
      <div style={{ fontSize: 13.5, fontWeight: 500, color: "var(--fg)" }}>
        {title}
      </div>
      <div
        style={{
          fontSize: 11.5,
          color: "var(--fg-muted)",
          marginTop: 2,
          lineHeight: 1.5,
        }}
      >
        {desc}
      </div>
    </div>
  </label>
);

export default SetupPage;
