// secure-code-ui/src/features/admin/RuntimeSettings.tsx
//
// The admin-managed settings, rendered from the backend catalog.
//
// Why generated rather than hand-written fields: the explanation, the unit, the
// allowed range and *when* a change takes effect all live next to the value in
// `app.shared.lib.settings_catalog`. A hand-maintained form drifts from that (it
// already had: the profiler limit was not configurable at all, and the concurrency
// overrides silently did nothing), and an operator cannot tell from a bare input what
// a number does or what a sane value is.

import React, { useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import {
  systemConfigService,
  type CatalogSection,
  type CatalogSetting,
} from "../../shared/api/systemConfigService";
import { useToast } from "../../shared/ui/Toast";
import { Icon } from "../../shared/ui/Icon";

const APPLIES_LABEL: Record<string, string> = {
  live: "applies within 30 seconds",
  "next-scan": "applies to the next scan",
  "worker-restart": "applies when the worker restarts",
  "app-restart": "applies when the API restarts",
};

interface Draft {
  [key: string]: string | boolean;
}

const initialDraft = (setting: CatalogSetting): string | boolean => {
  const current = setting.current ?? setting.default;
  if (setting.kind === "bool") return Boolean(current);
  if (current === null || current === undefined) return "";
  return String(current);
};

const SettingRow: React.FC<{
  setting: CatalogSetting;
  value: string | boolean;
  onChange: (next: string | boolean) => void;
  disabled: boolean;
}> = ({ setting, value, onChange, disabled }) => {
  const range =
    setting.kind === "int" && (setting.minimum !== null || setting.maximum !== null)
      ? `${setting.minimum ?? "—"} … ${setting.maximum ?? "—"}`
      : null;

  return (
    <div
      style={{
        display: "grid",
        gridTemplateColumns: "minmax(220px, 1fr) 180px",
        gap: 16,
        padding: "10px 0",
        borderBottom: "1px solid var(--border)",
        alignItems: "start",
      }}
    >
      <div style={{ display: "grid", gap: 3, minWidth: 0 }}>
        <span style={{ fontSize: 13, color: "var(--fg)", fontWeight: 500 }}>
          {setting.label}
          {setting.unit ? (
            <span style={{ color: "var(--fg-subtle)", fontWeight: 400 }}>
              {" "}
              ({setting.unit})
            </span>
          ) : null}
        </span>
        <span style={{ fontSize: 12, color: "var(--fg-muted)", lineHeight: 1.45 }}>
          {setting.description}
        </span>
        <span style={{ fontSize: 11, color: "var(--fg-subtle)" }}>
          {APPLIES_LABEL[setting.applies] ?? setting.applies}
          {range ? ` · range ${range}` : ""}
          {` · key ${setting.key}`}
        </span>
      </div>
      <div style={{ justifySelf: "end" }}>
        {setting.kind === "bool" ? (
          <label
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 8,
              fontSize: 12.5,
              cursor: disabled ? "not-allowed" : "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={Boolean(value)}
              disabled={disabled}
              onChange={(event) => onChange(event.target.checked)}
            />
            {value ? "on" : "off"}
          </label>
        ) : setting.kind === "enum" ? (
          <select
            className="sccap-input"
            value={String(value)}
            disabled={disabled}
            onChange={(event) => onChange(event.target.value)}
            style={{ width: 180 }}
          >
            {setting.choices.map((choice) => (
              <option key={choice} value={choice}>
                {choice}
              </option>
            ))}
          </select>
        ) : (
          <input
            type="number"
            className="sccap-input"
            value={String(value)}
            min={setting.minimum ?? undefined}
            max={setting.maximum ?? undefined}
            step={1}
            disabled={disabled}
            onChange={(event) => onChange(event.target.value)}
            style={{ width: 180 }}
          />
        )}
      </div>
    </div>
  );
};

export const RuntimeSettings: React.FC = () => {
  const queryClient = useQueryClient();
  const toast = useToast();
  const [drafts, setDrafts] = useState<Record<string, Draft>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["system-config-catalog"],
    queryFn: () => systemConfigService.getCatalog(),
    staleTime: 30_000,
  });

  const sections: CatalogSection[] = data ?? [];
  const visible = useMemo(
    () =>
      sections.map((section) => ({
        ...section,
        settings: section.settings.filter((s) => showAdvanced || !s.advanced),
      })),
    [sections, showAdvanced],
  );

  const valueFor = (sectionName: string, setting: CatalogSetting): string | boolean =>
    drafts[sectionName]?.[setting.key] ?? initialDraft(setting);

  const setValue = (
    sectionName: string,
    key: string,
    next: string | boolean,
  ) => {
    setDrafts((prev) => ({
      ...prev,
      [sectionName]: { ...(prev[sectionName] ?? {}), [key]: next },
    }));
  };

  const saveSection = async (section: CatalogSection) => {
    const dirty = section.settings.filter((setting) => {
      const draft = drafts[section.name]?.[setting.key];
      return draft !== undefined && draft !== initialDraft(setting);
    });
    if (dirty.length === 0) return;
    setSaving(section.name);
    try {
      for (const setting of dirty) {
        const raw = valueFor(section.name, setting);
        await systemConfigService.update(setting.key, {
          value:
            setting.kind === "bool"
              ? Boolean(raw)
              : setting.kind === "enum"
                ? String(raw)
                : parseInt(String(raw), 10),
        });
      }
      toast.success(`${section.name}: saved ${dirty.length} value(s).`);
      setDrafts((prev) => ({ ...prev, [section.name]: {} }));
      await queryClient.invalidateQueries({ queryKey: ["system-config-catalog"] });
      await queryClient.invalidateQueries({ queryKey: ["system-configs"] });
    } catch {
      toast.error("Some values were rejected — check the range shown under each field.");
    } finally {
      setSaving(null);
    }
  };

  if (isLoading) {
    return <div className="surface" style={{ padding: 20 }}>Loading settings…</div>;
  }
  if (isError) {
    return (
      <div className="surface" style={{ padding: 20, color: "var(--critical)" }}>
        Could not load the settings catalog.
      </div>
    );
  }

  return (
    <div style={{ display: "grid", gap: 16 }}>
      <div
        className="surface"
        style={{ padding: "12px 16px", display: "flex", gap: 12, alignItems: "center" }}
      >
        <Icon.Settings size={14} />
        <span style={{ fontSize: 12.5, color: "var(--fg-muted)" }}>
          Every value below is resolved from the database first, then <code>.env</code>.
          A fresh install seeds each one at its maximum so nothing is throttled by
          default; lower them for the provider plan you actually pay for.
        </span>
        <label
          style={{
            marginLeft: "auto",
            display: "inline-flex",
            alignItems: "center",
            gap: 6,
            fontSize: 12,
            cursor: "pointer",
            whiteSpace: "nowrap",
          }}
        >
          <input
            type="checkbox"
            checked={showAdvanced}
            onChange={(event) => setShowAdvanced(event.target.checked)}
          />
          show advanced
        </label>
      </div>

      {visible.map((section) => (
        <div key={section.name} className="surface" style={{ padding: 18 }}>
          <div style={{ marginBottom: 4, fontWeight: 600, fontSize: 14 }}>
            {section.name}
          </div>
          <div
            style={{
              marginBottom: 10,
              fontSize: 12,
              color: "var(--fg-muted)",
              lineHeight: 1.5,
            }}
          >
            {section.description}
          </div>
          {section.settings.map((setting) => (
            <SettingRow
              key={setting.key}
              setting={setting}
              value={valueFor(section.name, setting)}
              onChange={(next) => setValue(section.name, setting.key, next)}
              disabled={saving !== null}
            />
          ))}
          <div style={{ marginTop: 12 }}>
            <button
              className="sccap-btn sccap-btn-primary sccap-btn-sm"
              onClick={() => void saveSection(section)}
              disabled={saving !== null}
            >
              {saving === section.name ? "Saving…" : `Save ${section.name.toLowerCase()}`}
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default RuntimeSettings;
