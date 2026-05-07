// secure-code-ui/src/pages/account/AppearanceSettingsPage.tsx
//
// Per-user appearance settings: theme (light/dark), variation (A/B color
// system), and accent color override. Replaces the previous floating
// Tweaks widget with a proper settings page available to every signed-in
// user. Selections still persist via ThemeProvider (localStorage), so
// switching here is reflected globally on next render.

import React from "react";
import { useTheme } from "../../app/providers/ThemeProvider";
import { Icon } from "../../shared/ui/Icon";
import { SectionHead } from "../../shared/ui/DashboardPrimitives";

interface Accent {
  id: string;
  hex: string;
  name: string;
}

const ACCENTS: Record<"A" | "B", Accent[]> = {
  A: [
    { id: "indigo", hex: "#4f46e5", name: "Indigo (default)" },
    { id: "plum", hex: "#9333ea", name: "Plum" },
    { id: "ember", hex: "#ea580c", name: "Ember" },
    { id: "forest", hex: "#059669", name: "Forest" },
  ],
  B: [
    { id: "teal", hex: "#0d9488", name: "Teal (default)" },
    { id: "azure", hex: "#2563eb", name: "Azure" },
    { id: "rose", hex: "#e11d48", name: "Rose" },
    { id: "amber", hex: "#d97706", name: "Amber" },
  ],
};

const SubLabel: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      fontSize: 11,
      color: "var(--fg-muted)",
      textTransform: "uppercase",
      letterSpacing: ".06em",
      marginBottom: 8,
    }}
  >
    {children}
  </div>
);

const Hint: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <div
    style={{
      fontSize: 12,
      color: "var(--fg-subtle)",
      marginTop: 6,
      lineHeight: 1.5,
    }}
  >
    {children}
  </div>
);

const AppearanceSettingsPage: React.FC = () => {
  const { theme, variant, accent, setTheme, setVariant, setAccent } =
    useTheme();

  const resetAll = () => {
    setTheme("light");
    setVariant("A");
    setAccent("");
  };

  return (
    <div className="fade-in" style={{ display: "grid", gap: 20, maxWidth: 720 }}>
      <div className="sccap-card">
        <SectionHead
          title={
            <>
              <Icon.Settings size={16} /> Appearance
            </>
          }
          right={
            <button
              className="sccap-btn sccap-btn-sm sccap-btn-ghost"
              onClick={resetAll}
              title="Reset theme, variation, and accent to defaults"
            >
              Reset to defaults
            </button>
          }
        />
        <div style={{ color: "var(--fg-muted)", fontSize: 13, marginTop: 4 }}>
          These settings are stored in your browser and apply to every page in
          SCCAP.
        </div>
      </div>

      <div className="sccap-card">
        <SubLabel>Theme</SubLabel>
        <div className="radio-group" style={{ width: "100%" }}>
          <button
            className={theme === "light" ? "active" : ""}
            onClick={() => setTheme("light")}
            style={{ flex: 1, display: "inline-flex", gap: 6 }}
          >
            <Icon.Sun size={12} /> Light
          </button>
          <button
            className={theme === "dark" ? "active" : ""}
            onClick={() => setTheme("dark")}
            style={{ flex: 1, display: "inline-flex", gap: 6 }}
          >
            <Icon.Moon size={12} /> Dark
          </button>
        </div>
        <Hint>Light works well in well-lit rooms; dark is easier on the eyes during long sessions.</Hint>
      </div>

      <div className="sccap-card">
        <SubLabel>Color variation</SubLabel>
        <div className="radio-group" style={{ width: "100%" }}>
          <button
            className={variant === "A" ? "active" : ""}
            onClick={() => setVariant("A")}
            style={{ flex: 1 }}
          >
            A · Indigo + Warm
          </button>
          <button
            className={variant === "B" ? "active" : ""}
            onClick={() => setVariant("B")}
            style={{ flex: 1 }}
          >
            B · Teal + Cool
          </button>
        </div>
        <Hint>The variation sets the base palette; the accent below picks the highlight hue within it.</Hint>
      </div>

      <div className="sccap-card">
        <SubLabel>Accent color</SubLabel>
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            gap: 8,
          }}
        >
          {ACCENTS[variant].map((a) => {
            const isActive = accent === a.hex;
            return (
              <button
                key={a.id}
                onClick={() => setAccent(isActive ? "" : a.hex)}
                title={a.name}
                aria-label={a.name}
                aria-pressed={isActive}
                style={{
                  height: 44,
                  borderRadius: 8,
                  border: isActive
                    ? "2px solid var(--fg)"
                    : "1px solid var(--border)",
                  background: a.hex,
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "flex-end",
                  justifyContent: "flex-start",
                  padding: 6,
                  color: "#fff",
                  fontSize: 11,
                  fontWeight: 500,
                  textShadow: "0 1px 2px rgba(0,0,0,.35)",
                }}
              >
                {a.name.split(" ")[0]}
              </button>
            );
          })}
        </div>
        <Hint>
          Click an active swatch again to clear the override and fall back to the
          variation's default accent.
        </Hint>
      </div>

    </div>
  );
};

export default AppearanceSettingsPage;
