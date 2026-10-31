// src/features/semgrep/SemgrepOnboardingWizard.tsx
//
// Shown when 0 rule sources are configured. Loading the built-in community
// library used to be a button an operator had to find and click before their
// first scan; a fresh install therefore reported zero Semgrep findings until
// someone did. It now happens on first visit: seed the built-in sources, enable
// them, and start the first sync, all idempotent server-side. The button remains
// only as the retry path when that automatic run fails.

import React, { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ruleSourcesService } from "../../shared/api/ruleSourcesService";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";
import type { RuleSourceRead } from "../../shared/types/api";

type Phase = "loading" | "enabling" | "syncing" | "done" | "error";

const PHASE_TEXT: Record<Phase, string> = {
  loading: "Loading the built-in rule sources…",
  enabling: "Enabling the sources…",
  syncing: "Starting the first rule sync…",
  done: "Built-in sources are enabled and syncing.",
  error: "Loading the built-in sources failed.",
};

const SemgrepOnboardingWizard: React.FC = () => {
  const toast = useToast();
  const queryClient = useQueryClient();
  const [phase, setPhase] = useState<Phase>("loading");
  const [message, setMessage] = useState<string>("");
  const started = useRef(false);

  const bootstrap = async () => {
    setPhase("loading");
    setMessage("");
    let sources: RuleSourceRead[] = [];
    try {
      sources = await ruleSourcesService.seedSources();
    } catch (err) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      const detail = e.response?.data?.detail ?? e.message ?? "Failed to load the sources";
      setPhase("error");
      setMessage(typeof detail === "string" ? detail : "Failed to load the sources");
      return;
    }

    // The seed upserts the catalogue without touching `enabled`, so a fresh
    // install still has nothing running. Enable them here: the operator opened
    // this page to make Semgrep work, not to review a catalogue.
    setPhase("enabling");
    await Promise.allSettled(
      sources.map((source) => ruleSourcesService.updateSource(source.id, { enabled: true })),
    );

    setPhase("syncing");
    const syncs = await Promise.allSettled(
      sources.map((source) => ruleSourcesService.triggerSync(source.id)),
    );
    const failed = syncs.filter((result) => result.status === "rejected").length;

    await queryClient.invalidateQueries({ queryKey: ["rule-sources"] });
    setPhase("done");

    if (failed > 0) {
      toast.info(
        `Loaded and enabled ${sources.length} sources; ${failed} sync${failed === 1 ? "" : "s"} could not start. Use Sync now to retry.`,
      );
    } else {
      toast.success(
        `Loaded ${sources.length} built-in source${sources.length === 1 ? "" : "s"} and started syncing.`,
      );
    }
  };

  useEffect(() => {
    // React runs effects twice in development StrictMode; the server side is
    // idempotent, but there is no reason to seed twice.
    if (started.current) return;
    started.current = true;
    void bootstrap();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      className="sccap-card"
      style={{
        padding: 48,
        textAlign: "center",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 16,
      }}
    >
      <div style={{ color: phase === "error" ? "var(--critical)" : "var(--primary)" }}>
        {phase === "error" ? <Icon.Alert size={36} /> : <Icon.Code size={36} />}
      </div>
      <div>
        <div style={{ fontWeight: 600, fontSize: 15, color: "var(--fg)", marginBottom: 6 }}>
          {phase === "error" ? "Could not load the rule sources" : "Setting up Semgrep"}
        </div>
        <div style={{ fontSize: 13, color: "var(--fg-muted)", maxWidth: 520, lineHeight: 1.6 }}>
          {phase === "error"
            ? message
            : "The built-in library of community rule sources is loaded, enabled and synced automatically the first time this page is opened. Each source maps to a curated set of Semgrep rules for a specific language or category; you can disable or re-sync them below."}
        </div>
      </div>
      {phase === "done" ? null : phase === "error" ? (
        <button className="sccap-btn sccap-btn-primary" onClick={() => void bootstrap()}>
          <Icon.Refresh size={13} /> Retry
        </button>
      ) : (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            color: "var(--fg-muted)",
            fontSize: 12.5,
          }}
        >
          <div
            className="sccap-spin"
            style={{
              width: 12,
              height: 12,
              border: "2px solid currentColor",
              borderTopColor: "transparent",
              borderRadius: "50%",
            }}
          />
          {PHASE_TEXT[phase]}
        </div>
      )}
    </div>
  );
};

export default SemgrepOnboardingWizard;
