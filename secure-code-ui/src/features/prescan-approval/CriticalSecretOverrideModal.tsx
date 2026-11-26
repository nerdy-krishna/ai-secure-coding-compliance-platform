// secure-code-ui/src/features/prescan-approval/CriticalSecretOverrideModal.tsx
//
// Two-step confirm modal that pops when the operator clicks "Continue
// anyway" on a scan with a Critical Gitleaks finding. The modal lays
// out exactly what proceeding does — sends the source containing the
// secret to the configured LLM provider, Langfuse traces, and Loki
// logs — and requires the operator to type "OVERRIDE" before the
// Continue button enables.
//
// ADR-009 / G6 / G7. The modal is dumb; the host page submits the
// approval request with `override_critical_secret: true` after this
// resolves.
//
// Security note: this modal is a client-side attestation gate only.
// The backend prescan-approval endpoint MUST independently require and
// audit-log the `override_critical_secret: true` flag and reject
// requests that lack it; do not rely on this modal as a security
// boundary.

import React, { useEffect, useState } from "react";
import { Icon } from "../../shared/ui/Icon";
import { Modal } from "../../shared/ui/Modal";

interface Props {
  open: boolean;
  submitting: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}

const CONFIRM_PHRASE = "OVERRIDE";

export const CriticalSecretOverrideModal: React.FC<Props> = ({
  open,
  submitting,
  onCancel,
  onConfirm,
}) => {
  const [typed, setTyped] = useState("");

  // Reset only when the dialog closes, so reopening a *new* gate does not carry
  // the previous confirmation phrase across.
  useEffect(() => {
    if (!open) setTyped("");
  }, [open]);

  const phraseMatches = typed.trim() === CONFIRM_PHRASE;

  return (
    <Modal
      open={open}
      onClose={() => {
        if (!submitting) onCancel();
      }}
      title={
        <span style={{ display: "inline-flex", alignItems: "center", gap: 8, color: "var(--critical)" }}>
          <Icon.Alert size={14} /> Critical secret detected — proceed anyway?
        </span>
      }
      footer={
        <>
          <button
            className="sccap-btn"
            onClick={onCancel}
            disabled={submitting}
          >
            Cancel
          </button>
          <button
            className="sccap-btn sccap-btn-danger"
            onClick={onConfirm}
            disabled={!phraseMatches || submitting}
          >
            {submitting ? "Proceeding…" : "Override and continue"}
          </button>
        </>
      }
    >
      <div style={{ display: "grid", gap: 12, fontSize: 13 }}>
        <div>
          A <strong>Critical-severity secret</strong> was detected in your
          submission. Continuing will send the affected source content to:
        </div>
        <ul style={{ margin: 0, paddingLeft: 20, color: "var(--fg)" }}>
          <li>Your configured <strong>LLM provider</strong> (request body, traceable)</li>
          <li><strong>Langfuse</strong> tracing (if enabled in admin config)</li>
          <li>Application <strong>logs / Loki</strong> for the duration of the scan</li>
        </ul>
        <div style={{ color: "var(--fg-muted)" }}>
          We <strong>strongly recommend</strong> stopping the scan, rotating the
          credential, and resubmitting after the secret has been redacted from
          source. Override only if the credential is non-production, already
          rotated, or you have explicit approval to proceed.
        </div>
        <div
          className="sccap-card"
          style={{
            background: "var(--critical-weak)",
            borderColor: "transparent",
            padding: 12,
          }}
        >
          <div style={{ fontWeight: 600, color: "var(--critical)", marginBottom: 6 }}>
            This decision is recorded in the scan audit log.
          </div>
          <div style={{ color: "var(--fg)" }}>
            Type <code>{CONFIRM_PHRASE}</code> below to enable the Override
            button.
          </div>
        </div>
        <input
          type="text"
          className="sccap-input"
          value={typed}
          onChange={(e) => setTyped(e.target.value)}
          placeholder={CONFIRM_PHRASE}
          // The dialog's own opener focuses this, not the close button that
          // happens to be first in the panel.
          data-modal-autofocus
          autoFocus
          disabled={submitting}
          aria-label="Type OVERRIDE to confirm"
          style={{ width: "100%" }}
        />
      </div>
    </Modal>
  );
};

export default CriticalSecretOverrideModal;
