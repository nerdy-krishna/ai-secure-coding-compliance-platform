// Inline scan lifecycle controls (#87 / PRD #83).
//
// Rendered in the ScanCard `controls` slot on the Scans list and the
// project detail scan list. An active scan gets a Stop button; a
// terminal scan gets Delete; a failed/cancelled scan with resumable
// artifacts gets Resume + Restart.

import React, { useState } from "react";

import { useMutation } from "@tanstack/react-query";

import { scanService } from "../../shared/api/scanService";
import { isTerminalStatus } from "../../shared/lib/scanProgress";
import type { ScanHistoryItem } from "../../shared/types/api";
import { Icon } from "../../shared/ui/Icon";
import { useToast } from "../../shared/ui/Toast";

interface ScanRowControlsProps {
  scan: ScanHistoryItem;
  /** Called after a successful mutation so the list refetches. */
  onChanged: () => void;
}

export const ScanRowControls: React.FC<ScanRowControlsProps> = ({
  scan,
  onChanged,
}) => {
  const toast = useToast();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const isActive = !isTerminalStatus(scan.status);
  const canRunControl =
    scan.status === "FAILED" ||
    (scan.status === "CANCELLED" && scan.has_resumable_artifacts);

  const stopMut = useMutation({
    mutationFn: () => scanService.cancelScan(scan.id),
    onSuccess: () => {
      toast.info("Scan stopped.");
      onChanged();
    },
    onError: () => toast.error("Could not stop the scan."),
  });

  const deleteMut = useMutation({
    mutationFn: () => scanService.deleteScan(scan.id),
    onSuccess: () => {
      toast.info("Scan deleted.");
      onChanged();
    },
    onError: () => toast.error("Could not delete the scan."),
  });

  const resumeMut = useMutation({
    mutationFn: () => scanService.runControlScan(scan.id, "resume"),
    onSuccess: () => {
      toast.info("Scan resume queued. Completed durable work will be reused.");
      onChanged();
    },
    onError: () => toast.error("Could not resume the scan."),
  });

  const restartMut = useMutation({
    mutationFn: () => scanService.runControlScan(scan.id, "restart"),
    onSuccess: () => {
      toast.info("Scan restart queued.");
      onChanged();
    },
    onError: () => toast.error("Could not restart the scan."),
  });

  if (isActive) {
    return (
      <button
        className="sccap-btn sccap-btn-sm"
        disabled={stopMut.isPending}
        onClick={() => stopMut.mutate()}
        title="Stop this scan"
      >
        <Icon.X size={12} /> Stop
      </button>
    );
  }

  if (confirmDelete) {
    return (
      <span style={{ display: "flex", gap: 6 }}>
        <button
          className="sccap-btn sccap-btn-sm"
          onClick={() => setConfirmDelete(false)}
        >
          Cancel
        </button>
        <button
          className="sccap-btn sccap-btn-sm"
          style={{ color: "var(--critical)", borderColor: "var(--critical)" }}
          disabled={deleteMut.isPending}
          onClick={() => deleteMut.mutate()}
        >
          Confirm delete
        </button>
      </span>
    );
  }

  return (
    <span style={{ display: "flex", gap: 6 }}>
      {canRunControl && (
        <>
          <button
            className="sccap-btn sccap-btn-sm sccap-btn-primary"
            disabled={resumeMut.isPending}
            onClick={() => resumeMut.mutate()}
            title="Resume — reuse completed durable work"
          >
            {resumeMut.isPending ? "…" : "Resume"}
          </button>
          <button
            className="sccap-btn sccap-btn-sm"
            disabled={restartMut.isPending}
            onClick={() => restartMut.mutate()}
            title="Restart — discard partial artifacts, rerun from original snapshot"
          >
            {restartMut.isPending ? "…" : "Restart"}
          </button>
        </>
      )}
      <button
        className="sccap-btn sccap-btn-sm"
        style={{ color: "var(--critical)" }}
        onClick={() => setConfirmDelete(true)}
        title="Delete this scan"
      >
        <Icon.Trash size={12} /> Delete
      </button>
    </span>
  );
};
