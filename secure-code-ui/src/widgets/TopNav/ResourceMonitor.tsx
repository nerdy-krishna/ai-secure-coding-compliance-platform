// secure-code-ui/src/widgets/TopNav/ResourceMonitor.tsx
//
// Live resource usage in the header: CPU, memory and disk, at a glance, with the
// detail behind a click.
//
// It polls a cheap endpoint and stays honest about gaps — a value the server cannot
// read is shown as "—", never as zero, because a monitor that reports 0% during an
// outage is worse than one that admits it does not know.

import React, { useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getResourceUsage } from "../../shared/api/systemConfigService";
import { Icon } from "../../shared/ui/Icon";

function tone(percent: number | null | undefined): "ok" | "warn" | "bad" | "unknown" {
  if (percent == null) return "unknown";
  if (percent >= 90) return "bad";
  if (percent >= 75) return "warn";
  return "ok";
}

function fmt(value: number | null | undefined, suffix = "%"): string {
  return value == null ? "—" : `${Math.round(value)}${suffix}`;
}

function uptime(seconds: number | null): string {
  if (!seconds) return "—";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days}d ${hours}h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

const Meter: React.FC<{ label: string; percent: number | null | undefined }> = ({
  label,
  percent,
}) => (
  <span className={`resource-meter is-${tone(percent)}`} title={`${label} ${fmt(percent)}`}>
    <span className="resource-meter-label">{label}</span>
    <span className="resource-meter-bar">
      <i style={{ width: `${Math.min(100, Math.max(0, percent ?? 0))}%` }} />
    </span>
    <span className="resource-meter-value">{fmt(percent)}</span>
  </span>
);

const ResourceMonitor: React.FC = () => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  const usageQ = useQuery({
    queryKey: ["system", "resources"],
    queryFn: getResourceUsage,
    // A monitor, not a report: five seconds is fast enough to see a spike and slow
    // enough not to be the reason the server is busy.
    refetchInterval: 5000,
    refetchOnWindowFocus: true,
    retry: false,
  });

  const usage = usageQ.data;
  const cpu = usage?.cpu.percent ?? null;
  const memory = usage?.memory.host.percent ?? null;
  const disk = usage?.disk.percent ?? null;
  const worst = [cpu, memory, disk].filter((value): value is number => value != null);
  const overall = worst.length ? Math.max(...worst) : null;

  return (
    <div className="resource-monitor" ref={ref}>
      <button
        className={`resource-trigger is-${tone(overall)}${open ? " is-open" : ""}`}
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        aria-label="Resource usage"
        title="CPU, memory and disk usage"
      >
        <Icon.Cpu size={14} />
        <span className="resource-mini">
          <span>{fmt(cpu)}</span>
          <span>{fmt(memory)}</span>
        </span>
      </button>

      {open && (
        <div className="resource-panel surface">
          <div className="resource-head">
            <strong>This deployment</strong>
            <span className="resource-muted">
              {usage?.version ?? "running build"} · {usage?.environment ?? ""}
            </span>
          </div>

          {usageQ.isError && (
            <p className="resource-error">Resource usage is unavailable from the API.</p>
          )}

          <div className="resource-rows">
            <Meter label="CPU" percent={cpu} />
            <Meter label="Memory" percent={memory} />
            <Meter label="Disk" percent={disk} />
          </div>

          <dl className="resource-facts">
            <dt>Load average</dt>
            <dd>
              {usage
                ? `${usage.cpu.load["1m"].toFixed(2)} · ${usage.cpu.load["5m"].toFixed(2)} · ${usage.cpu.load["15m"].toFixed(2)}`
                : "—"}
            </dd>
            <dt>Cores</dt>
            <dd>
              {usage ? `${usage.cpu.cores} available` + (usage.cpu.host_cores !== usage.cpu.cores ? ` of ${usage.cpu.host_cores}` : "") : "—"}
            </dd>
            <dt>Host memory</dt>
            <dd>
              {usage?.memory.host.used_mb != null && usage.memory.host.total_mb != null
                ? `${(usage.memory.host.used_mb / 1024).toFixed(1)} / ${(usage.memory.host.total_mb / 1024).toFixed(1)} GB`
                : "—"}
            </dd>
            <dt>App container</dt>
            <dd>
              {usage?.memory.container.used_mb != null
                ? `${usage.memory.container.used_mb} MB` +
                  (usage.memory.container.limit_mb
                    ? ` of ${usage.memory.container.limit_mb} MB`
                    : " (no limit)")
                : "—"}
            </dd>
            <dt>Disk</dt>
            <dd>
              {usage?.disk.used_gb != null && usage.disk.total_gb != null
                ? `${usage.disk.used_gb} / ${usage.disk.total_gb} GB (${usage.disk.free_gb} GB free)`
                : "—"}
            </dd>
            <dt>Uptime</dt>
            <dd>{usage ? uptime(usage.uptime_seconds) : "—"}</dd>
            <dt>Running work</dt>
            <dd>
              {usage
                ? `${usage.work.active_scans} scan(s) · ${usage.work.running_pentests} pentest(s)`
                : "—"}
            </dd>
          </dl>

          <p className="resource-foot">
            Sampled in {usage?.collected_ms ?? "—"} ms. A dash means the host does not
            expose that value — it is not zero.
          </p>
        </div>
      )}
    </div>
  );
};

export default ResourceMonitor;
