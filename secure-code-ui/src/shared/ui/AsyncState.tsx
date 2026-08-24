import React from "react";

import { Icon } from "./Icon";

interface StateProps {
  title: string;
  detail?: React.ReactNode;
  action?: React.ReactNode;
  compact?: boolean;
}

const StateFrame: React.FC<StateProps & { children?: React.ReactNode }> = ({
  title,
  detail,
  action,
  compact = false,
  children,
}) => (
  <section
    className={`sccap-state${compact ? " sccap-state-compact" : ""}`}
    aria-label={title}
  >
    {children}
    <div>
      <h2>{title}</h2>
      {detail ? <p>{detail}</p> : null}
    </div>
    {action}
  </section>
);

export const LoadingState: React.FC<
  Omit<StateProps, "action"> & { fullscreen?: boolean }
> = ({ title, detail, compact, fullscreen = false }) => (
  <div
    className={fullscreen ? "sccap-state-fullscreen" : undefined}
    role="status"
    aria-live="polite"
  >
    <StateFrame title={title} detail={detail} compact={compact}>
      <span className="sccap-spinner" aria-hidden="true" />
    </StateFrame>
  </div>
);

export const EmptyState: React.FC<StateProps> = (props) => (
  <StateFrame {...props}>
    <Icon.Folder size={22} aria-hidden="true" />
  </StateFrame>
);

export const ErrorState: React.FC<StateProps> = (props) => (
  <StateFrame {...props}>
    <Icon.Alert size={22} aria-hidden="true" />
  </StateFrame>
);
