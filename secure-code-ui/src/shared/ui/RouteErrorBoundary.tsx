import React from "react";

import { ErrorState } from "./AsyncState";

interface State {
  error: Error | null;
}

/** Prevent a failed lazy route from blanking the authenticated application shell. */
export class RouteErrorBoundary extends React.Component<
  React.PropsWithChildren,
  State
> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <ErrorState
        title="This page could not be loaded"
        detail="Check your connection and try loading this route again."
        action={
          <button
            className="sccap-btn sccap-btn-primary"
            onClick={() => window.location.reload()}
          >
            Reload page
          </button>
        }
      />
    );
  }
}
