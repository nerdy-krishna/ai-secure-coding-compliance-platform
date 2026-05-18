// src/app/providers/FeatureContext.tsx
//
// Context object + value shape for the enabled-feature set (modular setup).
// Split from FeatureProvider so the provider file only exports a component
// (React Fast Refresh requirement) — mirrors AuthContext / AuthProvider.

import { createContext } from "react";

export interface FeatureContextValue {
  /** Names of enabled features. Empty until the /features query resolves. */
  enabledFeatures: Set<string>;
  /**
   * Whether a feature is enabled. While the query is still loading this
   * returns true — we never flash-hide a feature the install actually has;
   * a genuinely disabled feature is also backstopped by a backend 404.
   */
  isFeatureEnabled: (name: string) => boolean;
  /** True until the first /features response (or error) lands. */
  featuresLoading: boolean;
}

export const FeatureContext = createContext<FeatureContextValue | undefined>(
  undefined,
);
