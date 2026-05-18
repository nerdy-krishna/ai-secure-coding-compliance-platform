// src/shared/hooks/useFeatures.ts
//
// Accessor for the enabled-feature set (modular setup). Must be used within a
// FeatureProvider.

import { useContext } from "react";
import {
  FeatureContext,
  type FeatureContextValue,
} from "../../app/providers/FeatureContext";

export const useFeatures = (): FeatureContextValue => {
  const ctx = useContext(FeatureContext);
  if (!ctx) {
    throw new Error("useFeatures must be used within a FeatureProvider");
  }
  return ctx;
};
