// src/app/providers/FeatureProvider.tsx
//
// Supplies the enabled-feature set (modular setup) to the app. Fed by the
// public GET /features endpoint, so it resolves before authentication —
// route guards and the nav consume it via useFeatures().

import React from "react";
import { useQuery } from "@tanstack/react-query";
import { featureService } from "../../shared/api/featureService";
import { FeatureContext } from "./FeatureContext";

export const FeatureProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { data, isLoading } = useQuery({
    queryKey: ["features"],
    queryFn: featureService.getFeatures,
    // The enabled set only changes on app restart or an admin toggle; no
    // point refetching during a session.
    staleTime: Infinity,
    retry: 1,
  });

  const enabledFeatures = new Set(data?.enabled_features ?? []);

  const isFeatureEnabled = (name: string): boolean => {
    if (isLoading || !data) return true;
    return enabledFeatures.has(name);
  };

  return (
    <FeatureContext.Provider
      value={{ enabledFeatures, isFeatureEnabled, featuresLoading: isLoading }}
    >
      {children}
    </FeatureContext.Provider>
  );
};
