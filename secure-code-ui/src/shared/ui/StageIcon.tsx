// Renders the icon for a scan-pipeline stage.
//
// Each `RailStage` (see shared/lib/scanProgress) carries an `icon` key —
// the name of an `Icon` component. This tiny wrapper resolves that key
// so the scan-status page and the scan cards share one icon set.

import React from "react";
import { Icon } from "./Icon";

const ICONS = Icon as unknown as Record<
  string,
  React.FC<{ size?: number }>
>;

export const StageIcon: React.FC<{ name: string; size?: number }> = ({
  name,
  size = 14,
}) => {
  const Cmp = ICONS[name];
  return Cmp ? <Cmp size={size} /> : <Icon.Dot size={size} />;
};

export default StageIcon;
