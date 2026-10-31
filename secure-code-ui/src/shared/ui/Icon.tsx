// secure-code-ui/src/shared/ui/Icon.tsx
//
// Typed port of the SCCAP design bundle's Icons.jsx (stroke icons, 16–20px,
// stroke 1.75, round caps + joins). Exposed as a namespace object so usage
// matches the prototype: `<Icon.Shield size={16} />`, `<Icon.Chat />`, etc.

import React from "react";

export interface IconProps {
  size?: number;
  className?: string;
  style?: React.CSSProperties;
  // Inherits color from currentColor; override on the wrapping element or via color prop.
  color?: string;
}

const Svg: React.FC<IconProps & { children: React.ReactNode }> = ({
  size = 16,
  className,
  style,
  color,
  children,
}) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    stroke={color ?? "currentColor"}
    strokeWidth="1.75"
    strokeLinecap="round"
    strokeLinejoin="round"
    className={className}
    style={style}
    aria-hidden="true"
    focusable="false"
  >
    {children}
  </svg>
);

// Each icon is a small functional component so trees don't carry an extra wrapper.
// Prefer named imports via the `Icon.X` namespace at the bottom of the file.

const Shield: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 3l8 3v6c0 4.5-3.2 8.3-8 9-4.8-.7-8-4.5-8-9V6l8-3z" />
  </Svg>
);

const Logo: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 3l8 3v6c0 4.5-3.2 8.3-8 9-4.8-.7-8-4.5-8-9V6l8-3z" />
    <path d="M9 12l2 2 4-4" />
  </Svg>
);

const Home: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 11l9-7 9 7" />
    <path d="M5 10v10h14V10" />
  </Svg>
);

const Upload: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 15V3" />
    <path d="M7 8l5-5 5 5" />
    <path d="M5 15v4a2 2 0 002 2h10a2 2 0 002-2v-4" />
  </Svg>
);

const Folder: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z" />
  </Svg>
);

const Sparkle: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.5 5.5l2.8 2.8M15.7 15.7l2.8 2.8M5.5 18.5l2.8-2.8M15.7 8.3l2.8-2.8" />
  </Svg>
);

const Chat: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M21 12a8 8 0 01-11.6 7.2L4 20l1-4.5A8 8 0 1121 12z" />
  </Svg>
);

const History: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 12a9 9 0 109-9" />
    <path d="M3 3v6h6" />
    <path d="M12 7v5l3 2" />
  </Svg>
);

const Check: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M20 6L9 17l-5-5" />
  </Svg>
);

const X: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M18 6L6 18M6 6l12 12" />
  </Svg>
);

const ChevronR: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M9 6l6 6-6 6" />
  </Svg>
);

const ChevronL: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M15 6l-6 6 6 6" />
  </Svg>
);

const ChevronD: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M6 9l6 6 6-6" />
  </Svg>
);

const ChevronU: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M18 15l-6-6-6 6" />
  </Svg>
);

const Search: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="11" cy="11" r="7" />
    <path d="M20 20l-3.5-3.5" />
  </Svg>
);

const Bell: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M6 8a6 6 0 0112 0c0 7 3 9 3 9H3s3-2 3-9" />
    <path d="M10 21a2 2 0 004 0" />
  </Svg>
);

const User: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="12" cy="8" r="4" />
    <path d="M4 21a8 8 0 0116 0" />
  </Svg>
);

const Users: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="9" cy="8" r="3.5" />
    <path d="M2 20a7 7 0 0114 0" />
    <path d="M16 4a3.5 3.5 0 010 7" />
    <path d="M22 20a6.5 6.5 0 00-5-6.3" />
  </Svg>
);

const Settings: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.7 1.7 0 00.3 1.8l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.8-.3 1.7 1.7 0 00-1 1.5V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1.1-1.5 1.7 1.7 0 00-1.8.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.8 1.7 1.7 0 00-1.5-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.5-1.1 1.7 1.7 0 00-.3-1.8L4.2 7a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.8.3H9a1.7 1.7 0 001-1.5V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.5 1.7 1.7 0 001.8-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.8V9a1.7 1.7 0 001.5 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.5 1z" />
  </Svg>
);

const Github: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M9 19c-4 1-4-2-6-2m12 5v-3.5c0-1 .1-1.4-.5-2 2.8-.3 5.5-1.4 5.5-6a4.6 4.6 0 00-1.3-3.2 4.2 4.2 0 00-.1-3.2s-1.1-.3-3.5 1.3a12 12 0 00-6.2 0C6.5 3.8 5.4 4.1 5.4 4.1a4.2 4.2 0 00-.1 3.2A4.6 4.6 0 004 10.5c0 4.6 2.7 5.7 5.5 6-.6.6-.6 1.2-.5 2V22" />
  </Svg>
);

const Gitlab: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 21l-9-7 3-10 3 7h6l3-7 3 10-9 7z" />
  </Svg>
);

const Bitbucket: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 4h18l-2 16H5L3 4z" />
    <path d="M9 10h6l-1 4h-4l-1-4z" />
  </Svg>
);

const File: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M14 3H7a2 2 0 00-2 2v14a2 2 0 002 2h10a2 2 0 002-2V8l-5-5z" />
    <path d="M14 3v5h5" />
  </Svg>
);

const Code: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M16 18l6-6-6-6M8 6l-6 6 6 6" />
  </Svg>
);

const Zap: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" />
  </Svg>
);

const Play: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M6 4l14 8-14 8V4z" />
  </Svg>
);

const Pause: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="6" y="4" width="4" height="16" rx="1" />
    <rect x="14" y="4" width="4" height="16" rx="1" />
  </Svg>
);

const Download: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 3v14" />
    <path d="M7 12l5 5 5-5" />
    <path d="M5 21h14" />
  </Svg>
);

const Send: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M22 2L11 13" />
    <path d="M22 2l-7 20-4-9-9-4 20-7z" />
  </Svg>
);

const Minus: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M5 12h14" />
  </Svg>
);

const Expand: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M4 9V4h5M20 15v5h-5M15 4h5v5M9 20H4v-5" />
  </Svg>
);

const Collapse: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M9 4v5H4M15 20v-5h5M20 9h-5V4M4 15h5v5" />
  </Svg>
);

const Plus: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 5v14M5 12h14" />
  </Svg>
);

const Filter: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 5h18l-7 9v6l-4-2v-4L3 5z" />
  </Svg>
);

const Sort: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M7 4v16M3 8l4-4 4 4M17 20V4M13 16l4 4 4-4" />
  </Svg>
);

const Terminal: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="2" y="4" width="20" height="16" rx="2" />
    <path d="M7 10l3 2-3 2M13 14h4" />
  </Svg>
);

const Lock: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="4" y="11" width="16" height="10" rx="2" />
    <path d="M8 11V7a4 4 0 018 0v4" />
  </Svg>
);

const Eye: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12z" />
    <circle cx="12" cy="12" r="3" />
  </Svg>
);

const Book: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M4 3h7a3 3 0 013 3v15a2 2 0 00-2-2H4V3z" />
    <path d="M20 3h-7a3 3 0 00-3 3v15a2 2 0 012-2h8V3z" />
  </Svg>
);

const Hourglass: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M6 2h12M6 22h12" />
    <path d="M7 2v3.5c0 2 2.5 3.3 4 5 1.5-1.7 4-3 4-5V2" />
    <path d="M7 22v-3.5c0-2 2.5-3.3 4-5 1.5 1.7 4 3 4 5V22" />
  </Svg>
);

const Alert: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 2L2 20h20L12 2z" />
    <path d="M12 9v5M12 17v.01" />
  </Svg>
);

const Info: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 8v.01M12 11v5" />
  </Svg>
);

const Copy: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="8" y="8" width="13" height="13" rx="2" />
    <path d="M16 8V5a2 2 0 00-2-2H5a2 2 0 00-2 2v9a2 2 0 002 2h3" />
  </Svg>
);

const Link: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M10 14a5 5 0 007 0l3-3a5 5 0 00-7-7l-1 1" />
    <path d="M14 10a5 5 0 00-7 0l-3 3a5 5 0 007 7l1-1" />
  </Svg>
);

const Moon: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M21 12.8A9 9 0 1111.2 3 7 7 0 0021 12.8z" />
  </Svg>
);

const Sun: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="4" />
    <path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
  </Svg>
);

const Cpu: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="5" y="5" width="14" height="14" rx="2" />
    <rect x="9" y="9" width="6" height="6" />
    <path d="M9 2v3M15 2v3M9 19v3M15 19v3M2 9h3M2 15h3M19 9h3M19 15h3" />
  </Svg>
);

const BookOpen: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M2 4h7a3 3 0 013 3v14a2 2 0 00-2-2H2V4zM22 4h-7a3 3 0 00-3 3v14a2 2 0 012-2h8V4z" />
  </Svg>
);

const Clock: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7v5l3 2" />
  </Svg>
);

const Flag: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M4 21V4h12l-2 4 2 4H4" />
  </Svg>
);

const Gauge: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 12a9 9 0 1118 0" />
    <path d="M12 12l4-3" />
  </Svg>
);

const Integrate: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="3" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" />
    <path d="M17 14v7M14 17h7" />
  </Svg>
);

const ArrowR: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M5 12h14M13 5l7 7-7 7" />
  </Svg>
);

const PanelLeft: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="3" y="4" width="18" height="16" rx="2" />
    <path d="M9 4v16" />
  </Svg>
);

const Menu: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M4 7h16M4 12h16M4 17h16" />
  </Svg>
);

const Layers: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 2l10 6-10 6L2 8l10-6z" />
    <path d="M2 16l10 6 10-6M2 12l10 6 10-6" />
  </Svg>
);

const Mail: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <rect x="3" y="5" width="18" height="14" rx="2" />
    <path d="M3 7l9 6 9-6" />
  </Svg>
);

const Key: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="8" cy="15" r="4" />
    <path d="M11 12l10-10M17 6l3 3M14 9l3 3" />
  </Svg>
);

const Trash: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2M6 6l1 14a2 2 0 002 2h6a2 2 0 002-2l1-14" />
  </Svg>
);

const Edit: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M11 4H5a2 2 0 00-2 2v13a2 2 0 002 2h13a2 2 0 002-2v-6" />
    <path d="M18.5 2.5a2.1 2.1 0 013 3L12 15l-4 1 1-4 9.5-9.5z" />
  </Svg>
);

const Refresh: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M21 12a9 9 0 00-15-7M3 12a9 9 0 0015 7" />
    <path d="M21 3v6h-6M3 21v-6h6" />
  </Svg>
);

const Lightning: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M13 2L4 14h6l-1 8 9-12h-6l1-8z" />
  </Svg>
);

const Dot: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="12" cy="12" r="2" fill="currentColor" />
  </Svg>
);

const Branch: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <circle cx="6" cy="4" r="2" />
    <circle cx="6" cy="20" r="2" />
    <circle cx="18" cy="8" r="2" />
    <path d="M6 6v12M18 10v2a4 4 0 01-4 4H6" />
  </Svg>
);

const Dollar: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M12 1v22M17 5H9a3 3 0 000 6h6a3 3 0 010 6H6" />
  </Svg>
);

const Box: React.FC<IconProps> = (p) => (
  <Svg {...p}>
    <path d="M21 8l-9 5-9-5 9-5 9 5z" />
    <path d="M3 8v8l9 5 9-5V8" />
  </Svg>
);

export const Icon = {
  Shield,
  Logo,
  Home,
  Upload,
  Folder,
  Sparkle,
  Chat,
  History,
  Check,
  X,
  ChevronR,
  ChevronL,
  ChevronD,
  ChevronU,
  Search,
  Bell,
  User,
  Users,
  Settings,
  Github,
  Gitlab,
  Bitbucket,
  File,
  Code,
  Zap,
  Play,
  Pause,
  Hourglass,
  Download,
  Send,
  Plus,
  Minus,
  Expand,
  Collapse,
  Filter,
  Sort,
  Terminal,
  Lock,
  Eye,
  Book,
  Alert,
  Info,
  Copy,
  Link,
  Moon,
  Sun,
  Cpu,
  BookOpen,
  Clock,
  Flag,
  Gauge,
  Integrate,
  ArrowR,
  Layers,
  PanelLeft,
  Menu,
  Mail,
  Key,
  Trash,
  Edit,
  Refresh,
  Lightning,
  Dot,
  Branch,
  Dollar,
  Box,
};

export default Icon;
