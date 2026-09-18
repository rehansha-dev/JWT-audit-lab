// Minimal stroke-icon set. All use currentColor so callers set color via style.
const base = (size) => ({
  width: size,
  height: size,
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeLinecap: "round",
  strokeLinejoin: "round",
});

export const Shield = ({ size = 16, w = 1.5 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M12 2 4 5v6c0 5 3.5 8.5 8 11 4.5-2.5 8-6 8-11V5l-8-3Z" /></svg>
);
export const Globe = ({ size = 12, w = 1.5 }) => (
  <svg {...base(size)} strokeWidth={w}><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.5 2.5 15 0 18M12 3c-2.5 2.5-2.5 15 0 18" /></svg>
);
export const User = ({ size = 12, w = 1.5 }) => (
  <svg {...base(size)} strokeWidth={w}><circle cx="12" cy="8" r="3.5" /><path d="M5 20c0-3.5 3-6 7-6s7 2.5 7 6" /></svg>
);
export const Lock = ({ size = 12, w = 1.5 }) => (
  <svg {...base(size)} strokeWidth={w}><rect x="5" y="11" width="14" height="9" rx="2" /><path d="M8 11V8a4 4 0 0 1 8 0v3" /></svg>
);
export const Key = ({ size = 12, w = 1.5 }) => (
  <svg {...base(size)} strokeWidth={w}><circle cx="8" cy="8" r="4" /><path d="M11 11l8 8M16 16l2-2M19 19l2-2" /></svg>
);
export const Info = ({ size = 12, w = 1.5 }) => (
  <svg {...base(size)} strokeWidth={w}><circle cx="12" cy="12" r="9" /><path d="M12 11v5M12 8h.01" /></svg>
);
export const Download = ({ size = 14, w = 1.6 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M12 3v12M7 11l5 5 5-5M5 21h14" /></svg>
);
export const Chevron = ({ size = 14, w = 2 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M6 9l6 6 6-6" /></svg>
);
export const Caret = ({ size = 9, w = 2.5 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M9 6l6 6-6 6" /></svg>
);
export const Check = ({ size = 14, w = 2 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M4 12l5 5L20 6" /></svg>
);
export const ArrowLeft = ({ size = 14, w = 1.8 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M19 12H5M11 18l-6-6 6-6" /></svg>
);
export const ArrowRight = ({ size = 14, w = 1.8 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M5 12h14M13 6l6 6-6 6" /></svg>
);
export const Bolt = ({ size = 18, w = 1.6 }) => (
  <svg {...base(size)} strokeWidth={w}><path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z" /></svg>
);
export const LockBig = ({ size = 64, w = 1 }) => (
  <svg {...base(size)} strokeWidth={w}><rect x="4" y="11" width="16" height="10" rx="2.5" /><path d="M8 11V7.5a4 4 0 0 1 8 0V11" /><circle cx="12" cy="16" r="1.4" /></svg>
);
