// secure-code-ui/src/shared/ui/BackToTop.tsx
//
// One button, on every page, for the one thing every long page needs.
//
// The pentest run page and the findings lists are tall by nature. Scrolling up to reach the
// navigation is a tax paid dozens of times per session, so the control appears once the page has
// moved — not immediately, where it would sit on top of the content for no reason — and respects
// reduced-motion preferences.

import { useEffect, useState } from "react";
import { Icon } from "./Icon";

const SHOW_AFTER = 400;

export function BackToTop() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const onScroll = () => setVisible(window.scrollY > SHOW_AFTER);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  const toTop = () => {
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches;
    window.scrollTo({ top: 0, behavior: reduced ? "auto" : "smooth" });
    // Keyboard users land back at the top of the document, not mid-page.
    document.getElementById("main-content")?.focus({ preventScroll: true });
  };

  if (!visible) return null;

  return (
    <button type="button" className="back-to-top" onClick={toTop} title="Back to top">
      <Icon.ChevronD size={18} />
      <span className="back-to-top-label">Top</span>
    </button>
  );
}

export default BackToTop;
