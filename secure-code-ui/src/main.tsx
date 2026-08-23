// secure-code-ui/src/main.tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./app/App";
import "./app/styles/index.css";
// SCCAP design foundations — tokens (CSS custom properties) and
// primitive utility classes (.sccap-btn, .chip, .surface, …).
import "./app/styles/tokens.css";
import "./app/styles/primitives.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
