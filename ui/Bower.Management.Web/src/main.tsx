import "@fontsource-variable/geist";
import "@fontsource/ibm-plex-mono/400.css";
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { AuthenticationProvider, initializeAuthentication } from "./auth";
import "./styles.css";

// Apply the saved or system theme before the first render, so a dark-mode user never
// sees a light frame first (App keeps it in sync afterwards).
document.documentElement.dataset.theme =
  localStorage.getItem("bower-theme") === "dark" ||
  (!localStorage.getItem("bower-theme") && window.matchMedia("(prefers-color-scheme: dark)").matches)
    ? "dark"
    : "light";

await initializeAuthentication();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <AuthenticationProvider>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </AuthenticationProvider>
  </React.StrictMode>
);
