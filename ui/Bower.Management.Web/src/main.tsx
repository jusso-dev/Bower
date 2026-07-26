import "@fontsource-variable/geist";
import "@fontsource/ibm-plex-mono/400.css";
import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { App } from "./App";
import { AuthenticationProvider, initializeAuthentication } from "./auth";
import "./styles.css";

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
