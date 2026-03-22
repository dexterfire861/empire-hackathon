/// <reference types="vite/client" />

import React from "react";
import ReactDOM from "react-dom/client";

import { ResultsApp } from "./ResultsApp";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ResultsApp />
  </React.StrictMode>,
);
