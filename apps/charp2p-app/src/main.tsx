import React, { Component, type ErrorInfo, type ReactNode } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";

type AppErrorBoundaryState = { failed: boolean };

class AppErrorBoundary extends Component<{ children: ReactNode }, AppErrorBoundaryState> {
  state: AppErrorBoundaryState = { failed: false };

  static getDerivedStateFromError(): AppErrorBoundaryState {
    return { failed: true };
  }

  componentDidCatch(_error: Error, _errorInfo: ErrorInfo) {
    document.title = "CharP2P could not open · CharP2P";
  }

  render() {
    if (!this.state.failed) return this.props.children;

    return (
      <div className="onboarding-shell">
        <section className="brand-panel" aria-labelledby="fallback-brand-title">
          <div className="brand-lockup">
            <h1 id="fallback-brand-title">Char<span>P2P</span></h1>
          </div>
          <p>Private groups. Direct connections.</p>
        </section>
        <main className="setup-panel" id="main-content">
          <div className="setup-content">
            <section className="setup-form information-card" role="alert">
              <header>
                <h2>CharP2P could not open</h2>
                <p>An unexpected app error occurred. Restart CharP2P to try again.</p>
              </header>
              <button className="primary-button" onClick={() => window.location.reload()} type="button">
                Restart CharP2P
              </button>
            </section>
          </div>
        </main>
      </div>
    );
  }
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <AppErrorBoundary>
      <App />
    </AppErrorBoundary>
  </React.StrictMode>,
);
