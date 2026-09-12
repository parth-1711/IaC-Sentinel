"use client";

import { signIn } from "next-auth/react";

export default function LoginPage() {
  return (
    <div className="auth-screen">
      <div className="glass-panel auth-card">
        <div className="brand-icon" style={{ width: "52px", height: "52px" }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <h1 className="brand-title" style={{ fontSize: "1.4rem" }}>IaC Sentinel</h1>
        <p className="brand-subtitle" style={{ marginTop: "0.35rem" }}>AI-Augmented Terraform Compliance Engine</p>

        <p style={{ color: "var(--text-secondary)", fontSize: "0.875rem", marginTop: "1.5rem", lineHeight: 1.6 }}>
          Sign in with GitHub to view compliance scan history for the
          repositories you have access to.
        </p>

        <button className="github-signin-btn" onClick={() => signIn("github", { callbackUrl: "/" })}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 .5C5.65.5.5 5.65.5 12c0 5.09 3.29 9.39 7.86 10.91.57.1.79-.25.79-.55 0-.27-.01-1.16-.02-2.11-3.2.7-3.87-1.36-3.87-1.36-.53-1.34-1.29-1.7-1.29-1.7-1.05-.72.08-.7.08-.7 1.17.08 1.78 1.2 1.78 1.2 1.03 1.77 2.71 1.26 3.37.96.1-.75.4-1.26.73-1.55-2.55-.29-5.23-1.28-5.23-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11.05 11.05 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.64 1.59.24 2.76.12 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.38-5.25 5.67.41.36.78 1.07.78 2.15 0 1.55-.01 2.8-.01 3.18 0 .3.21.66.8.55A10.52 10.52 0 0 0 23.5 12c0-6.35-5.15-11.5-11.5-11.5z" />
          </svg>
          Sign in with GitHub
        </button>
      </div>
    </div>
  );
}
