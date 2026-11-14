import Link from "next/link";
import type { ReactNode } from "react";

/**
 * Shell for the free standalone tools at /tools/*.
 *
 * Each tool is search-indexable, works with zero login, and carries the
 * "part of AiSOC" backlink the growth loop depends on. Deliberately light —
 * no app chrome, no auth.
 */
export default function ToolsLayout({ children }: { children: ReactNode }) {
  return (
    <div style={{ background: "#0b1020", minHeight: "100vh", color: "#e6e9f5" }}>
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "16px 24px",
          borderBottom: "1px solid #232b4d",
        }}
      >
        <Link href="/tools" style={{ color: "#e6e9f5", textDecoration: "none", fontWeight: 800, letterSpacing: 0.5 }}>
          AiSOC <span style={{ color: "#8b93b7", fontWeight: 500 }}>· free tools</span>
        </Link>
        <nav style={{ display: "flex", gap: 18, fontSize: 14 }}>
          <Link href="/tools/translate" style={{ color: "#c4cae0", textDecoration: "none" }}>
            Translate
          </Link>
          <Link href="/tools/nl2sigma" style={{ color: "#c4cae0", textDecoration: "none" }}>
            NL→Sigma
          </Link>
          <Link href="/tools/coverage" style={{ color: "#c4cae0", textDecoration: "none" }}>
            Coverage
          </Link>
          <Link href="/tools/noise" style={{ color: "#c4cae0", textDecoration: "none" }}>
            Noise
          </Link>
          <a href="https://github.com/beenuar/AiSOC" style={{ color: "#7b2bbe", textDecoration: "none", fontWeight: 700 }}>
            GitHub ★
          </a>
        </nav>
      </header>
      <div style={{ maxWidth: 980, margin: "0 auto", padding: "40px 24px 64px" }}>{children}</div>
      <footer style={{ borderTop: "1px solid #232b4d", padding: "24px", textAlign: "center", color: "#6b7394", fontSize: 13 }}>
        Free & open source · part of{" "}
        <a href="https://github.com/beenuar/AiSOC" style={{ color: "#8b93b7" }}>
          AiSOC
        </a>
        , the self-hostable AI SOC. Everything on this page runs in your browser — your rules never touch our servers.
      </footer>
    </div>
  );
}
