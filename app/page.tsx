import AttestPurchaseBrowser from "@/components/AttestPurchaseBrowser";
import styles from "./page.module.css";

export default function Home() {
  return (
    <main className={styles.page}>
      <header>
        <h1>Amazon purchase → zkTLS attestation</h1>
        <p>
          Generate a Primus zkTLS attestation of an Amazon order using the
          Primus Chrome extension and a Dev Hub template — no cookies pasted,
          the extension uses your live browser session.
        </p>
      </header>

      <section className={styles.prereqs}>
        <h2>Before you click</h2>
        <ol>
          <li>
            Install the{" "}
            <a
              href="https://chromewebstore.google.com/detail/primus/oeiomhmbaapihbilkfkhmlajkeegnjhe"
              target="_blank"
              rel="noreferrer"
            >
              Primus Chrome extension
            </a>
            .
          </li>
          <li>Log into amazon.com in this browser profile.</li>
          <li>
            Set <code>NEXT_PUBLIC_PRIMUS_APP_ID</code>,{" "}
            <code>NEXT_PUBLIC_PRIMUS_TEMPLATE_ID</code>, and{" "}
            <code>PRIMUS_APP_SECRET</code> in <code>.env.local</code>.
          </li>
        </ol>
      </section>

      <AttestPurchaseBrowser />
    </main>
  );
}
