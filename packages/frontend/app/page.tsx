import AttestationTabs from "@/components/AttestationTabs";
import styles from "./page.module.css";

export default function Home() {
  return (
    <main className={styles.page}>
      <header>
        <h1>Amazon zkTLS attestation</h1>
      </header>

      <section className={styles.prereqs}>
        <ol>
          <li>Open the Amazon page you want to notarize.</li>
          <li>Fill the matching tab with the page parameters.</li>
          <li>Run the Primus extension flow.</li>
        </ol>
      </section>

      <AttestationTabs />
    </main>
  );
}
