"use client";

import { useState } from "react";
import AttestDeliveryCode from "./AttestDeliveryCode";
import AttestPurchaseBrowser from "./AttestPurchaseBrowser";

type Tab = "invoice" | "delivery_code";

const TABS: { id: Tab; label: string }[] = [
  { id: "invoice", label: "invoice" },
  { id: "delivery_code", label: "delivery_code" },
];

export default function AttestationTabs() {
  const [active, setActive] = useState<Tab>("invoice");

  return (
    <section className="tabs-shell">
      <div role="tablist" aria-label="Amazon attestation type" className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active === tab.id}
            className={active === tab.id ? "tab tab-active" : "tab"}
            onClick={() => setActive(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div role="tabpanel" className="tab-panel">
        {active === "invoice" ? <AttestPurchaseBrowser /> : null}
        {active === "delivery_code" ? <AttestDeliveryCode /> : null}
      </div>
    </section>
  );
}
