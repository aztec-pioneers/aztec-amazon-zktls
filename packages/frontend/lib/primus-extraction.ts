"use client";

export type JsonResponseRow = {
  id?: string;
  content?: string;
};

export type ResolvedPlaintext = {
  plaintext: string;
  localHash: string;
  source: string;
  verified: boolean | null;
};

type PlaintextCandidate = {
  plaintext: string;
  sourceKind: string;
};

export async function sha256Hex(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function isSha256Hex(value: string): boolean {
  return /^[0-9a-f]{64}$/i.test(value);
}

function rawElementSlice(
  body: string,
  start: number,
  tagName: string,
): string | null {
  const openTagEnd = body.indexOf(">", start);
  if (openTagEnd === -1) return null;
  const tag = tagName.toLowerCase();
  const openRe = new RegExp(`<${tag}(?=[\\s>/])`, "gi");
  const closeRe = new RegExp(`</${tag}\\s*>`, "gi");
  let depth = 1;
  let pos = openTagEnd + 1;
  while (depth > 0) {
    openRe.lastIndex = pos;
    closeRe.lastIndex = pos;
    const om = openRe.exec(body);
    const cm = closeRe.exec(body);
    if (!cm) return null;
    if (om && om.index < cm.index) {
      depth++;
      pos = om.index + om[0].length;
    } else {
      depth--;
      pos = cm.index + cm[0].length;
      if (depth === 0) return body.substring(start, pos);
    }
  }
  return null;
}

function firstXPathNode(doc: Document, xpath: string): Node | null {
  return doc.evaluate(
    xpath,
    doc,
    null,
    XPathResult.FIRST_ORDERED_NODE_TYPE,
    null,
  ).singleNodeValue as Node | null;
}

export function normalizedTextContent(html: string): string {
  return (
    new DOMParser()
      .parseFromString(`<x>${html}</x>`, "text/html")
      .documentElement.textContent?.trim() ?? ""
  );
}

export function extractOrderId(plaintext: string): string {
  let href = plaintext;
  if (plaintext.trimStart().startsWith("<")) {
    const parsed = new DOMParser().parseFromString(plaintext, "text/html");
    href = parsed.querySelector("a")?.getAttribute("href") ?? plaintext;
  }
  try {
    const url = new URL(href, "https://www.amazon.com");
    return (
      url.searchParams.get("orderID") ??
      url.searchParams.get("orderId") ??
      href.match(/\borderI[Dd]=([^&]+)/)?.[1] ??
      ""
    );
  } catch {
    return href.match(/\borderI[Dd]=([^&]+)/)?.[1] ?? "";
  }
}

export function extractByXPath(html: string, xpath: string): string | null {
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const node = firstXPathNode(doc, xpath);
    if (!node) return null;
    if (node.nodeType === Node.ATTRIBUTE_NODE) return (node as Attr).value;
    if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? "";
    if (!(node instanceof Element)) return node.textContent ?? "";

    const serialized = node.outerHTML;
    const openTagEnd = serialized.indexOf(">");
    const openTag =
      openTagEnd === -1 ? serialized : serialized.substring(0, openTagEnd + 1);
    const targetText = (node.textContent ?? "").trim();

    let from = 0;
    let firstSlice: string | null = null;
    while (true) {
      const idx = html.indexOf(openTag, from);
      if (idx === -1) break;
      const slice = rawElementSlice(html, idx, node.tagName);
      if (slice) {
        if (!firstSlice) firstSlice = slice;
        if (normalizedTextContent(slice) === targetText) return slice;
      }
      from = idx + openTag.length;
    }

    return firstSlice ?? serialized;
  } catch {
    return null;
  }
}

function rawAttributeCandidate(
  html: string,
  xpath: string,
): PlaintextCandidate | null {
  const match = xpath.match(/^(.*)\/@([A-Za-z_:][\w:.-]*)$/);
  if (!match) return null;
  const [, elementXPath, attrName] = match;
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const node = firstXPathNode(doc, elementXPath);
    if (!(node instanceof Element)) return null;

    const rawElement = extractByXPath(html, elementXPath) ?? node.outerHTML;
    const openTagEnd = rawElement.indexOf(">");
    const rawOpenTag =
      openTagEnd === -1 ? rawElement : rawElement.substring(0, openTagEnd + 1);
    const escapedAttr = attrName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const attrMatch = rawOpenTag.match(
      new RegExp(`\\s${escapedAttr}=(["'])(.*?)\\1`, "i"),
    );
    return attrMatch
      ? { plaintext: attrMatch[2], sourceKind: "raw-attr" }
      : null;
  } catch {
    return null;
  }
}

export function xpathPlaintextCandidates(
  html: string,
  xpath: string,
): PlaintextCandidate[] {
  try {
    const doc = new DOMParser().parseFromString(html, "text/html");
    const node = firstXPathNode(doc, xpath);
    if (!node) return [];
    if (node.nodeType === Node.ATTRIBUTE_NODE) {
      const rawAttr = rawAttributeCandidate(html, xpath);
      return [
        ...(rawAttr ? [rawAttr] : []),
        { plaintext: (node as Attr).value, sourceKind: "attr" },
      ];
    }
    if (node.nodeType === Node.TEXT_NODE) {
      const text = node.textContent?.trim() ?? "";
      return text ? [{ plaintext: text, sourceKind: "text" }] : [];
    }
    if (!(node instanceof Element)) {
      const text = node.textContent?.trim() ?? "";
      return text ? [{ plaintext: text, sourceKind: "text" }] : [];
    }

    const candidates: PlaintextCandidate[] = [];
    const seen = new Set<string>();
    const add = (plaintext: string | null | undefined, sourceKind: string) => {
      const value = plaintext ?? "";
      if (!value || seen.has(value)) return;
      seen.add(value);
      candidates.push({ plaintext: value, sourceKind });
    };

    for (const child of Array.from(node.childNodes)) {
      if (child.nodeType === Node.TEXT_NODE) {
        add(child.textContent?.trim(), "direct-text");
      }
    }
    add(node.textContent?.trim(), "text-content");
    add(extractByXPath(html, xpath), "outer-html");
    add(node.outerHTML, "serialized-html");
    return candidates;
  } catch {
    return [];
  }
}

export async function resolveSignedPlaintext({
  allJson,
  key,
  xpath,
  signedHash,
}: {
  allJson: JsonResponseRow[] | null;
  key: string;
  xpath: string;
  signedHash: string;
}): Promise<ResolvedPlaintext> {
  const responses = Array.isArray(allJson)
    ? allJson
        .map((entry, index) => ({
          id: entry.id ?? "",
          content: entry.content ?? "",
          index,
        }))
        .filter((entry) => entry.content)
    : [];
  const canCheck = isSha256Hex(signedHash);
  const ordered = [
    ...responses.filter((entry) => entry.id === key),
    ...responses.filter((entry) => entry.id !== key),
  ];

  const check = async (plaintext: string) => {
    const localHash = await sha256Hex(plaintext);
    return {
      localHash,
      verified: canCheck
        ? localHash.toLowerCase() === signedHash.toLowerCase()
        : null,
    };
  };

  for (const entry of ordered) {
    const { localHash, verified } = await check(entry.content);
    if (verified) {
      return {
        plaintext: entry.content,
        localHash,
        source: `allJson[${entry.index}]${entry.id ? `:${entry.id}` : ""}`,
        verified,
      };
    }
  }

  let firstExtracted: ResolvedPlaintext | null = null;
  for (const entry of ordered) {
    for (const candidate of xpathPlaintextCandidates(entry.content, xpath)) {
      const { localHash, verified } = await check(candidate.plaintext);
      const source = `xpath-${candidate.sourceKind}(allJson[${entry.index}]${
        entry.id ? `:${entry.id}` : ""
      })`;
      const row = { plaintext: candidate.plaintext, localHash, verified, source };
      if (!firstExtracted) firstExtracted = row;
      if (verified) return row;
    }
  }

  return (
    firstExtracted ?? {
      plaintext: "(missing)",
      localHash: "",
      source: "missing",
      verified: null,
    }
  );
}
