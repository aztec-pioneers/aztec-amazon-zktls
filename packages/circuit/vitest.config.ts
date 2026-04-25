import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // We do not exercise the DOMParser-based extractor in tests anymore (the
    // sidecar in the fixture supplies plaintexts), so a plain node env is
    // enough — and bb.js's WASM SRS init under jsdom traps unreachable.
    environment: "node",
    include: ["test/**/*.test.ts"],
    // Proving can take a while even on small circuits; the hashing pass over
    // 4 fields × ~4KB each on a debug build is the slow part.
    testTimeout: 5 * 60 * 1000,
    hookTimeout: 5 * 60 * 1000,
  },
});
