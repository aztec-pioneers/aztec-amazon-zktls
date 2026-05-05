import type { NextConfig } from "next";
import path from "node:path";

const nextConfig: NextConfig = {
  // Pin Turbopack's project root to this package directory. In a pnpm
  // monorepo Turbopack walks up `app/` looking for `next/package.json`,
  // gets confused, and aborts with ENOENT on the (legitimate) `app/`
  // directory. `process.cwd()` is the package dir when `next dev` is
  // invoked via `pnpm --filter @amazon-zktls/frontend dev`.
  // Pin Turbopack's root to the pnpm workspace root, two dirs up from
  // `packages/frontend`. `next` lives at `<root>/node_modules/.pnpm/...`
  // and the Turbopack/Rust resolver can't follow pnpm's symlink from
  // `packages/frontend/node_modules/next` back to that real location.
  // Without this we get a misleading "next/package.json not found from
  // /packages/frontend/app" error at boot.
  turbopack: {
    // Resolve to an absolute path explicitly; relative segments leak
    // through into Turbopack's error messages without being normalized.
    root: path.resolve(process.cwd(), "..", ".."),
  },

  // bb.js exports a hand-built `dest/browser/` bundle via the `browser`
  // condition in its package.json; that bundle picks `helpers/browser`
  // (typeof-window-guarded) where the source tree picks `helpers/node`
  // unconditionally. Don't `transpilePackages` it — that compiles from
  // `src/` and drags in the Node-only helpers, which trip a runtime
  // `ReferenceError: window is not defined` from inside the Web Worker
  // during `Barretenberg.new()`.

  // Multi-threaded WASM via SharedArrayBuffer requires the page to be
  // cross-origin-isolated. Without these headers, bb.js falls back to the
  // single-threaded WASM path and proving is roughly N× slower (where N =
  // hardwareConcurrency). `same-origin` COOP + `require-corp` COEP is the
  // standard recipe; downstream pages must serve any cross-origin sub-
  // resources with `Cross-Origin-Resource-Policy: cross-origin` or use
  // `crossorigin="anonymous"` with a CORS-permissive response.
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Cross-Origin-Embedder-Policy", value: "require-corp" },
          { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
        ],
      },
    ];
  },
};

export default nextConfig;
