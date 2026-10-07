import { defineConfig } from "vite";

// Safari 14 is what WKWebView on a supported macOS is guaranteed to have.
export default defineConfig({
  base: "./",
  build: {
    target: "safari14",
    outDir: "dist",
    emptyOutDir: true,
    // The CSP has no 'unsafe-inline': keep every script and style a separate file.
    modulePreload: false,
    assetsInlineLimit: 0,
  },
  server: { port: 5173, strictPort: true },
});
