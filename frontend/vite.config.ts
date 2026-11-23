import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { readFileSync, writeFileSync } from "fs";

// Single source of truth for the product version: the repo-root VERSION file.
// The UI, backend, self-updater and NetProtection engine all read that same
// file, so bumping the release is a one-line edit to VERSION. If VERSION is
// somehow unavailable we fall back to package.json's version.
const pkg = JSON.parse(readFileSync(new URL("./package.json", import.meta.url), "utf-8"));
function readAppVersion(): string {
  try {
    return readFileSync(new URL("../VERSION", import.meta.url), "utf-8").trim() || pkg.version;
  } catch {
    return pkg.version;
  }
}
const appVersion = readAppVersion();
const buildId = (process.env.EASYPI_BUILD_ID || `${appVersion}-${Date.now()}`)
  .trim()
  .replace(/[^0-9A-Za-z._-]/g, "-");

const stampServiceWorker = {
  name: "stamp-service-worker",
  apply: "build" as const,
  closeBundle() {
    const serviceWorker = new URL("./dist/sw.js", import.meta.url);
    const source = readFileSync(serviceWorker, "utf-8");
    if (!source.includes("__EASYPI_BUILD_ID__")) {
      throw new Error("Service worker build ID placeholder is missing");
    }
    writeFileSync(
      serviceWorker,
      source.replaceAll("__EASYPI_BUILD_ID__", buildId),
      "utf-8",
    );
  },
};

export default defineConfig({
  plugins: [react(), stampServiceWorker],
  define: {
    __APP_VERSION__: JSON.stringify(appVersion),
  },
  server: {
    host: "0.0.0.0",
    port: 4173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://127.0.0.1:8000",
        ws: true,
      },
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 4173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://127.0.0.1:8000",
        ws: true,
      },
    },
  },
  build: {
    outDir: "dist",
    minify: 'terser',
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      onwarn(warning, warn) {
        if (
          warning.code === 'EVAL' &&
          typeof warning.id === 'string' &&
          warning.id.includes('pdfjs-dist/build/pdf.js')
        ) {
          return
        }
        warn(warning)
      },
    },
    terserOptions: {
      compress: {
        drop_console: true,
        drop_debugger: true,
      },
    },
  },
});
