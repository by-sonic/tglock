import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  build: {
    outDir: "dist-ui",
  },
  server: {
    strictPort: true,
    watch: {
      ignored: ["**/target/**"],
    },
  },
});
