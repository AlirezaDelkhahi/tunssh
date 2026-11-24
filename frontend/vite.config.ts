import fs from "node:fs";
import path from "node:path";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

function cleanDistPreserveGitkeep(): Plugin {
  return {
    name: "clean-dist-preserve-gitkeep",
    buildStart() {
      const distDir = path.resolve(__dirname, "dist");
      if (!fs.existsSync(distDir)) {
        fs.mkdirSync(distDir, { recursive: true });
      }
      for (const entry of fs.readdirSync(distDir)) {
        if (entry === ".gitkeep") {
          continue;
        }
        fs.rmSync(path.join(distDir, entry), { recursive: true, force: true });
      }
      const gitkeepPath = path.join(distDir, ".gitkeep");
      if (!fs.existsSync(gitkeepPath)) {
        fs.writeFileSync(gitkeepPath, "");
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), cleanDistPreserveGitkeep()],
  build: {
    outDir: "dist",
    emptyOutDir: false,
  },
});
