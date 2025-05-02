import js from "@eslint/js";
import globals from "globals";
import { defineConfig } from "eslint/config";

export default defineConfig([
  {
    files: ["**/*.{js,mjs,cjs}"],
    plugins: { js },
    extends: [
      "js/recommended",          // Existing rule set for JS
      "eslint:recommended",      // Standard recommended rules
      "plugin:node/recommended", // Node.js-specific recommended rules
      "prettier"                 // Prettier rules to disable formatting conflicts
    ],
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: { globals: globals.node }, // Ensures Node.js global variables
  },
]);
