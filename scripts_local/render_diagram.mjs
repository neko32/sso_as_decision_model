// Renders docs/architecture.svg to docs/architecture.png using Playwright's Chromium.
// Run from the e2e directory: node ../scripts_local/render_diagram.mjs
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(resolve(here, "../e2e/package.json"));
const { chromium } = require("@playwright/test");

const svg = readFileSync(resolve(here, "../docs/architecture.svg"), "utf8");
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1600, height: 900 }, deviceScaleFactor: 2 });
await page.setContent(`<html><body style="margin:0">${svg}</body></html>`);
await page.locator("svg").screenshot({ path: resolve(here, "../docs/architecture.png") });
await browser.close();
console.log("wrote docs/architecture.png");
