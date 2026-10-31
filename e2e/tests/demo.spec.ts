// Recorded walkthrough of the persona scenarios. Runs only in the `demo` project (E2E_DEMO=1):
// each scenario is evaluated against the PDP, asserted, and its decision trace rendered in the
// browser so the video shows what the API decided and why.
import { resolve } from "node:path";
import { expect, test } from "@playwright/test";
import { evaluationBody, live, type Persona, personas } from "./personas.data";

interface TraceEntry {
  factor: string;
  source: "rule" | "model" | "system";
  effect: "allow" | "step_up" | "deny";
  detail: string;
}

interface Evaluated {
  persona: Persona;
  outcome: TraceEntry["effect"];
  model?: string;
  trace: TraceEntry[];
  ms: number;
}

const VIDEO_PATH = resolve(__dirname, "../../docs/demo/playwright-demo.webm");
const HOLD_MS = 2_600;

const esc = (s: string) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);
const label = { allow: "ALLOW", step_up: "STEP-UP MFA", deny: "DENY" } as const;

function contextLines(p: Persona): string[] {
  const c = p.context as Record<string, any>;
  const d = c.device ?? {};
  const device = d.compromised
    ? `${d.os} · rooted / compromised`
    : `${d.os ?? "device"} · ${d.managed ? `managed (${d.mdm})` : "personal (BYOD)"}`;
  const loc = c.location ?? {};
  const last = c.history?.recent_logins?.at(-1);
  const lines = [
    `🕒 ${p.time.slice(11, 16)} local`,
    `💻 ${device}`,
    `📍 ${[loc.city, loc.country].filter(Boolean).join(", ")}${loc.network ? ` · ${loc.network}` : ""}`,
  ];
  if (last) lines.push(`↩︎ last login: ${last.city}, ${last.country}`);
  if (c.signals?.failed_attempts_24h) lines.push(`⚠️ ${c.signals.failed_attempts_24h} failed attempts / 24h`);
  return lines;
}

const STYLE = `
  * { box-sizing: border-box; }
  body { margin: 0; width: 1280px; height: 720px; overflow: hidden; background: #0f172a; color: #e2e8f0;
         font: 16px/1.45 "Segoe UI", Inter, system-ui, sans-serif; }
  header { display: flex; justify-content: space-between; align-items: center; padding: 22px 40px 0; color: #94a3b8; font-size: 15px; }
  header b { color: #e2e8f0; }
  .pill { padding: 3px 12px; border-radius: 999px; background: #1e293b; border: 1px solid #334155; }
  .grid { display: grid; grid-template-columns: 430px 1fr; gap: 28px; padding: 22px 40px; }
  .card { background: #111c33; border: 1px solid #1f2b46; border-radius: 16px; padding: 22px 24px; }
  h1 { margin: 0 0 6px; font-size: 26px; line-height: 1.25; color: #f8fafc; }
  .meta { color: #a5b4fc; font-family: Consolas, monospace; font-size: 15px; margin-bottom: 14px; }
  .ctx div { padding: 5px 0; border-bottom: 1px dashed #1f2b46; }
  .req { margin-top: 16px; font-family: Consolas, monospace; font-size: 14px; color: #94a3b8; }
  .outcome { font-size: 40px; font-weight: 800; letter-spacing: .5px; padding: 10px 22px; border-radius: 14px; display: inline-block;
             animation: pop .45s ease-out both; }
  .allow { color: #4ade80; background: #052e1a; border: 2px solid #16a34a; }
  .step_up { color: #fbbf24; background: #2d1d03; border: 2px solid #d97706; }
  .deny { color: #f87171; background: #2c0b0b; border: 2px solid #dc2626; }
  .why { color: #94a3b8; margin: 10px 0 14px; font-size: 14px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  td { padding: 6px 8px; border-bottom: 1px solid #1f2b46; vertical-align: top; }
  tr { opacity: 0; animation: in .35s ease-out forwards; }
  .src { font-size: 12px; font-weight: 700; padding: 2px 8px; border-radius: 6px; }
  .rule { background: #312e81; color: #c7d2fe; } .model { background: #78350f; color: #fde68a; } .system { background: #7f1d1d; color: #fecaca; }
  .eff { font-weight: 700; } .eff.allow, .eff.step_up, .eff.deny { background: none; border: 0; }
  .ok { margin-top: 12px; color: #4ade80; font-weight: 600; opacity: 0; animation: in .3s ease-out forwards; }
  .center { height: 600px; display: flex; flex-direction: column; justify-content: center; padding: 0 80px; }
  .big { font-size: 52px; font-weight: 800; color: #f8fafc; margin: 0; }
  .sub { font-size: 22px; color: #94a3b8; margin: 10px 0 28px; }
  .chips span { display: inline-block; margin: 4px 8px 4px 0; padding: 6px 14px; border-radius: 999px; font-weight: 600; }
  @keyframes in { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
  @keyframes pop { from { opacity: 0; transform: scale(.85); } to { opacity: 1; transform: none; } }
`;

const page = (header: string, body: string) =>
  `<html><head><meta charset="utf-8"><style>${STYLE}</style></head><body><header>${header}</header>${body}</body></html>`;

const headerFor = (i: number) =>
  `<span><b>SSO as a Decision Model</b> · Playwright E2E · POST /access/v1/evaluation</span>` +
  `<span class="pill">signals: ${live ? "Jev jev-1.14.0 (live)" : "offline mock"}</span>` +
  `<span class="pill">${i} / ${personas.length}</span>`;

function scene(i: number, e: Evaluated): string {
  const title = e.persona.name.split(" -> ")[0];
  const rows = e.trace
    .map(
      (t, n) => `<tr style="animation-delay:${0.5 + n * 0.28}s">
        <td>${t.factor}</td><td><span class="src ${t.source}">${t.source}</span></td>
        <td class="eff ${t.effect}">${t.effect}</td><td>${esc(t.detail)}</td></tr>`,
    )
    .join("");
  const why = e.model ? `signals from ${e.model}` : "decided by Rust rules only — model never called";
  return page(
    headerFor(i),
    `<div class="grid">
      <div class="card">
        <h1>${esc(title)}</h1>
        <div class="meta">roles: [${e.persona.roles.join(", ")}] → ${e.persona.action ?? "read"} ${e.persona.resource}</div>
        <div class="ctx">${contextLines(e.persona).map((l) => `<div>${esc(l)}</div>`).join("")}</div>
        <div class="req">HTTP 200 · ${e.ms} ms</div>
      </div>
      <div class="card">
        <div class="outcome ${e.outcome}">${label[e.outcome]}</div>
        <div class="why">${why}</div>
        <table>${rows}</table>
        <div class="ok" style="animation-delay:${0.6 + e.trace.length * 0.28}s">✓ assertions passed</div>
      </div>
    </div>`,
  );
}

test("recorded persona walkthrough", async ({ page: browser, request }) => {
  test.setTimeout(120_000);

  await browser.setContent(
    page(
      headerFor(0),
      `<div class="center">
        <p class="big">Every SSO login is a decision.</p>
        <p class="sub">Identity · Policy · Role · Time → Rust rules &nbsp;|&nbsp; Device · Location · Risk → Jev decision model</p>
        <div class="chips"><span class="allow">ALLOW</span><span class="step_up">STEP-UP MFA</span><span class="deny">DENY</span></div>
        <p class="sub" style="margin-top:28px">${personas.length} persona scenarios, each with a decision trace</p>
      </div>`,
    ),
  );
  await browser.waitForTimeout(3_000);

  const results: Evaluated[] = [];
  for (const [i, p] of personas.entries()) {
    const started = Date.now();
    const res = await request.post("/access/v1/evaluation", { data: evaluationBody(p) });
    const ms = Date.now() - started;
    expect(res.status()).toBe(200);
    const body = await res.json();
    const e: Evaluated = { persona: p, outcome: body.context.outcome, model: body.context.model, trace: body.context.trace, ms };
    if (live) expect(p.expected).toContain(e.outcome);
    else expect(e.outcome).toBe(p.expected[0]);
    expect(Boolean(e.model)).toBe(!p.ruleOnly);
    results.push(e);

    await browser.setContent(scene(i + 1, e));
    await expect(browser.locator("tr")).toHaveCount(e.trace.length);
    // Let the staggered row animation finish, then hold the full trace on screen.
    await browser.waitForTimeout(900 + e.trace.length * 280 + HOLD_MS);
  }

  const summary = results
    .map(
      (r) => `<tr style="animation-delay:${0.2 + results.indexOf(r) * 0.2}s"><td>${esc(r.persona.name.split(" -> ")[0])}</td>
        <td class="eff ${r.outcome}">${label[r.outcome]}</td><td>${r.model ? "rules + Jev" : "rules only"}</td><td>${r.ms} ms</td></tr>`,
    )
    .join("");
  await browser.setContent(
    page(
      headerFor(personas.length),
      `<div class="center" style="padding:0 60px">
        <p class="big" style="font-size:40px">${results.length} / ${results.length} scenarios passed</p>
        <p class="sub">fail-closed · pinned model · user id never sent to the model · AuthZEN compatible</p>
        <div class="card"><table style="font-size:17px">${summary}</table></div>
      </div>`,
    ),
  );
  await browser.waitForTimeout(5_000);

  const video = browser.video();
  await browser.close();
  if (video) await video.saveAs(VIDEO_PATH);
});
