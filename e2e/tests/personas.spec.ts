import { expect, test } from "@playwright/test";
import { evaluationBody, live, personas } from "./personas.data";

for (const p of personas) {
  test(p.name, async ({ request }) => {
    const res = await request.post("/access/v1/evaluation", { data: evaluationBody(p) });
    expect(res.status()).toBe(200);
    const body = await res.json();
    test.info().annotations.push({ type: "reason", description: body.context.reason_admin });

    if (live) expect(p.expected).toContain(body.context.outcome);
    else expect(body.context.outcome).toBe(p.expected[0]);
    expect(body.decision).toBe(body.context.outcome === "allow");

    const sources: string[] = body.context.trace.map((e: { source: string }) => e.source);
    if (p.ruleOnly) {
      expect(sources).not.toContain("model");
      expect(body.context.model).toBeUndefined();
    } else {
      expect(sources).toContain("model");
      expect(body.context.model).toBeTruthy();
    }
  });
}

test("rejects invalid input with 400", async ({ request }) => {
  const res = await request.post("/access/v1/evaluation", {
    data: { subject: { type: "user", id: "x", properties: { roles: ["Bad Role"] } }, resource: { type: "app", id: "wiki" }, action: { name: "read" } },
  });
  expect(res.status()).toBe(400);
  expect((await res.json()).error).toContain("roles");
});

test("publishes AuthZEN discovery metadata", async ({ request, baseURL }) => {
  const res = await request.get("/.well-known/authzen-configuration");
  expect(res.ok()).toBeTruthy();
  expect((await res.json()).access_evaluation_endpoint).toBe(`${baseURL}/access/v1/evaluation`);
});
