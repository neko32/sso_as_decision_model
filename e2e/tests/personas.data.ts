// Persona scenarios shared by the API tests (personas.spec.ts) and the recorded demo (demo.spec.ts).

export type Outcome = "allow" | "step_up" | "deny";

export interface Persona {
  name: string;
  roles: string[];
  resource: string;
  action?: string;
  time: string;
  context: Record<string, unknown>;
  /** First entry is expected in mock mode; any entry is accepted against the real Jev. */
  expected: Outcome[];
  /** Deterministic denials must not consult the decision model. */
  ruleOnly?: boolean;
}

const tokyoHistory = {
  recent_logins: [
    { time: "2026-10-28T09:05:00+09:00", country: "JP", city: "Tokyo" },
    { time: "2026-10-29T09:12:00+09:00", country: "JP", city: "Tokyo" },
  ],
};
const managedLaptop = { managed: true, mdm: "Intune", disk_encrypted: true, os: "macOS 15.4", last_patch_days: 3 };

export const personas: Persona[] = [
  {
    name: "engineer at the Tokyo office on a managed laptop -> allow",
    roles: ["engineer"],
    resource: "wiki",
    time: "2026-10-30T10:00:00+09:00",
    context: { device: managedLaptop, location: { country: "JP", city: "Tokyo", network: "corporate" }, history: tokyoHistory },
    expected: ["allow"],
  },
  {
    name: "HR opening payroll from a personal phone -> step-up MFA",
    roles: ["hr"],
    resource: "payroll",
    time: "2026-10-30T13:00:00+09:00",
    context: {
      device: { managed: false, os: "iOS 19.1", last_patch_days: 10 },
      location: { country: "JP", city: "Tokyo", network: "home_isp" },
      history: tokyoHistory,
    },
    expected: ["step_up"],
  },
  {
    name: "admin at 03:00 from Sao Paulo, last seen in Tokyo -> step-up (or deny)",
    roles: ["admin"],
    resource: "admin-console",
    time: "2026-10-30T03:00:00+09:00",
    context: { device: managedLaptop, location: { country: "BR", city: "Sao Paulo", network: "hotel_wifi" }, history: tokyoHistory },
    expected: ["step_up", "deny"],
  },
  {
    name: "rooted phone with many failed attempts -> deny",
    roles: ["engineer"],
    resource: "source-code",
    time: "2026-10-30T11:00:00+09:00",
    context: {
      device: { managed: false, compromised: true, jailbroken: true, os: "Android 9", last_patch_days: 900 },
      location: { country: "JP", city: "Tokyo" },
      history: tokyoHistory,
      signals: { failed_attempts_24h: 14 },
    },
    expected: ["deny"],
  },
  {
    name: "sales trying to read payroll -> deny by role (no model call)",
    roles: ["sales"],
    resource: "payroll",
    time: "2026-10-30T10:00:00+09:00",
    context: { device: managedLaptop, location: { country: "JP" }, history: tokyoHistory },
    expected: ["deny"],
    ruleOnly: true,
  },
  {
    name: "HR opening payroll at 23:30 -> deny by business hours (no model call)",
    roles: ["hr"],
    resource: "payroll",
    time: "2026-10-30T23:30:00+09:00",
    context: { device: managedLaptop, location: { country: "JP" }, history: tokyoHistory },
    expected: ["deny"],
    ruleOnly: true,
  },
];

export const live = process.env.E2E_SIGNAL_MODE === "jev";

/** AuthZEN evaluation request body for a persona. */
export function evaluationBody(p: Persona) {
  return {
    subject: { type: "user", id: "persona@example.com", properties: { roles: p.roles } },
    resource: { type: "app", id: p.resource },
    action: { name: p.action ?? "read" },
    context: { ...p.context, time: p.time },
  };
}
