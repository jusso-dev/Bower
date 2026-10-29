import type { SetupStepId } from "../types";

export const stepCopy: Record<SetupStepId, { title: string; why: string }> = {
  "sign-in": {
    title: "Sign in",
    why: "Bower uses your organisation's Entra ID account and app roles, so every change is tied to a person and kept in the audit log."
  },
  entra: {
    title: "Connect Entra apps",
    why: "People and collectors sign in with separate Bower app roles. Without them, collectors cannot enrol and nobody can approve them."
  },
  destination: {
    title: "Choose where events go",
    why: "Bower sends security events to one Log Analytics workspace that Microsoft Sentinel reads. The data collection rule decides which columns arrive."
  },
  collector: {
    title: "Approve the first collector",
    why: "A collector cannot report until a person approves it, so an unknown machine cannot join your fleet."
  },
  probe: {
    title: "Choose what the test proves",
    why: "The test event can prove Bower's general event path, or that a specific pack parser works end to end."
  },
  canary: {
    title: "Send a test event",
    why: "A synthetic test event goes through privacy rules, policy, the queue and delivery exactly like real events. It holds no real data."
  },
  proof: {
    title: "See proof it arrived",
    why: "A collector accepting an event does not prove it reached Sentinel. Only a Sentinel query that finds the exact test event does."
  }
};

