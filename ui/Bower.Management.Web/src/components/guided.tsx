import {
  TriangleAlert,
  CheckCircle2,
  CircleDashed,
  Clock3,
  LockKeyhole,
  XCircle
} from "lucide-react";
import { type ReactNode, useEffect, useRef } from "react";
import type { GuidedCheck, GuidedState, HomeState } from "../types";

/*
 * Guided-flow primitives shared by the setup wizard and later plain-language views.
 * Every state is shown as words plus an icon shape, never colour alone. See DESIGN.md,
 * "Guided flows".
 */

const stateLabels: Record<GuidedState, string> = {
  complete: "Done",
  attention: "Needs attention",
  blocked: "Waiting on earlier steps",
  "in-progress": "In progress",
  "not-started": "Not started"
};

const stateIcons: Record<GuidedState, typeof CheckCircle2> = {
  complete: CheckCircle2,
  attention: TriangleAlert,
  blocked: LockKeyhole,
  "in-progress": Clock3,
  "not-started": CircleDashed
};

/** A plain-language status: "Done", "Needs attention"… `label` overrides the words, not the tone. */
export function PlainStatus({ state, label }: { state: GuidedState; label?: string }) {
  const Icon = stateIcons[state];
  return (
    <span className={`plain-status plain-status--${state}`}>
      <Icon aria-hidden="true" />
      {label ?? stateLabels[state]}
    </span>
  );
}

export interface StepperItem {
  id: string;
  title: string;
  state: GuidedState;
}

/**
 * Ordered step navigation. Every step stays selectable so a finished flow can be revisited
 * and re-run; the current step carries aria-current="step".
 */
export function Stepper({
  label,
  steps,
  current,
  onSelect
}: {
  label: string;
  steps: StepperItem[];
  current: string;
  onSelect: (id: string) => void;
}) {
  return (
    <nav className="stepper" aria-label={label}>
      <ol>
        {steps.map((step, index) => (
          <li key={step.id}>
            <button
              type="button"
              className="stepper__item"
              aria-current={step.id === current ? "step" : undefined}
              aria-label={`Step ${index + 1}: ${step.title}, ${stateLabels[step.state]}`}
              onClick={() => onSelect(step.id)}
            >
              <span className="stepper__number" aria-hidden="true">
                {index + 1}
              </span>
              <span className="stepper__text">
                <span className="stepper__title">{step.title}</span>
                <PlainStatus state={step.state} />
              </span>
            </button>
          </li>
        ))}
      </ol>
    </nav>
  );
}

/**
 * One step's panel. When the step changes (not on first render) focus moves to its heading,
 * so keyboard and screen-reader users land on the new content.
 */
export function GuidedStep({
  id,
  number,
  total,
  title,
  state,
  stateLabel,
  why,
  children
}: {
  id: string;
  number: number;
  total: number;
  title: string;
  state: GuidedState;
  /** Overrides the status words, for example "Verified in Sentinel". */
  stateLabel?: string;
  why: string;
  children: ReactNode;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  const shown = useRef<string | null>(null);
  useEffect(() => {
    if (shown.current !== null && shown.current !== id) {
      heading.current?.focus();
    }
    shown.current = id;
  }, [id]);

  return (
    <section className="sheet guided-step" aria-labelledby={`guided-step-${id}`}>
      <header className="guided-step__header">
        <div>
          <p className="guided-step__count">
            Step {number} of {total}
          </p>
          <h2 id={`guided-step-${id}`} ref={heading} tabIndex={-1}>
            {title}
          </h2>
        </div>
        <PlainStatus state={state} label={stateLabel} />
      </header>
      <div className="guided-step__body">
        <WhyItMatters>{why}</WhyItMatters>
        {children}
      </div>
    </section>
  );
}

/** The one-line reason a step exists, in plain English. */
export function WhyItMatters({ children }: { children: ReactNode }) {
  return (
    <p className="why-it-matters">
      <strong>Why this matters:</strong> {children}
    </p>
  );
}

const lightLabels: Record<HomeState, string> = {
  green: "All good",
  amber: "Needs a look",
  red: "Needs action now"
};

const lightIcons: Record<HomeState, typeof CheckCircle2> = {
  green: CheckCircle2,
  amber: TriangleAlert,
  red: XCircle
};

/** A traffic light: "All good", "Needs a look" or "Needs action now", always words plus an icon shape. */
export function TrafficLight({ state }: { state: HomeState }) {
  const Icon = lightIcons[state];
  return (
    <span className={`traffic-light traffic-light--${state}`}>
      <Icon aria-hidden="true" />
      {lightLabels[state]}
    </span>
  );
}

const checkLabels: Record<GuidedCheck["state"], string> = {
  pass: "Passed",
  warn: "Warning",
  fail: "Problem",
  pending: "To do"
};

const checkIcons: Record<GuidedCheck["state"], typeof CheckCircle2> = {
  pass: CheckCircle2,
  warn: TriangleAlert,
  fail: XCircle,
  pending: CircleDashed
};

/** Validation results, each with its suggested fix. */
export function CheckList({ label, checks }: { label: string; checks: GuidedCheck[] }) {
  if (!checks.length) {
    return null;
  }
  return (
    <ul className="check-list" aria-label={label}>
      {checks.map((check) => {
        const Icon = checkIcons[check.state];
        return (
          <li key={check.id} className={`check-list__item check-list__item--${check.state}`}>
            <Icon aria-hidden="true" />
            <div>
              <p>
                <span className="visually-hidden">{checkLabels[check.state]}: </span>
                {check.message}
              </p>
              {check.fix && check.state !== "pass" && (
                <p className="check-list__fix">
                  <strong>How to fix:</strong> {check.fix}
                </p>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}
