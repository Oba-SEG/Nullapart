/**
 * Nullapart accessible Hint (tooltip) primitive.
 *
 * Explains a rule the label cannot carry: why a control is locked, what a
 * domain term means, or what an irreversible action will do.
 *
 * Design notes:
 * - The bubble renders into a portal with fixed positioning, so it is never
 *   clipped by the `overflow` of a dense table cell or scroll container.
 * - Pointer and keyboard share one open state. `focusin`/`focusout` bubble in
 *   React, so a focusable child gets the hint on tab without a second tab stop.
 * - When the content is not focusable (a badge, a table header term, a disabled
 *   control) the wrapper takes the tab stop itself, after mount, so keyboard
 *   users can still reach the explanation.
 * - `aria-describedby` points at a permanently mounted visually-hidden copy of
 *   the text. Screen readers announce it in context instead of waiting for a
 *   hover that never happens.
 */

import {
  cloneElement,
  isValidElement,
  useEffect,
  useId,
  useLayoutEffect,
  useRef,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";
import { createPortal } from "react-dom";

import "./Hint.css";

const GAP = 8;
const EDGE = 8;
/**
 * Focusable descendants. A disabled control cannot receive focus, so it must
 * not count: the wrapper borrows the tab stop instead, which is what makes a
 * switched-off action's reason reachable by keyboard.
 */
const FOCUSABLE =
  "button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])";

export interface HintProps {
  /** The explanation. A rule, not a mechanism. Keep it to one or two sentences. */
  label: string;
  children: ReactNode;
  /** Preferred side when there is room. Falls back to the opposite side. */
  placement?: "top" | "bottom";
}

export function Hint({ label, children, placement = "top" }: HintProps) {
  const id = useId();
  const wrapRef = useRef<HTMLSpanElement>(null);
  const [bubble, setBubble] = useState<{ top: number; left: number; place: string } | null>(null);
  const [focusable, setFocusable] = useState(false);

  // Only borrow a tab stop when nothing inside can receive focus.
  useLayoutEffect(() => {
    const node = wrapRef.current;
    if (node && !node.querySelector(FOCUSABLE)) {
      setFocusable(true);
    }
  }, [children]);

  const show = () => {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (!rect) {
      return;
    }
    const width = Math.min(320, window.innerWidth - EDGE * 2);
    const left = Math.min(
      Math.max(rect.left + rect.width / 2 - width / 2, EDGE),
      window.innerWidth - width - EDGE,
    );
    // Measured after paint would be exact; the estimate keeps the bubble off
    // the trigger without a second layout pass.
    const preferTop = placement === "top";
    const roomAbove = rect.top > 96;
    const place =
      preferTop === roomAbove ? (preferTop ? "top" : "bottom") : roomAbove ? "top" : "bottom";
    const top = place === "top" ? rect.top - GAP : rect.bottom + GAP;
    setBubble({ top, left, place });
  };

  const hide = () => setBubble(null);

  useEffect(() => {
    if (!bubble) {
      return;
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        hide();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [bubble]);

  // The description must sit on the element that receives focus, or a screen
  // reader announces the button and never the rule. A child that already
  // describes something else (an Input error) keeps its own reference.
  const described = isValidElement<{ "aria-describedby"?: string }>(children)
    ? children.props["aria-describedby"]
    : undefined;
  const content = isValidElement(children)
    ? cloneElement(children as ReactElement<{ "aria-describedby"?: string }>, {
        "aria-describedby": described ? `${described} ${id}` : id,
      })
    : children;

  return (
    <span
      className="hint"
      ref={wrapRef}
      tabIndex={focusable ? 0 : undefined}
      aria-describedby={focusable ? id : undefined}
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      {content}
      <span className="sr-only" id={id}>
        {label}
      </span>
      {bubble
        ? createPortal(
            <span
              className={`hint-bubble hint-bubble-${bubble.place}`}
              role="tooltip"
              style={{
                top: bubble.top,
                left: bubble.left,
                width: Math.min(320, window.innerWidth - EDGE * 2),
                transform: bubble.place === "top" ? "translateY(-100%)" : undefined,
              }}
            >
              {label}
            </span>,
            document.body,
          )
        : null}
    </span>
  );
}
