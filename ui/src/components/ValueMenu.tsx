import { useEffect, useId, useRef, useState } from "react";

/** One thing a value's menu offers. */
export interface Way {
  label: string;
  run: () => void;
}

interface Props {
  value: string;
  /** What this place can do with the value, before what every place can. */
  ways?: Way[];
  /** Shown instead of the value, when the value is long or has a name. */
  children?: React.ReactNode;
}

/**
 * A value that names something, as a way on: see "A value is a way on" in
 * docs/adr/0024-interface.md. Every view shows such a value through this
 * one component, so that the same value offers the same menu everywhere.
 */
export function ValueMenu({ value, ways = [], children }: Props) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const root = useRef<HTMLSpanElement>(null);
  const id = useId();

  useEffect(() => {
    if (!open) {
      return;
    }
    const away = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    const leave = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", leave, true);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", leave, true);
    };
  }, [open]);

  const copy = () => {
    // The clipboard may be refused; the value is then selected by hand.
    void navigator.clipboard?.writeText(value).then(
      () => setCopied(true),
      () => setCopied(false),
    );
    setOpen(false);
  };

  return (
    <span className="way" ref={root}>
      <button
        type="button"
        className="way-name mono"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? id : undefined}
        title={value}
        onClick={(event) => {
          event.stopPropagation();
          setCopied(false);
          setOpen(!open);
        }}
      >
        {children ?? value}
      </button>
      {copied && <span className="way-note">Copied</span>}
      {open && (
        <span className="menu" role="menu" id={id}>
          {ways.map((way) => (
            <button
              type="button"
              role="menuitem"
              key={way.label}
              onClick={(event) => {
                event.stopPropagation();
                setOpen(false);
                way.run();
              }}
            >
              {way.label}
            </button>
          ))}
          <button
            type="button"
            role="menuitem"
            onClick={(event) => {
              event.stopPropagation();
              copy();
            }}
          >
            Copy
          </button>
        </span>
      )}
    </span>
  );
}
