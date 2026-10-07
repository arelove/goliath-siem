/**
 * The mark: a G of seven bars, as lines of a log are. One bar is bronze, the
 * crossbar of the letter: the event that matters among the others.
 */
export function Mark() {
  return (
    <svg className="mark" viewBox="0 0 32 32" aria-hidden="true">
      <rect x="9" y="2" width="15" height="4" rx="1.4" fill="currentColor" />
      <rect x="4" y="8" width="8" height="4" rx="1.4" fill="currentColor" />
      <rect x="4" y="14" width="8" height="4" rx="1.4" fill="currentColor" />
      <rect x="16" y="14" width="12" height="4" rx="1.4" fill="var(--accent)" />
      <rect x="4" y="20" width="8" height="4" rx="1.4" fill="currentColor" />
      <rect x="21" y="20" width="7" height="4" rx="1.4" fill="currentColor" />
      <rect x="9" y="26" width="19" height="4" rx="1.4" fill="currentColor" />
    </svg>
  );
}
