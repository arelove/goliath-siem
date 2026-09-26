import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Without Vitest's globals, Testing Library cannot remove what a test
// rendered by itself.
afterEach(cleanup);

// jsdom lays nothing out, so every element measures zero and a virtualized
// list would show no rows. Give elements a screenful of size instead.
Object.defineProperties(HTMLElement.prototype, {
  offsetHeight: { configurable: true, get: () => 800 },
  offsetWidth: { configurable: true, get: () => 1200 },
});
