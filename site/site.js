// The theme, as the interface of the platform keeps it: dark unless the
// reader chose light, here or in their system. Set before the page is
// drawn, so that it does not flash the other one.
(() => {
  const root = document.documentElement;
  const stored = (() => {
    try {
      return localStorage.getItem("goliath-theme");
    } catch {
      return null;
    }
  })();
  const light = window.matchMedia("(prefers-color-scheme: light)").matches;
  root.dataset.theme = stored ?? (light ? "light" : "dark");

  const diagrams = () => {
    if (!window.mermaid) return;
    const dark = root.dataset.theme === "dark";
    const style = getComputedStyle(root);
    const color = (name) => style.getPropertyValue(name).trim();
    window.mermaid.initialize({
      startOnLoad: false,
      securityLevel: "strict",
      theme: "base",
      themeVariables: {
        darkMode: dark,
        background: color("--bg"),
        primaryColor: color("--raised"),
        primaryTextColor: color("--text"),
        primaryBorderColor: color("--accent"),
        lineColor: color("--muted"),
        secondaryColor: color("--panel"),
        tertiaryColor: color("--panel"),
        fontFamily: '"Segoe UI", system-ui, -apple-system, sans-serif',
        fontSize: "14px",
      },
      // At its own size: a wide diagram scrolls, and stays readable.
      flowchart: { useMaxWidth: false },
      sequence: { useMaxWidth: false },
    });
    for (const diagram of document.querySelectorAll("pre.mermaid")) {
      // Kept, to draw again in the other theme.
      diagram.dataset.source ??= diagram.textContent;
      diagram.textContent = diagram.dataset.source;
      diagram.removeAttribute("data-processed");
    }
    window.mermaid.run({ querySelector: "pre.mermaid" });
  };

  document.addEventListener("DOMContentLoaded", () => {
    const theme = document.getElementById("theme");
    const label = () => {
      theme.textContent = root.dataset.theme === "dark" ? "Light" : "Dark";
    };
    label();
    theme.addEventListener("click", () => {
      root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
      try {
        localStorage.setItem("goliath-theme", root.dataset.theme);
      } catch {
        // Not kept; the choice holds for this page.
      }
      label();
      diagrams();
    });

    const sidebar = document.getElementById("sidebar");
    const menu = document.getElementById("menu");
    if (sidebar) {
      menu.addEventListener("click", () => sidebar.classList.toggle("open"));
      // The page being read, in view in a long navigation.
      sidebar.querySelector('[aria-current="page"]')?.scrollIntoView({ block: "center" });
    } else {
      menu.hidden = true;
    }
  });
  window.addEventListener("load", diagrams);
})();
