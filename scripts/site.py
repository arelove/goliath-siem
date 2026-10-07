#!/usr/bin/env python3
"""Builds the documentation site from the Markdown the repository already has.

    pip install markdown-it-py
    python scripts/site.py [output directory, target/site if left out]

Nothing is written twice: the pages are `docs/`, and the front page is the
sections of `README.md` under a short introduction. The build fails on a
link to a file that is not there, and on a figure of the front page that
`README.md` no longer states, so the site cannot say what the repository
does not.
"""

from __future__ import annotations

import html
import posixpath
import re
import shutil
import sys
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent
REPOSITORY = "https://github.com/arelove/goliath-siem"
SOURCE = f"{REPOSITORY}/blob/main"

# Mermaid draws the diagrams of the pages that have one. It is the only
# script fetched from elsewhere, at a fixed version, checked by its hash.
MERMAID = "https://cdn.jsdelivr.net/npm/mermaid@11.4.1/dist/mermaid.min.js"
MERMAID_HASH = "sha384-rbtjAdnIQE/aQJGEgXrVUlMibdfTSa4PQju4HDhN3sR2PmaKFzhEafuePsl9H/9I"

# The pages beside the decisions, in the order the navigation lists them.
# A document that is not named here is listed under "More".
GROUPS = [
    ("Overview", ["docs/README.md", "docs/architecture.md", "docs/roadmap.md"]),
    ("Measured", ["docs/sigma-coverage.md", "docs/benchmarks.md", "docs/benchmark-rig.md"]),
    ("Operating", ["docs/detector.md", "docs/lab.md"]),
]
# Shorter than the documents' own titles, for the navigation.
LABELS = {"docs/README.md": "Contents"}

# The figures of the front page. Each is shown only while `README.md` states
# it, in these words: a figure that changed there fails the build here.
FIGURES = [
    ("2,046", "SigmaHQ rules evaluated against every event", "2,046 rules"),
    ("~2M", "events a second on one 16-core laptop", "2,000,000 events/s"),
    ("359 / 359", "SigmaHQ regression cases fire as expected", "all 359 SigmaHQ regression cases"),
    ("38-806 ms", "to search 10 million stored events", "in 38 to 806 ms"),
]
# The sections of `README.md` the front page shows, in order.
SECTIONS = ["What works today", "Run it", "Why another SIEM"]


class Broken(Exception):
    """Something the site would say that the repository does not hold."""


class Page:
    """A Markdown file of the repository, and where it is written."""

    def __init__(self, source: str) -> None:
        self.source = source
        self.text = (ROOT / source).read_text(encoding="utf-8")
        name = posixpath.basename(source)
        directory = posixpath.dirname(source)
        self.output = posixpath.join(
            directory, "index.html" if name == "README.md" else name[:-3] + ".html"
        )
        heading = re.search(r"^# (.+)$", self.text, re.M)
        self.title = heading.group(1).strip() if heading else name
        self.label = LABELS.get(source, self.title)
        self.status = None
        self.date = None
        # The file decisions are copied from, which is none itself.
        self.template = name.startswith("0000-")
        if directory == "docs/adr":
            status = re.search(r"^- \*\*Status:\*\* (.+)$", self.text, re.M)
            date = re.search(r"^- \*\*Date:\*\* (.+)$", self.text, re.M)
            self.status = status.group(1).strip() if status else ""
            self.date = date.group(1).strip() if date else ""
            number, _, rest = self.title.partition(". ")
            self.number = number
            self.label = f"{number} {rest}" if rest else self.title


def slug(text: str, taken: dict[str, int]) -> str:
    """The anchor GitHub gives a heading, so that links written for it hold."""
    base = re.sub(r"[^\w\- ]", "", text.strip().lower()).replace(" ", "-")
    count = taken.get(base, 0)
    taken[base] = count + 1
    return base if count == 0 else f"{base}-{count}"


def relative(target: str, start: str) -> str:
    """The link from the page written at `start` to the file at `target`."""
    return posixpath.relpath(target, posixpath.dirname(start) or ".")


class Site:
    def __init__(self) -> None:
        documents = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "docs").glob("*.md")
        )
        decisions = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "docs/adr").glob("*.md")
        )
        named = [source for _, sources in GROUPS for source in sources]
        for source in named:
            if source not in documents:
                raise Broken(f"the navigation names {source}, which is not there")
        self.groups = [(title, [Page(s) for s in sources]) for title, sources in GROUPS]
        more = [Page(s) for s in documents if s not in named]
        if more:
            self.groups.append(("More", more))
        self.decisions = [Page(s) for s in decisions]
        # The template is no decision: last, and named for what it is.
        for page in self.decisions:
            if page.template:
                page.label = "Template"
        self.decisions.sort(key=lambda page: page.template)
        self.pages = [page for _, pages in self.groups for page in pages] + self.decisions
        self.by_source = {page.source: page for page in self.pages}
        self.markdown = MarkdownIt("commonmark", {"html": True}).enable("table")

    # -- links ------------------------------------------------------------

    def link(self, href: str, source: str, output: str) -> str:
        """Where a link written in the file `source` leads from `output`."""
        if re.match(r"^([a-z][a-z0-9+.-]*:|#|//)", href, re.I):
            return href
        path, mark, fragment = href.partition("#")
        target = posixpath.normpath(posixpath.join(posixpath.dirname(source), path))
        fragment = mark + fragment
        if target in self.by_source:
            return relative(self.by_source[target].output, output) + fragment
        if target == "docs/adr":
            return relative("docs/adr/index.html", output) + fragment
        if target == "docs":
            return relative("docs/index.html", output) + fragment
        if target == "README.md":
            return relative("index.html", output) + fragment
        on_disk = ROOT / target
        if target.startswith("..") or not on_disk.exists():
            raise Broken(f"{source} links to {href}, which is not in the repository")
        kind = "tree" if on_disk.is_dir() else "blob"
        return f"{REPOSITORY}/{kind}/main/{target}{fragment}"

    # -- Markdown ---------------------------------------------------------

    def render(self, text: str, source: str, output: str) -> tuple[str, list[tuple[str, str]], bool]:
        """The HTML of `text`, its second-level headings, and whether it
        holds a diagram."""
        tokens = self.markdown.parse(text)
        taken: dict[str, int] = {}
        outline = []
        diagram = False
        for index, token in enumerate(tokens):
            if token.type == "heading_open":
                inline = tokens[index + 1]
                plain = "".join(
                    child.content for child in inline.children or [] if child.type in ("text", "code_inline")
                )
                anchor = slug(plain, taken)
                token.attrSet("id", anchor)
                if token.tag == "h2":
                    outline.append((anchor, plain))
            if token.type == "inline":
                for child in token.children or []:
                    if child.type == "link_open":
                        child.attrSet("href", self.link(child.attrGet("href") or "", source, output))
                    if child.type == "image":
                        child.attrSet("src", self.link(child.attrGet("src") or "", source, output))
            if token.type == "fence" and token.info.strip() == "mermaid":
                diagram = True
                token.type = "html_block"
                token.content = f'<pre class="mermaid">{html.escape(token.content)}</pre>\n'
        body = self.markdown.renderer.render(tokens, self.markdown.options, {})
        # A wide table scrolls by itself, not the page.
        body = body.replace("<table>", '<div class="table"><table>').replace("</table>", "</table></div>")
        return body, outline, diagram

    # -- the frame every page has ------------------------------------------

    def navigation(self, output: str, current: str | None) -> str:
        def item(page: Page) -> str:
            here = ' aria-current="page"' if page.source == current else ""
            return f'<li><a href="{relative(page.output, output)}"{here}>{html.escape(page.label)}</a></li>'

        parts = []
        for title, pages in self.groups:
            parts.append(f"<h2>{title}</h2><ul>{''.join(item(page) for page in pages)}</ul>")
        here = ' aria-current="page"' if current == "docs/adr" else ""
        parts.append(
            f'<h2><a href="{relative("docs/adr/index.html", output)}"{here}>Decisions</a></h2>'
            f'<ul class="decisions">{"".join(item(page) for page in self.decisions)}</ul>'
        )
        return "".join(parts)

    def frame(self, output: str, title: str, main: str, *, wide: bool = False, diagram: bool = False) -> str:
        def to(target: str) -> str:
            return relative(target, output)

        mermaid = ""
        if diagram:
            mermaid = (
                f'<script src="{MERMAID}" integrity="{MERMAID_HASH}" crossorigin="anonymous" defer></script>'
            )
        name = "Goliath" if title == "Goliath" else f"{html.escape(title)} - Goliath"
        return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<meta name="description" content="Goliath: an open security data platform in Rust. Logs to OCSF, ClickHouse storage and search, threat intelligence matching, and Sigma detection.">
<title>{name}</title>
<link rel="icon" href="{to('assets/favicon.svg')}" type="image/svg+xml">
<link rel="stylesheet" href="{to('assets/style.css')}">
<script src="{to('assets/site.js')}"></script>
{mermaid}
</head>
<body class="{'front' if wide else 'document'}">
<header class="topbar">
  <a class="brand" href="{to('index.html')}">goliath<span class="mark">.</span></a>
  <span class="section">{'platform' if wide else 'documentation'}</span>
  <nav class="links">
    <a href="{to('docs/index.html')}">Docs</a>
    <a href="{to('docs/architecture.html')}">Architecture</a>
    <a href="{to('docs/roadmap.html')}">Roadmap</a>
    <a href="{to('docs/adr/index.html')}">Decisions</a>
  </nav>
  <span class="grow"></span>
  <a class="quiet" href="{REPOSITORY}">GitHub</a>
  <button class="quiet" id="theme" type="button" aria-label="Switch between dark and light">Light</button>
  <button class="quiet" id="menu" type="button" aria-label="Show the navigation">Menu</button>
</header>
{main}
<footer>
  <span>goliath<span class="mark">.</span> is open source under Apache-2.0. Pre-alpha: nothing here is production-ready.</span>
  <span class="grow"></span>
  <a href="{REPOSITORY}">Source</a>
  <a href="{REPOSITORY}/blob/main/SECURITY.md">Security</a>
  <a href="{REPOSITORY}/blob/main/CONTRIBUTING.md">Contributing</a>
</footer>
</body>
</html>
"""

    # -- pages ------------------------------------------------------------

    def document(self, page: Page, body: str, outline: list[tuple[str, str]], diagram: bool) -> str:
        order = self.pages
        index = order.index(page)
        steps = []
        if index > 0:
            before = order[index - 1]
            steps.append(
                f'<a class="step" href="{relative(before.output, page.output)}">'
                f"<small>Previous</small>{html.escape(before.label)}</a>"
            )
        else:
            steps.append("<span></span>")
        if index + 1 < len(order):
            after = order[index + 1]
            steps.append(
                f'<a class="step next" href="{relative(after.output, page.output)}">'
                f"<small>Next</small>{html.escape(after.label)}</a>"
            )
        aside = ""
        if len(outline) >= 3:
            entries = "".join(f'<li><a href="#{anchor}">{html.escape(text)}</a></li>' for anchor, text in outline)
            aside = f'<aside class="outline"><h2>On this page</h2><ul>{entries}</ul></aside>'
        main = f"""<div class="shell">
<nav class="sidebar" id="sidebar">{self.navigation(page.output, page.source)}</nav>
<main>
<article>
{body}
</article>
<div class="steps">{''.join(steps)}</div>
<p class="edit"><a href="{SOURCE}/{page.source}">This page on GitHub</a></p>
</main>
{aside}
</div>"""
        return self.frame(page.output, page.title, main, diagram=diagram)

    def decision_index(self) -> str:
        output = "docs/adr/index.html"
        rows = []
        for page in self.decisions:
            if page.template:
                continue
            # The status in a word or two; what follows it is in the record.
            whole = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"", page.status or "")
            state = re.split(r"[;:,]| by ", whole)[0].strip()
            kind = "accepted" if state.startswith("Accepted") else "other"
            _, _, rest = page.title.partition(". ")
            rows.append(
                f'<tr><td class="number">{page.number}</td>'
                f'<td><a href="{relative(page.output, output)}">{html.escape(rest)}</a></td>'
                f'<td><span class="pill {kind}" title="{html.escape(whole)}">{html.escape(state)}</span></td>'
                f'<td class="date">{html.escape(page.date or "")}</td></tr>'
            )
        body = f"""<h1>Decisions</h1>
<p>Every significant decision is recorded with what it was made against, what
was refused and why, and when to look at it again. A decision is changed by a
new record, never by editing history out of an old one.</p>
<div class="table"><table class="decisions">
<thead><tr><th>ADR</th><th>Decision</th><th>Status</th><th>Date</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>"""
        main = f"""<div class="shell">
<nav class="sidebar" id="sidebar">{self.navigation(output, 'docs/adr')}</nav>
<main><article>{body}</article></main>
</div>"""
        return self.frame(output, "Decisions", main)

    def front(self) -> str:
        output = "index.html"
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        flat = " ".join(readme.split())
        tiles = []
        for figure, caption, stated in FIGURES:
            if stated not in flat:
                raise Broken(f"README.md no longer says `{stated}`; the front page shows {figure}")
            tiles.append(f'<div class="tile"><strong>{figure}</strong><span>{caption}</span></div>')
        sections = []
        diagram = False
        for title in SECTIONS:
            found = re.search(rf"^## {re.escape(title)}\n(.*?)(?=^## |\Z)", readme, re.M | re.S)
            if not found:
                raise Broken(f"README.md has no section `{title}`")
            body, _, drawn = self.render(found.group(1), "README.md", output)
            diagram = diagram or drawn
            anchor = slug(title, {})
            sections.append(f'<section id="{anchor}"><h2>{title}</h2>{body}</section>')
        template = (ROOT / "site/front.html").read_text(encoding="utf-8")
        main = (
            template.replace("{{tiles}}", "".join(tiles))
            .replace("{{sections}}", "".join(sections))
            .replace("{{repository}}", REPOSITORY)
        )
        return self.frame(output, "Goliath", main, wide=True, diagram=diagram)

    # -- writing ------------------------------------------------------------

    def build(self, out: Path) -> int:
        if out.exists():
            shutil.rmtree(out)
        written = {}
        for page in self.pages:
            body, outline, diagram = self.render(page.text, page.source, page.output)
            written[page.output] = self.document(page, body, outline, diagram)
        written["docs/adr/index.html"] = self.decision_index()
        written["index.html"] = self.front()
        for output, text in written.items():
            path = out / output
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")
        assets = out / "assets"
        assets.mkdir(parents=True, exist_ok=True)
        for name in ("style.css", "site.js", "favicon.svg"):
            shutil.copyfile(ROOT / "site" / name, assets / name)
        # Served as the files are, without a build of its own.
        (out / ".nojekyll").write_text("", encoding="utf-8")
        return len(written)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "target/site"
    try:
        pages = Site().build(out)
    except Broken as broken:
        print(f"site: {broken}", file=sys.stderr)
        return 1
    print(f"site: {pages} pages in {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
