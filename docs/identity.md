# Identity

How Goliath looks, and the reasons, so that the interface, the site, and
anything made later stay one thing.

## The mark

A letter G built from seven horizontal bars, as lines of a log are. Six bars
take the colour of the text. One is bronze: the crossbar of the letter, the
event that matters among the others. The armour of Goliath is bronze in the
text the name comes from.

- The drawing is in [Mark.tsx](../ui/src/components/Mark.tsx), on a grid of
  32 units: bars 4 high, 2 apart.
- It is drawn from straight bars alone, so it holds at 16 pixels, the size
  of a browser tab.
- On a ground that is not the interface's, it sits on a dark tile, as in
  [favicon.svg](../ui/public/favicon.svg).
- The README shows that tile from [assets/mark.svg](assets/mark.svg), so it
  reads on GitHub's light ground and on its dark one.
- It is not redrawn, outlined, tilted, or given a gradient.

## The name

`goliath`, in lowercase, in the weight of a heading, with nothing after it.
In running text the product is Goliath, as any name is written.

## Colour

A near black ground with a violet glow behind the top of a page, surfaces
told apart by lightness, and one violet accent. The interface is read for hours in a dark room, so it is dark
first; the light theme has the same tokens. The decision and its reasons
are in [ADR-0024](adr/0024-interface.md).

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--bg` | `#09090d` | `#f5f5f8` | The ground |
| `--panel` | `#121218` | `#ffffff` | Bars, cards, tables |
| `--raised` | `#1a1a23` | `#f0f0f5` | A surface above a surface |
| `--line` | `#24242f` | `#dedee6` | Borders and rules |
| `--text` | `#f2f2f7` | `#1c1c22` | Text |
| `--muted` | `#8f8fa3` | `#676774` | Labels and what matters less |
| `--accent` | `#a78bfa` | `#6d28d9` | What can be acted on, and what is selected |
| `--accent-fill` | `#7c3aed` | `#6d28d9` | The ground of the main action, under white text |
| `--brand` | `#c98a4b` | `#9c5f22` | The mark's one bar, and nothing else |

The tokens are defined in [styles.css](../ui/src/styles.css). Text, the
accent, and every state have a contrast of 4.5 to 1 or more against each
surface.

## The accent is never a severity

In a product that reports severities, a colour of the product that could be
read as one is a defect. The accent was bronze until ADR-0024; bronze reads
as orange, and orange is high severity in most systems, so in the interface
it went. It stays where it cannot be read as a severity: in the mark, which
is the product's and says nothing of an event. Violet means that something
can be acted on, and nothing else:

| Severity | Token | Dark | Light |
| --- | --- | --- | --- |
| Critical | `--critical` | `#ff453a` | `#d70015` |
| High | `--high` | `#ff9f0a` | `#c93400` |
| Medium | `--medium` | `#ffd60a` | `#a05a00` |
| Low | `--low` | `#38bdf8` | `#0369a1` |
| Informational | `--info` | `#7c83ff` | `#4f46e5` |

A state is green when it is as it should be, the yellow of medium when it
is degraded, and the red of critical when it is failing. A severity is
never shown by its colour alone: it has its word beside it. A series of a
chart that is not a severity takes a colour from the list of eight in
[canvas.ts](../ui/src/charts/canvas.ts), which holds no red, orange, or
yellow.

## Type

The fonts of the reader's system, and a monospace face for identifiers,
times, and code. Nothing is fetched from elsewhere: the interface must work
on a network with no way out.
