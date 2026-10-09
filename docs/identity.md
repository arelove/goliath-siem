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

A cool, near black ground, surfaces told apart by lightness, and one blue
accent. The interface is read for hours in a dark room, so it is dark
first; the light theme has the same tokens. The decision and its reasons
are in [ADR-0024](adr/0024-interface.md).

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--bg` | `#0b0c0e` | `#f5f5f7` | The ground |
| `--panel` | `#141518` | `#ffffff` | Bars, cards, tables |
| `--raised` | `#1c1d21` | `#f0f0f3` | A surface above a surface |
| `--line` | `#26282d` | `#dedee3` | Borders and rules |
| `--text` | `#f2f3f5` | `#1d1d1f` | Text |
| `--muted` | `#8b8d98` | `#68686d` | Labels and what matters less |
| `--accent` | `#0a84ff` | `#0066cc` | What can be acted on, and what is selected |
| `--accent-fill` | `#0071e3` | `#0066cc` | The ground of the main action, under white text |
| `--brand` | `#c98a4b` | `#9c5f22` | The mark's one bar, and nothing else |

The tokens are defined in [styles.css](../ui/src/styles.css). Text, the
accent, and every state have a contrast of 4.5 to 1 or more against each
surface.

## The accent is never a severity

In a product that reports severities, a colour of the product that could be
read as one is a defect. The accent was bronze until ADR-0024; bronze reads
as orange, and orange is high severity in most systems, so in the interface
it went. It stays where it cannot be read as a severity: in the mark, which
is the product's and says nothing of an event. Blue means that something
can be acted on, and nothing else:

| Severity | Token | Dark | Light |
| --- | --- | --- | --- |
| Critical | `--critical` | `#ff453a` | `#d70015` |
| High | `--high` | `#ff9f0a` | `#c93400` |
| Medium | `--medium` | `#ffd60a` | `#a05a00` |
| Low | `--low` | `#7d8fa9` | `#5b6b82` |
| Informational | `--info` | `#787a85` | `#86868b` |

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
