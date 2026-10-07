# Identity

How Goliath looks, and the reasons, so that the interface, the site, and
anything made later stay one thing.

## The mark

A letter G built from seven horizontal bars, as lines of a log are. Six bars
take the colour of the text. One is bronze: the crossbar of the letter, the
event that matters among the others.

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

Warm graphite, and bronze. The armour of Goliath is bronze in the text the
name comes from, and no other product of this kind uses it.

| Token | Dark | Light | Use |
| --- | --- | --- | --- |
| `--bg` | `#121110` | `#f3efe9` | The ground |
| `--panel` | `#1b1917` | `#ffffff` | Bars, cards, tables |
| `--line` | `#2e2a26` | `#e2dbd1` | Borders and rules |
| `--text` | `#ece6dd` | `#221d17` | Text |
| `--muted` | `#9a9085` | `#766c60` | Labels and what matters less |
| `--accent` | `#c98a4b` | `#9c5f22` | The product's own: what is selected, the main action, links |
| `--on-accent` | `#17110a` | `#ffffff` | Text on the accent |

The tokens are defined in [styles.css](../ui/src/styles.css).

## Bronze is never a severity

In a product that reports severities, a colour of the product that could be
read as one is a defect. Bronze lies between orange and amber, so those two
are not used for severities:

| Severity | Colour |
| --- | --- |
| Informational, Low | Blues |
| Medium | Yellow, `#e3c341` |
| High | Red-orange, `#f2643a` |
| Critical | Crimson, `#dc3550` |
| Fatal | Purple, `#a23b8f` |

Blue is a colour of data here, not of the product. A new state or a new
chart series takes a colour from this scale or a neutral, never a second
bronze.

## Type

The fonts of the reader's system, and a monospace face for identifiers,
times, and code. Nothing is fetched from elsewhere: the interface must work
on a network with no way out.
