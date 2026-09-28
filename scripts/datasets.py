#!/usr/bin/env python3
"""Downloads the OTRF Security Datasets the rig replays, into bench/datasets.

    python3 scripts/datasets.py                 # every Windows atomic dataset
    python3 scripts/datasets.py --only SDWIN-190301125905 SDWIN-201018195009

Each dataset becomes a directory, bench/datasets/otrf/<id>/, holding:

- sysmon.jsonl: its Sysmon events, flat JSON lines, which the `sysmon-flat`
  definition reads;
- other.jsonl: its events from other channels, such as Security, kept for
  when a definition reads them;
- label.json: what it records, for `replay --label`: its id, title, ATT&CK
  techniques, source, licence, and the commit it was taken from.

The datasets are recordings of real attack tools. Security software may
quarantine them, which is why they are downloaded, never committed, and why
bench/datasets is ignored. Run this on a machine meant for it. See
docs/benchmark-rig.md, Replaying real datasets.

Needs only Python 3.9 or later. `--self-test` checks the parsing, offline.
"""

import argparse
import io
import json
import sys
import urllib.request
import zipfile
from pathlib import Path

REPOSITORY = "OTRF/Security-Datasets"
# Pinned, so that a run names exactly what it replayed.
COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
LICENSE = "MIT"
METADATA = "datasets/atomic/_metadata"
SYSMON = "Microsoft-Windows-Sysmon"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "goliath-datasets"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def raw(path):
    return f"https://raw.githubusercontent.com/{REPOSITORY}/{COMMIT}/{path}"


def listing():
    """The metadata files of the atomic datasets, by name."""
    url = f"https://api.github.com/repos/{REPOSITORY}/contents/{METADATA}?ref={COMMIT}"
    return [entry["name"] for entry in json.loads(fetch(url)) if entry["name"].endswith(".yaml")]


def unquote(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1]
    return text


def parse(text):
    """The few members of a dataset's metadata this script needs.

    The metadata is YAML in one fixed layout; reading those members by line
    keeps the script free of dependencies.
    """
    found = {"id": None, "title": None, "platform": [], "type": None, "techniques": [], "host": []}
    section = None
    technique = None
    file_type = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indented = line[0] in " \t-"
        if not indented:
            key, _, value = line.partition(":")
            section = key.strip()
            value = unquote(value)
            if section in ("id", "title", "type") and value:
                found[section] = value
            continue
        item = line.strip()
        if item.startswith("- "):
            item = item[2:]
            starts_item = True
        else:
            starts_item = False
        key, _, value = item.partition(":")
        key, value = key.strip(), unquote(value)
        if section == "platform" and starts_item and not value:
            found["platform"].append(key)
        elif section == "attack_mappings":
            if key == "technique":
                technique = value
                found["techniques"].append(technique)
            elif key == "sub-technique" and technique and value:
                found["techniques"][-1] = f"{technique}.{value}"
        elif section == "files":
            if key == "type":
                file_type = value
            elif key == "link" and file_type == "Host":
                found["host"].append(value)
    return found


def pinned(link):
    """A raw GitHub link rewritten from a branch to the pinned commit."""
    prefix = f"https://raw.githubusercontent.com/{REPOSITORY}/"
    if not link.startswith(prefix):
        return link
    _, _, path = link[len(prefix):].partition("/")
    return raw(path)


def split(archive):
    """The Sysmon lines and the other lines of every JSON file in a zip."""
    sysmon, other = [], []
    with zipfile.ZipFile(io.BytesIO(archive)) as files:
        for name in files.namelist():
            if not name.endswith(".json"):
                continue
            for line in files.read(name).decode("utf-8", "replace").splitlines():
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    other.append(line)
                    continue
                (sysmon if record.get("SourceName") == SYSMON else other).append(line)
    return sysmon, other


def download(name, out):
    meta = parse(fetch(raw(f"{METADATA}/{name}")).decode("utf-8", "replace"))
    if meta["type"] != "atomic" or "Windows" not in meta["platform"] or not meta["host"]:
        return None
    directory = out / meta["id"]
    directory.mkdir(parents=True, exist_ok=True)
    sysmon, other = [], []
    links = [pinned(link) for link in meta["host"]]
    for link in links:
        more, rest = split(fetch(link))
        sysmon += more
        other += rest
    (directory / "sysmon.jsonl").write_text("\n".join(sysmon) + "\n", encoding="utf-8")
    (directory / "other.jsonl").write_text("\n".join(other) + "\n", encoding="utf-8")
    label = {
        "dataset": meta["id"],
        "title": meta["title"],
        "techniques": meta["techniques"],
        "source": f"https://github.com/{REPOSITORY}",
        "license": LICENSE,
        "commit": COMMIT,
        "files": links,
    }
    (directory / "label.json").write_text(json.dumps(label, indent=2) + "\n", encoding="utf-8")
    return meta["id"], len(sysmon), len(other)


def self_test():
    sample = """title: An example
id: SDWIN-000000000000
platform:
- Windows
type: atomic
attack_mappings:
  - technique: T1222
    sub-technique: "001"
    tactics:
      - TA0005
  - technique: T1087
files:
  - type: Host
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/x/host/a.zip
  - type: Network
    link: https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/x/network/a.zip
"""
    meta = parse(sample)
    assert meta["id"] == "SDWIN-000000000000", meta
    assert meta["title"] == "An example", meta
    assert meta["platform"] == ["Windows"], meta
    assert meta["type"] == "atomic", meta
    assert meta["techniques"] == ["T1222.001", "T1087"], meta
    assert meta["host"] == [
        "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/x/host/a.zip"
    ], meta
    assert pinned(meta["host"][0]).endswith(f"/{COMMIT}/datasets/atomic/x/host/a.zip")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        lines = [
            {"SourceName": SYSMON, "EventID": 1},
            {"SourceName": "Microsoft-Windows-Security-Auditing", "EventID": 4688},
        ]
        archive.writestr("a.json", "\n".join(json.dumps(line) for line in lines) + "\nnot json\n")
    sysmon, other = split(buffer.getvalue())
    assert len(sysmon) == 1 and len(other) == 2, (sysmon, other)
    print("ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=Path("bench/datasets/otrf"))
    parser.add_argument("--only", nargs="*", help="dataset ids to download, such as SDWIN-190301125905")
    parser.add_argument("--self-test", action="store_true", help="check the parsing, offline")
    arguments = parser.parse_args()
    if arguments.self_test:
        self_test()
        return 0
    names = listing()
    if arguments.only:
        wanted = {f"{dataset}.yaml" for dataset in arguments.only}
        missing = wanted - set(names)
        if missing:
            print(f"no such datasets: {', '.join(sorted(missing))}", file=sys.stderr)
            return 1
        names = [name for name in names if name in wanted]
    for name in sorted(names):
        if not name.startswith("SDWIN-"):
            continue
        got = download(name, arguments.out)
        if got:
            print("%s: %d Sysmon events, %d others" % got)
    return 0


if __name__ == "__main__":
    sys.exit(main())
