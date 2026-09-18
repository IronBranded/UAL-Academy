<h3 align="center">
  <a href="https://ironbranded.github.io/UAL-Academy/" target="_blank" rel="noopener noreferrer">
    🟢 TRY THE ACADEMY🟢
  </a>
</h3>

# Content data contract

The renderer knows nothing about DFIR. All investigative content lives in
`data/categories/*.json` and is validated by `scripts/validate.mjs` before it can
ship. Adding a category means adding a file, not touching application code.

```
data/
  taxonomy.json                    verified enums - the only source of truth
  _schema.json                     structural contract (JSON Schema 2020-12)
  categories/
    mailbox-operations.json        reference implementation, 3 scenarios
    <category>.json                one file per sidebar category
scripts/validate.mjs               semantic validator, zero dependencies
```

## Model

A **category** is a sidebar entry. It holds one or more **scenarios**, and each
scenario renders the six-tab workspace. Scenarios are the leaf nodes, not
categories — "Mailbox Operations" is a container, "scoping mailbox data access"
is the thing with six tabs.

`status: "stub"` renders the Phase 2 placeholder and is skipped by content
validation. The renderer must never present a stub as finished content.

## Why RecordTypes are stored as pairs

```json
{ "id": 50, "member": "ExchangeItemAggregated" }
```

Because the same concept has two representations and using the wrong one fails
silently. PowerShell and the Graph API take the integer or the member name;
Sentinel's `OfficeActivity.RecordType` column holds the **member name as a
string**. A query emitting `RecordType == 50` against `OfficeActivity` returns
zero rows and looks like a clean result. Storing both lets the builder emit the
right form per target, and lets the validator catch the mismatch.

## Claims carry a verification date

Any assertion that can go stale is a claim object:

```json
{ "text": "...", "verified": true, "source": "https://learn.microsoft.com/...", "lastVerified": "2026-09-06" }
```

`verified: false` renders a `[VERIFY]` badge in the UI. Prefer that over a
confident-sounding guess — a visibly flagged gap is more useful to an analyst
than a wrong number that looks authoritative.

`lastVerified` exists because this surface moves and stale guidance is the main
failure mode here. Half the public writing on `MailItemsAccessed` still says
E5-only; it has been Audit (Standard) since the post-Storm-0558 changes. The
weekly CI job surfaces claims older than 180 days.

## What the validator enforces

| Check | Prevents |
|---|---|
| RecordType id/member against `taxonomy.json` | invented or misremembered enum values |
| MITRE ID against the anchor set | plausible-looking sub-technique numbers that don't exist |
| KQL platform/table/time-column agreement | `TimeGenerated` in Defender, `Timestamp` in Sentinel |
| `AuditData` reference in any query | the column exists in neither KQL target |
| Integer `RecordType` comparison in `OfficeActivity` | queries that silently return nothing |
| Known-bad table names | `SignInLogs` (real name: `SigninLogs`) |
| Declared table appears in query body | copy-paste drift between metadata and query |
| `{{Param}}` binding both directions | code-builder inputs wired to nothing |
| Placeholder identifier policy | real-looking tenants and IPs on a public Pages site |
| Latency wording | reintroduction of the retired fixed 15-30 minute figure |

Comments are stripped before KQL linting, so a comment may discuss the wrong
column by name in order to warn about it.

## Adding a category

1. If it needs a RecordType or MITRE ID not already present, add it to
   `taxonomy.json` **first**, with a source.
2. Copy `mailbox-operations.json` as the shape reference.
3. Run `node scripts/validate.mjs` until clean.
4. Anything you could not verify: `verified: false`, not a plausible guess.
