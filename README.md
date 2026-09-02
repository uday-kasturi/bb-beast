# bb-beast

bb-beast (BugBounty Beast) is a bug bounty automation tool written in Python.
You point it at a target, it runs a set of security tools, and it uses a
language model to help triage the output. It is meant to be run by a person, not
as a background service.

## The idea

A lot of bug bounty work is running tools by hand, reading through their output,
and deciding what is worth looking at. bb-beast tries to take some of that
repetitive work off the operator.

The rough flow is:

1. You give it a target.
2. It runs playbooks, which are ordered sequences of security tools such as
   subfinder, nuclei, and ffuf.
3. Tool output is normalized into a common JSON format.
4. A language model reads the findings and suggests what looks worth pursuing,
   with a reason.
5. You get a structured list of next steps.
6. Interesting targets can be handed to Burp or ZAP for closer inspection.

The person stays in the loop for judgment calls. The tool handles the setup and
the first pass.

## Design notes

A few choices that shape the code:

- Plugin based. Adding a playbook or a tool wrapper means dropping files into a
  folder. Nothing else has to change.
- The model is used sparingly. Fast tools do the scanning. The model is only
  called when there is something worth reasoning about, since model calls cost
  money.
- Every file passed between pipeline stages has a JSON schema with a version
  field. A validator runs before anything moves downstream.
- Parsers run on their own at runtime, without the model.

## Layout

| Path | What is there |
|------|---------------|
| `core/` | The engine, schema validator, model client, and run lifecycle |
| `tools/` | One wrapper per external tool, each normalizing its output |
| `playbooks/` | Ordered tool chains grouped by what they look for (recon, exposure, injection, auth) |
| `schemas/` | JSON schemas for the files passed between stages |
| `programs/` | Scope definitions for programs, pulled from public disclosure pages |
| `execution/` | Acting on triaged findings |

## Scope and safety

Only run this against targets you are allowed to test, such as programs whose
disclosure or bounty scope permits it. The `programs/` files record in-scope and
out-of-scope assets so runs can be checked against them. Run output and any
captured evidence stay local and are not committed to this repository.

## Status

A work in progress and a personal project. It runs locally.

## Setup

Copy `.env.example` to `.env` and fill in the required keys. See
`bb-beast-overview.md` for a fuller description of the pipeline.
