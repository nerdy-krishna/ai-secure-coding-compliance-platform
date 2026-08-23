# Issue tracker: Local Markdown

Issues and PRDs for this repository live as private Markdown files under `.scratch/`.
They are local working material and must never be committed to the public repository.

## Conventions

- One initiative per directory: `.scratch/<feature-slug>/`.
- The initiative PRD is `.scratch/<feature-slug>/PRD.md`.
- Implementation issues are `.scratch/<feature-slug>/issues/<NN>-<slug>.md`, numbered from `01`.
- Triage state is recorded as a `Status:` line near the top of each issue file.
- Comments and decision history are appended under a `## Comments` heading.

## Skill operations

When a skill says to publish an issue or PRD, create the corresponding file under `.scratch/`.
When a skill says to fetch a ticket, read the referenced local Markdown file.

The `.scratch/` directory is gitignored. Sensitive findings, credentials, customer data, and
undisclosed vulnerabilities must not be copied into committed documentation.
