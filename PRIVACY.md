# Privacy

Sentinel OSS MCP is local, self-operated software. The project does not run a hosted
Sentinel service or collect project telemetry. Operators remain responsible for the data
they send to model providers and tools.

## Data flow

1. The caller supplies trusted intent, content, declared provenance, and optionally a
   draft output to `scan_exchange`.
2. Sentinel normalizes the content in memory and evaluates local policy/signature rules.
3. If a model adapter is configured, Sentinel sends the content needed for classification
   to that provider. Provider handling is governed by the operator's account, configuration,
   contract, region, and the provider's terms.
4. `authorize_action` evaluates tool and destination details locally.
5. Sentinel returns a structured decision and writes non-content decision metadata to the
   configured local SQLite audit store.

The default MCP transport is local stdio. Sentinel does not create a public listener.

## Local audit data

The core audit record is limited to operational metadata such as:

- timestamp and random decision ID;
- policy ID and version;
- status, outcome, reason code, and evaluation stage;
- provider/model identifier when used;
- latency and other non-content routing signals.

The core does **not** persist prompts, retrieved content, draft outputs, tool arguments,
destinations, embeddings, or hashes derived from those payloads. Reason messages and
signals must be from a controlled vocabulary or otherwise safe; they must not quote input.

Operational metadata can still reveal usage patterns. Restrict access to the runtime
directory, choose an appropriate retention setting, back it up only when necessary, and
delete it according to your incident and records policy. Stop the Sentinel process before
copying or removing the SQLite database.

## Optional components

- A model adapter transmits classification inputs to its provider. Review that provider's
  data-use and retention settings before enabling it.
- Semantic routing may compute an embedding in memory. The beta must not persist request
  content or request embeddings. Review any third-party vector/embedder adapter separately.
- The dashboard reads aggregate local metadata. It must not display raw interactions because
  the core does not retain them.
- Red-team generation sends its synthetic request to the configured provider and may return
  harmful text. It is a development CLI command and is not exposed by the MCP server.

Optional dependencies do not activate merely because they are installed. Imports and help
output should not initialize a provider or access credentials.

## Operator responsibilities

- Minimize content before sending it to Sentinel or a provider.
- Do not use real personal, health, payment, credential, or customer data in examples,
  evaluation fixtures, bug reports, or red-team generation.
- Keep credentials in an approved secret manager or process environment; never pass them in
  a prompt, tool argument, command-line flag, repository file, or audit field.
- Accurately label provenance and data sensitivity, and enforce destination restrictions.
- Configure provider region, retention, logging, and abuse-monitoring controls appropriate
  to your use case.
- Apply filesystem permissions, retention, deletion, and backup controls to local metadata.
- Perform your own privacy and legal review. Bundled policies are illustrative only.

## Contributions and reports

Repository issues, pull requests, CI logs, and evaluation assets are public. Use synthetic
reproductions. Report suspected data exposure through the private process in
[SECURITY.md](SECURITY.md), without attaching the exposed data.

Privacy behavior is part of the public contract. A change that adds a stored field, external
request, telemetry event, or new processor must update this document, the threat model,
tests, and changelog before release.
