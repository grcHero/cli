# Local report format

`grchero scan --format json` and `grchero scan --output review.json` produce JSON with `schema_version: 1`, `rules_version`, CLI version, UTC creation time, local mode, selected file paths, applicable rule IDs, findings and limitations. The applicable rule list describes which checks matched the selected file types. It does not claim complete repository coverage.

Each finding has a rule ID, title, severity, relative path, line, observation, recommendation and SHA-256 hash of the reviewed file text. The hash enables local comparisons but can confirm a guessed short input. Do not publish reports containing sensitive paths or hashes.

The CLI never includes source text or detected credential values in the report. Consumers must treat every field as untrusted input, validate the schema and size limits, and label imported reports as user supplied. Importing a report is not equivalent to the server independently verifying its observations.
