# Decisions

## PM Log

### 2026-04-02 -- Initial v1 Story Breakdown

Analyzed the full codebase to determine implemented vs stubbed/missing functionality. Created 12 GitHub issues covering all work needed to reach a working v1.

**Current state summary:**
- Domain types defined but evaluation logic stubbed (assertion engine always returns `Passed: true`)
- Config YAML types exist but no loading, validation, or conversion logic
- Engine report accumulator is functional and thread-safe
- Admin API partially working (health, JSON report, reset) but missing config endpoint, SARIF, and JUnit
- Four packages are empty shells: proxy, decoy, preset, report
- Public embedding API has only a Mode type
- CLI prints version and exits -- no flag parsing, no wiring
- Zero tests in the entire repository
- Dockerfile exists and looks correct

**Issues created (in dependency order):**

| # | Title | Dependencies | Est. Size |
|---|-------|-------------|-----------|
| 1 | Config loading: parse YAML, validate, and convert to domain types | None | 2-3 days |
| 2 | Match evaluation: implement request matching logic | None | 1-2 days |
| 3 | Condition evaluation: implement allow/deny condition checks | #2 | 2-3 days |
| 4 | Preset rule packs: implement built-in assertion sets | #1 | 2-3 days |
| 5 | Decoy endpoint mode: echo server with assertion evaluation | #3 | 1-2 days |
| 6 | Transparent proxy mode: forward traffic with assertion inspection | #3 | 2-3 days |
| 7 | CLI entrypoint: flag parsing, config loading, server wiring, and graceful shutdown | #1, #4, #5, #6 | 2-3 days |
| 8 | Report formatters: SARIF, JUnit XML, and JSON output | #3 | 2-3 days |
| 9 | Admin API: add config endpoint and wire report formatters | #4, #8 | 1-2 days |
| 10 | Public Go API: implement embedding interface in pkg/snitchproxy | #7 | 2-3 days |
| 11 | End-to-end integration tests | #5, #6, #8, #9 | 2-3 days |
| 12 | CI pipeline: GitHub Actions for test, build, and release | #11 | 1-2 days |

**Critical path:** #1 + #2 -> #3 -> #5/#6 -> #7 -> #10

**Parallelizable work:**
- #1 (config) and #2 (match eval) can be done in parallel
- #4 (presets) can start once #1 is done
- #5 (decoy) and #6 (proxy) can be done in parallel after #3
- #8 (report formatters) can be done in parallel with #5/#6

**Open questions:**
1. Should HTTPS body inspection via TLS interception (MITM) be a v1 requirement or deferred to v2? Currently scoped as out-of-scope for #6.
2. Should there be a `go.sum` tracking story or is that expected to happen naturally as dependencies are added?
3. The DSL spec mentions HTML report format -- confirmed deferred, but should we create a v1.1 backlog issue for it?
4. The `ConditionSpec.Value` field is a `string` in the domain type but `StringOrSlice` in the config type (for multi-CIDR `in-cidr`). Need architect to decide how the domain type should handle multi-value conditions.
5. Testcontainers module is mentioned in CLAUDE.md as a separate repo -- confirm this is NOT in scope for snitchproxy v1.
