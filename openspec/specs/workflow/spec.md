# Workflow spec

Source of truth for how work is tracked: one GitHub Project managed as code
by [SAFO](https://github.com/ChiefGyk3D/scrum-around-and-find-out) (`safo`
0.2.0 on `cachyos-x8664`, `~/safo`). Board:
<https://github.com/orgs/tweak-wiki/projects/1>.

## Purpose

No hidden work. Every unit of work has an issue and a board card before work
starts, and every pull request links its issue. The board file
(`~/safo-boards/irc-serve.board.yaml` on `cachyos-x8664`) is the definition;
the live project is kept current from it, never the other way round.

## Requirements

### Requirement: Tracking

Every change SHALL be traceable from card to issue to pull request to merge.

#### Scenario: New work gets a card first
- **WHEN** work starts (human or agent)
- **THEN** an issue exists and carries a board card before the first commit.

#### Scenario: One item, one owner
- **WHEN** an item is in progress
- **THEN** it has exactly one owner, so two agents never implement the same
  issue on two branches.


#### Scenario: Pull request links its issue
- **WHEN** a pull request opens
- **THEN** its body contains `Refs #n` or `Closes #n`, and `audit` reports a
  pull request without one as drift.

### Requirement: Board definition

`irc-serve.board.yaml` SHALL be the only definition of the project's fields,
views, and rules.

#### Scenario: Bootstrap creates, never edits
- **WHEN** `safo bootstrap` finds an existing field whose options differ
- **THEN** it refuses and prints the UI step; the option is added by hand in
  the project's settings (the API would re-id every option and wipe values).

#### Scenario: Gate matches branch protection
- **WHEN** `main`'s required checks change
- **THEN** `rules.gate_check` is updated to match (today: `ci_test`), so the
  audit fails when the gate is not enforced.

### Requirement: Automation

A daily systemd timer on `cachyos-x8664` SHALL keep the board current.

#### Scenario: Daily reconcile
- **WHEN** `safo-reconcile-irc-serve.timer` fires
- **THEN** open issues and pull requests gain cards, closed ones move to Done
  with the date, and anything needing a person is reported as HUMAN (exit 1
  with a HUMAN line is a flag, not a failure).

#### Scenario: Manual verification
- **WHEN** the board definition changes
- **THEN** `safo validate` passes offline, `safo audit` is clean (0 drift,
  0 unknown), and `safo reconcile` run twice reports nothing to do.

### Requirement: Agent routing

Task routing SHALL recommend omp roles only — never Claude, Codex, Copilot,
or any other vendor agent.

#### Scenario: omp-only recommendations
- **WHEN** `safo route <shape>` runs with `~/.config/safo/agents.yaml`
- **THEN** the recommended agent and reviewer are `omp-lead`, `omp-worker`,
  or `maintainer`, and nothing else.
