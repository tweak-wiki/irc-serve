# Workflow spec

Source of truth for how work is tracked and routed on this project.
The rule is simple: no hidden work — if it is not on the board, it does not happen.

## Purpose

Planning lives on the board-as-code project (`tweak-wiki/1`), not in chat
threads, private notes, or drive-by commits. A daily reconcile timer keeps the
board honest against the repo (open issues, open PRs), and routing goes through
`omp` only, so every work item has exactly one path from board to branch to PR.

## Requirements

### Requirement: Board as source of truth

Project `tweak-wiki/1` SHALL be the single list of what is being worked on.

#### Scenario: No hidden work
- **WHEN** work starts on anything non-trivial
- **THEN** there is a board item for it first, and the branch/PR references it —
  contributors learn the state of the project by reading the board, not by
  asking around.

#### Scenario: One item, one owner
- **WHEN** an item is in progress
- **THEN** it has exactly one owner, so two agents never implement the same
  issue on two branches.

### Requirement: Daily reconcile

A reconcile timer SHALL run daily and report board/repo drift.

#### Scenario: Drift surfaces
- **WHEN** the timer runs
- **THEN** items closed on the board with no merged PR, and merged work with no
  closed item, are flagged where the team will see them — the board converges
  on reality instead of rotting.

### Requirement: omp-only routing

Work SHALL be routed through `omp` only.

#### Scenario: Single path
- **WHEN** a contributor picks up a board item
- **THEN** assignment, branching, and the `Closes #N` PR trailer all go through
  the `omp` flow — no side channels, so the board always knows who is doing
  what.
