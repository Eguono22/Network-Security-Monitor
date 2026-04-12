# Week 1 Execution Plan

This document turns the current product direction into a practical short-term build plan for the repository.

## Goal

Make the project feel useful and trustworthy for a first-time user in one short session.

Target user:
- SMB IT admin or small SOC team

Target outcome:
- Clone the repo
- Install dependencies
- Run a simulation
- Understand the alerts
- Know what to do next

## Week 1 Priorities

### 1. Tighten first-run experience

- Keep `README.md` focused on fast setup and visible value
- Make the simulation flow the default demo path
- Add screenshots or sample output near the top of the README
- Ensure Windows and Linux instructions are both easy to follow

Definition of done:
- A new user can reach the first alert in under 5 minutes

### 2. Improve product framing

- Describe who the product is for right now
- Emphasize actionable detection and triage rather than broad future scope
- Keep `SentinelNet` vision visible, but separate it from current repo capabilities

Definition of done:
- The README clearly communicates current value and future direction without confusion

### 3. Strengthen demo workflow

- Make sure simulation produces understandable alerts and incident artifacts
- Add a guided “first five minutes” path in the README
- Consider adding sample screenshots for dashboard, watcher, and SOC views

Definition of done:
- Someone reviewing the repo can understand the main workflow without reading source files

### 4. Prepare next engineering wedge

- Confirm the next major build target is persistent storage and better incident lifecycle
- Identify current log-backed paths that should become structured storage interfaces
- Keep tests green as documentation and UX improvements land

Definition of done:
- The repo is ready to begin Week 2 work on persistence and incident workflow

## Recommended Backlog Order

1. Add screenshots or example UI/API responses to the README
2. Add a dedicated architecture or flow diagram image
3. Refine incident workflow messaging in docs and dashboard labels
4. Start datastore abstraction for alerts and incidents
5. Add richer filtering and status handling to incident views

## Success Check

At the end of Week 1, the repository should answer these questions quickly:

- What problem does this solve?
- Who is it for?
- How do I run it?
- What will I see?
- Why should I trust the results?

If those answers are easy to find, the project is in a much stronger position for adoption and iteration.
