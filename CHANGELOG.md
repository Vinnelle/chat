# Changelog

## 0.1.2

### Fixed
- On Linux, `:update` saved the new binary as `chat (deleted)` instead of replacing
  `chat` when the executable had been replaced (for example rebuilt) while chat was running.

## 0.1.1

### Added
- `@` nick completion: typing `@` and the start of an online peer's nick shows the rest
  dimmed; `Tab` completes it.
- The version number is shown in the status bar, after the identity badge.
- `/help` lists every command with its arguments.

### Changed
- Every command works both as `/name` in INSERT and as `:name` in COMMAND mode, from one
  shared command table, so `/new`, `/join`, `/sign`, `/copyid`, `/update` and `/quitall`
  (`/qa`) now work typed too.
- `/nick` changes your nickname in every open session.
- `/quit` (`/q`) leaves the current session and quits when none is left open.
- `/colour`, `/notify` and `/netverbose` without an argument show the current setting.
- Password and session-id prompts are plain fields (`Enter` confirms, `Esc` cancels), and
  the draft you were typing comes back afterwards.

## 0.1.0

First versioned release.

- `:update` checks the GitHub releases page, downloads the binary for your platform,
  verifies its SHA-256 against `SHA256SUMS`, and replaces the executable.
- `--version` prints the version number.
