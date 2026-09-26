# Changelog

## 0.1.5

### Security
- `/peers` could overflow a stack buffer once about 25 peers were online.
- A room member could make a message appear to come from someone else. A message now shows
  the nick of the peer that sent it. A message passed on for a peer you aren't connected to
  shows as `nick (via relayer)`. A passed-on copy of a message from a peer you are connected
  to is ignored, because that peer's own copy arrives directly.
- Nicks can no longer contain `(`, `)`, `#`, `:` or `@`, so a nick can't fake "(verified)",
  "(you)" or an id. The sidebar shortens a long nick instead of hiding a peer's status.
- chat warns when a peer's signing identity changes, disappears or stops verifying after a
  re-handshake.
- Peer addresses shared by other peers must be IP addresses. Before, a room member could
  make everyone look up any hostname.
- The PGP key browser hides file names that contain terminal control characters.
- On Windows, `/update` runs `curl.exe` from `System32` only. Before, a `curl.exe` in the
  same folder as `chat.exe` or in the current folder would run instead.
- `/update` makes curl ignore `.curlrc`.
- The peer verify code is 16 hex digits instead of 8. The first 8 still match the code that
  older versions show.
- Hardening against outsiders who replay recorded packets or send junk: re-handshakes with
  new keys, or from a new address mid-handshake, must answer a cookie first. A replayed
  `kx` can no longer lock in bad keys. Junk packets from unknown addresses cost less CPU.
- Releases are signed. `/update` and `--update` install a release only if its `SHA256SUMS`
  carries a valid minisign signature from the release key built into chat, made for that
  release's tag. Control of the GitHub account alone is no longer enough to push an update.
- Before a peer rekeys, it announces its new key over the current session. A new key that a
  peer never announced is refused, so a room member between two peers can't swap in its own
  key at a rekey. This works between peers that both run this version.
- When a peer drops and comes back, chat says if its verify code changed.
- Nicks that look alike (case, `l`/`I`/`1`, `0`/`O`, Cyrillic or Greek letters, fullwidth
  forms) show with `#` and the peer's id. Invisible characters are removed from nicks.
- Candidate addresses from the DHT and from other peers are rate-limited, at most 4 per
  host, so chat can't be used to flood an address with handshake traffic.
- `--simple` without `--session` on a non-terminal starts a new random session instead of
  joining the fixed `lobby` session, which anyone could join.

### Changed
- `/peers` prints one line per peer.
- Releases are built and published with `just release`. CI builds every push but no longer
  publishes releases.

## 0.1.4

### Added
- `--update` installs the latest release from the shell and exits, without opening chat.
  It exits with status 1 if the update fails, so `sudo chat --update` works for a copy
  in a system folder.

### Changed
- The Linux release binary is statically linked against musl, so it runs on any x86_64
  Linux distribution without depending on the system's glibc version.
- Building with [just](https://github.com/casey/just) is supported: `just build`,
  `just run`, and `just dist` for release binaries.
- chat is deliberately not packaged, to leave no trace beyond the executable. The README
  explains where to keep it so updates keep working.

## 0.1.3

### Added
- `/port [N]` shows this session's UDP port, or moves the session to port `N` without
  leaving it (`0` picks a free one). Connected peers follow the new port automatically.

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
