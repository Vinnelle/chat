# Releasing

```sh
just dist               # static musl Linux + Windows binaries and SHA256SUMS in dist/ (needs zig)
just release patch      # release CHANGELOG.md's Unreleased section as the next patch, 0.5.0 -> 0.5.1: tag, dist, sign, publish (needs minisign, gh)
just release minor      # the same, as the next minor, 0.5.0 -> 0.6.0
just release major      # the same, as the next major, 0.5.0 -> 1.0.0
just release            # the same, as the version in CMakeLists.txt (the betas' own), or the patch after it
just release 1.0.0      # the same, as any other version
just release beta       # release the Unreleased section as the next beta of that version, e.g. v0.5.1-beta.2
just release beta minor # the same, as a beta of the next minor, e.g. v0.6.0-beta.1 (patch, major or a version too)
just reproduce 0.5.1    # build release 0.5.1 again from its tag (checked out) and compare it with what GitHub has
```

## Versions and the changelog

Changes go under `## Unreleased` at the top of [CHANGELOG.md](../CHANGELOG.md). `just release`
renames that heading to the new version, sets the version in `CMakeLists.txt`, commits both as
`Release VERSION` and tags `vVERSION`. `patch`, `minor` and `major` count on from the last
release published on GitHub. It only pushes the branch and tag once `SHA256SUMS` is
signed. If a step fails, run the same again and it picks up from the tag.

## Betas

`just release beta` is for testing builds. It does the same, but as `VERSION-beta.N`, N counting up
from 1: the heading becomes `## 0.5.0-beta.1`, `CMakeLists.txt` gets `0.5.0` and `CHAT_PRERELEASE`
`-beta.1`, and the release on GitHub is a pre-release. `:update` only installs one with `betas` on
(`:set betas on`, or `--betas`), so testers turn that on or download a beta themselves, and
`:update` takes them on to `0.5.0` once it's out. `just release` then folds the Unreleased section
and every beta's since the last release into one `## 0.5.0`: oldest first, each `###` heading once.
Betas of another version are folded in too, so `just release minor` can finish a cycle of `0.5.1`
betas as `0.6.0`. It keeps every line, so if a later beta fixed something an earlier one added, tidy
those sections first. Once the release is published, it deletes the GitHub releases of every beta up
to it, keeping their tags.

## Signing

It signs twice, so minisign asks for the key's password twice. First it signs the list of the
release's binaries (`dist/BUILDS`) and appends it to each binary, so peers can check builds.
Then it signs `SHA256SUMS` of the published binaries, list included, for downloads and
`:update`.

Releases are signed offline with the release key, never in CI, so even if someone takes over
the GitHub account they can't publish an update chat will install. `just keygen` makes the key.
Commit `keys/minisign.pub`, and keep the secret key backed up and off GitHub.

## Reproducible builds

`just dist` stamps a release with the time of its commit, not when it was built
(`SOURCE_DATE_EPOCH`), and its binaries don't name the folders they were built in, so the same tag
built with the same zig (0.16.0) should give the same bytes on any computer. When a release is
published, GitHub Actions builds it again from the tag and compares its binaries with the published
ones, leaving out the list of builds each one ends with. `just reproduce VERSION`, with the tag
checked out, does the same on your own computer, so you can check that what you download is what the
source builds without trusting the computer it was built on, or GitHub.

## The backup key

`just keygen backup` makes a second key, the backup, in `keys/minisign-backup.pub` and
`~/.minisign/chat-release-backup.key` (or `CHAT_BACKUP_SIGNING_KEY`). Builds made with it take a
release signed by either key, so updates don't end with a lost or stolen release key. Keep its
secret key apart from the other one's, so one lost drive or one break-in can't take both, and only
use it once the release key is gone: sign the next release with it
(`CHAT_SIGNING_KEY=~/.minisign/chat-release-backup.key just release`), and in that release make the
backup the release key (`keys/minisign-backup.pub` becomes `keys/minisign.pub`) and make a new
backup. Builds from then on no longer take the old key. Builds from before still do until they
update, which is why a stolen key means releasing straight away.
