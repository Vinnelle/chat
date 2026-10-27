# Security and privacy

How chat protects what you say and who you say it to, and what it can't hide. The threat model, and
how to report a vulnerability, are in [SECURITY.md](../SECURITY.md).

> **Note:** the cryptography here has not been independently audited.

## Encryption

Messages use a hybrid post-quantum setup:

- **X25519 + ML-KEM-768** for key agreement (classical and post-quantum together)
- **XChaCha20-Poly1305** for encryption
- a **ratchet per message** for forward secrecy

## Session ids, passwords and invites

The session **id + password** key both the encryption and the DHT lookup, so you need both to find
the room or read it. The id is often passed around in the open, so the password does the work: the
NEW SESSION box (`Ctrl+N`) starts with a random one, eight words (64 bits), shown so you can pass it
on. Type to use your own instead. A blank password still encrypts, but then the id alone gets anyone
in. `:invite` copies the id and password together as one invite (`chat:ID:PASSWORD:CHECK`), which
the JOIN box (`Ctrl+J`) takes in place of the id. Its check catches an invite that was mistyped or
cut off, which otherwise leaves you alone in a room nobody else is in, since a wrong password can't
be told from an empty room. chat never shows an invite, since it holds the password: it only copies
it.

## Comparing verify codes

The id and password only prove someone is in the room. Any member could sit between two others and
read what they say. When a peer joins, chat shows a verify code. Compare it with them over something
else (in person, a call). It only matches on both ends if nobody is in the middle. Mark it with
`:verify NICK ok`, or `:verify NICK no` if it didn't match, and then that peer gets nothing. By
default, what you send goes to everyone else whether you've compared or not. **Compare verify
codes** on the settings page (`:set verify required`, `--verify-required`) holds it back instead:
nothing you send goes to a peer until you've marked it `ok`. Until then, their messages show `(code
not compared)` (a yellow `?` after their name in the full screen UI), the sidebar says `compare
code`, and the input box tells you your messages aren't going to them (`:verify NICK` shows the
code). Once compared, their messages show `(code compared)` (a green `✓`).

## Verified keys

If the peer signs with an identity (below), `:verify NICK ok` also keeps its signing key, with its
nick, as verified. When a peer signs a handshake with a verified key, in this session, another one
or (after `:install`) a later run, the code doesn't need comparing again: the signature covers that
handshake's keys. When a peer has the nick of a verified key but signs with another key, or with
none, chat prints a warning in the chat and the console, and the sidebar shows `key changed`. Their
key changed, or someone else is using the nick. They count as not compared until you compare codes
again, and with **Compare verify codes** set to required nothing you send goes to them. `:verify
NICK ok` then replaces the key kept for that nick. `:verified` lists the keys, with their nicks and
fingerprints, and `:verified forget NICK` (or `all`) removes them. A peer with no signing key has
nothing to keep, so its code is compared again each session.

## Moving a room

With no server, nobody can be put out of a room, and a password that leaked can't be changed.
`:move` is what you can do instead: it takes the peers whose verify codes you compared to a new
room, with an id and password chat makes up, and leaves everyone else behind. A box says first who'd
come and who wouldn't, and why: a code not compared, codes that differ, or a version too old to
move. The new room goes only to the peers asked along, over their encrypted sessions, and they don't
pass it on. Each of them gets a box naming who else is asked: `y` goes there and leaves the old
room, `n` stays (and can't go later), and `Esc` puts the box away until `:move`. If they haven't
compared your code yet, they're asked once they have. Codes compared in the old room count in the
new one: everyone moving shows the others a key made for the move, over the old room, and signs its
sessions in the new one with it. Nobody typed the new room's id and password, so its console shows
them once: keep them to come back or to invite someone. Those left behind keep the old room and
everything said in it. Nothing tells them where you went, but they see everyone leave together. A
peer that only reaches the room through someone else is left behind too. With `--simple`, `:move`
says who would come, and `:move yes` or `:move no` answers.

## Direct messages

`:msg NICK TEXT` (or `:dm`) sends a message to one peer alone, over your session with them and in
the same slots as everything else, so the network sees nothing new. It's never passed on, so it only
goes to a peer you're connected to directly, and only to one whose chat reads direct messages: an
older one is refused rather than sent it. With **Compare verify codes** required, it waits until
you've compared codes, like any message. Both sides show who it's between (`bob (→ you)`, `alice (→
bob)`), it counts as a mention, and a history keeps it like any message.

## Ignoring someone

`:ignore NICK` hides what a peer says, sends you directly or offers: none of it shows or notifies
you, and a history doesn't keep it. It's only on your screen. Nothing is sent, so they can't tell,
and what they say still goes on to peers who only reach them through you, so ignoring someone
changes nothing for anyone else. If they sign with an identity, their signing key is ignored too, in
every session they turn up in, and kept in the open save like a verified key (saved straight away
with autosave on, or by `:save`). Without one, it lasts for that session. `:ignore NICK off` shows
what they say again, from then on, and `:ignore` lists who's ignored. The sidebar marks them `i`. It
doesn't keep them out: `:move` does that.

## Calls

Once you and a peer have verified each other's signing keys, you don't need to swap an
id and password again: `:call NICK` (a nick `:verified` lists) opens a room only your two keys can
work out, and they `:call` you to open the same one. It shows as `@NICK` in the session list. Its
id and password come from X25519 between the two signing keys (taken the way age takes ssh-ed25519
keys), both keys and the day (UTC), so it's a new room each day. One nobody else is in moves to the
new day's room at midnight, so calls made either side of it, or with clocks a little apart, still
meet. Nobody compares codes there, since the verified key signs the handshake, and nothing goes to
anyone else who turns up, whatever **Compare verify codes** says. Both of you need a signing
identity. Anyone who gets one of the two signing keys later can work out these rooms, past and
future, and see when you meet in them, but can't read what was said: the sessions' keys are
ephemeral. Only the full-screen UI calls, not `--simple`.

## Lock screen

Walk away from chat and anyone can read the screen, scroll back or type as you. `Ctrl+L` (or
`:lock`) locks chat's screen at once, and `:set lock 5m` locks it after five minutes without a key
(or `1m`, `15m`, `30m`). Locked, chat draws nothing but a box for the open save's passphrase. With
no save open, it asks you for a PIN first, which it keeps hashed in memory until it exits, and a
save's passphrase takes over once one is open. Sessions carry on behind the lock: messages arrive,
files keep moving, and notifications show no preview whatever **Notification preview** says. Each
try takes a second or two of Argon2id. Wrong passphrases count toward **Self-destruct**, like wrong
ones when chat starts, and the shadow passphrase panics, leaving the decoy in the save's place (see
[A shadow passphrase, and self-destruct](saves.md#a-shadow-passphrase-and-self-destruct)). The lock
only hides what chat draws from then on: not what was on screen before, a terminal set to copy the
full screen UI into its scrollback, or the window's title, and anything that can read chat's memory
can read past it.

## Panic key

`Ctrl+\` clears the screen, the terminal's own as well, and quits at once, from anywhere in chat,
the lock screen too, without asking. Every session says bye (one kept to
[reopen](saves.md#kept-rooms) goes offline), memory is wiped and chat's own tor stops. Nothing is
saved: not settings, and not the last 30 seconds of a history unless `:set panichistory on`. `:set
panicwipe on` makes it delete the open save too, as `:uninstall` would. Anyone at the keyboard can
press it, so with that on, anyone can delete the save. `:set lockkey` and `:set panickey` pick other
keys (`Ctrl+\` is awkward on some keyboards), or none. In `--simple` there's no lock screen, and the
terminal's `Ctrl+\` panics, unless the panic key is off. Its lines are in the terminal's scrollback,
so that's cleared too.

## Signing identities

Identity signing is optional, and lets peers check who they're talking to. Pick it under
**Signing identity** on the settings page (or `:set sign`), or with `--identity`:

- `age`: an Ed25519 identity made from a password and your nick, with an `age1...` recipient
  others can `age -r` encrypt files to (settings shows it and copies it to the clipboard)
- `pgp`: the same key as PGP. Settings copies the public key for others to `gpg --import`
- `age-nonick`, `pgp-nonick`: the same, made from the password without your nick, as earlier
  versions made them
- `age:KEYFILE`: sign with your own AGE key, as `age-keygen` writes it. Your `age1...` recipient
  doesn't change
- `pgp:KEYFILE`: sign with an unencrypted armored EdDSA secret key exported from gpg

The picker in settings lists **Off**, **AGE** and **PGP**. Each has **Native** (a key made
there), **Native, without nick**, a key file (picked in a file browser, or its path typed) and a pasted key. chat needs
the secret key of your own key because it signs your handshakes with it, and only the secret key
can make a signature. It stays in memory and is never sent: peers get the public key and the
signatures. For a key file, `:install` saves the file's path, not the key. A pasted key is only
written to disk by `:install`, sealed (see [Installing](saves.md)).

A **Native** key asks for a password. `--identity age` or `pgp` asks at startup, or reads
`CHAT_SIGN_PASSWORD`, and makes the key once your nick is settled: `--nick`, the one `:install`
saved, or else a random one. The key comes from Argon2id over that password, your nick and the
OS install's machine id (`/etc/machine-id`, or `MachineGuid` on Windows). So the same password
and nick on the same device and OS always give the same key and fingerprint, and nothing is
stored unless you `:install`.
**Use the same password and nick every time if you want to keep your signing identity.** A
different password or nick, or a typo, gives a different key and peers see a new fingerprint.
The nick counts exactly as shown, so `Alice` and `alice` give different keys. Changing your nick
opens a box that asks for the password, to make the key again with the new nick; `Esc` keeps
the key you have, which the password then only gives back with the old nick. AGE and PGP give
the same key for the same password and nick. Reinstalling the OS changes the machine id, so it
changes the key too.

**Native, without nick** (`age-nonick`, `pgp-nonick`) makes the key from the password and
machine id alone, as earlier versions of chat made every **Native** key. The same password gives
back a key made with one of those, whatever your nick is now, and changing your nick doesn't ask
for anything.

The machine id and your nick aren't secret: any program on the device can read the machine id,
and peers see your nick. So the password is the only thing protecting the key. Someone with your
machine id can brute force passwords against the public key you show peers, so use a long one. A
blank password gives a random key that only lasts until chat exits.

`:exportkey`, or **Export signing key** under it in settings, writes the key in use to a new file
in a folder you pick, after asking. An AGE key comes out as `age-keygen` writes one
(`age-secret-key.txt`), and a PGP key made here armored, as `gpg --export-secret-keys` writes a
key with no passphrase (`pgp-secret-key.asc`). It's the same key, with the same fingerprint, so
peers who verified you still see you as verified when another device picks the file
(`:set sign age:PATH`). That's how a **Native** key, which only comes back from its password (and
nick) on the same device and OS, or a random one, outlives the run. An AGE key of your own comes out the
way age uses it, so its text can differ from your file's while the key is the same. A PGP key
from a file or a paste isn't exported: chat keeps only its secret part, not its user ids and
signatures, so `gpg --export-secret-keys` gives the whole key.
**The file isn't encrypted.** Anyone who reads it can sign as you. Only you can open it, and chat
never writes over a file that's already there. With the sandbox up, it can only go in the folders
in your home that aren't hidden (see [Sandbox](#sandbox-linux)).

## What a verify code looks like

`:verify NICK` shows a peer's verify code and identity fingerprint to compare out of band.
Verify codes and fingerprints are 128 bits. A verify code is shown as 16 words, one for each byte
(from [Bytewords](https://developer.blockchaincommons.com/bytewords/), four letters each, chosen to
be hard to mishear), so it can be read out over a call: `iron when sets good · deli axis road exam ·
...`. The same code follows in groups of four hex digits, which `:peers` and fingerprints use too,
and which is all 0.4.0 and older, and 0.5.0's betas, show. 0.3.1 and older show the first 16 hex
digits.

## Rekeys

Each peer rekeys every few minutes. It sends its new key over the current encrypted session
first, so a room member in the middle can't swap in their own key at a rekey. If a peer drops
and comes back, chat tells you its verify code changed.

## Modified clients

Each client sends its peers, over the encrypted session, its version and the SHA-256 of its own
executable. The hash is keyed with both peers' session ids, so a non release build can't be
recognised from one session or peer to the next. Release binaries also carry a list of that
release's binaries, signed with the release key, and send it too. Peers check the list against the
release key built into chat and look for the hash in it. Nothing is downloaded and nobody else is
asked, so the check doesn't tell anyone you met that peer. A peer whose hash isn't in its release's
list, or with no signed list (a build from source, for example), is marked **modified**. You get a
warning after it joins, the sidebar shows `! modified client` under its name, and `:peers` says
`modified client`. One that passes shows as `says official`, because that's only its word.

> This is not perfect as a client can be modified to send the correct SHA and will be marked as unmodified. I am working on a better solution for this

0.3.0 sent its hash without a list. chat has 0.3.0's published hashes built in and checks those
peers against them. 0.3.0 can't read the list, so it shows newer peers' builds as unknown.

## Memory and notifications

Keys, and the conversation on screen, are locked in memory so they don't go to swap, as far as
the system's memory lock limit allows (on Windows, chat raises its working set so they fit).
Core dumps are off, and on Windows a crash ends chat before Windows Error Reporting can dump its
memory. Desktop notifications only say a message came in, unless **Notification preview**
(`:set preview nick` or `message`) is set to show who sent it, or who and what. Desktops keep
notifications (Windows writes them to disk), so it's off by default. A notification never names
the session, since the id is all you need to join one with a blank password.

## Other programs on the computer

Other programs on the computer are kept from seeing what chat is doing, as far as a program
can keep them out:

- They can't read or change chat's memory, even ones running as you. On Linux, nothing without
  root can attach a debugger to chat, or read its memory, environment, open files or I/O through
  `/proc`. On Windows, chat's process and threads let other programs see that it runs, wait for
  it and end it, and nothing more.
- The command line is blanked once chat has read it, so a session id, `--peer` address, nick or
  save named there doesn't stay in `ps` or Task Manager. It can be read for the moment chat
  starts, and your shell keeps it in its history, so it's safer to type a session id into chat.
- `CHAT_PASSWORD`, `CHAT_INSTALL_PASSWORD` and `CHAT_SIGN_PASSWORD` leave the environment as chat
  starts, so tor and curl never inherit them.
- chat's own tor only lets chat log in to its control port (see [Routing](routing.md#tor)).
- On Linux, notifications go to the desktop over D-Bus from chat itself. notify-send would have
  started a process with their text on its command line, which every user can read.
- A session id or an invite you copy comes off the clipboard again after 30 seconds, or as soon as
  chat quits, locks its screen or panics: clipboard managers keep what they see, and it's easy to
  paste by accident. On Windows chat puts it there itself, marked so clipboard history (`Win+V`),
  the cloud clipboard and clipboard managers leave it alone, and only takes it off if nothing was
  copied since. Elsewhere the terminal puts it there (OSC 52), and chat can't tell whether you
  copied something else since, so that comes off too.
- Reading a save doesn't change its access time (Linux).

## Sandbox (Linux)

chat reads a lot of untrusted input with its own code: pictures from peers, the DHT's bencode from
anyone on the internet, the relays' JSON. In case a bug there gets past the fuzzers, chat puts up a
sandbox as it starts reaching the network (at **Start chatting**, or as `--simple` starts). From
then on chat, and tor, can only write under the folders in your home that aren't hidden or on
`PATH`, chat's own folder and the temporary folders, can only run tor and the transport programs for
bridges (the ones found as it goes up), and are refused the system calls chat never makes (`ptrace`,
`mount`, `bpf`, `io_uring` and the like). A bug can't plant anything that runs later: not in
`.bashrc`, `~/.config/autostart`, `~/.ssh` or `~/.local/bin`. It still runs as you, though, so it
can read what you can and send it out. It's Landlock (Linux 5.13 or later) and seccomp, with no root
needed, and without Landlock chat carries on with seccomp alone.

Pictures from peers get a sandbox of their own on Linux, since they're what a room member can most
easily send chat's own code. Each one shown is decoded in a child process, a copy of chat made for
that picture, which seccomp lets do nothing but allocate memory, write the thumbnail back to chat
and exit: no files, no network, no other process, and nothing it can run. It has a copy of chat's
memory, keys included, but no way to send any of it anywhere but back to chat, which only takes a
thumbnail of the size it asked for. One that tries anything else is killed, and so is one that takes
more than 10 seconds, and the picture isn't shown. That's whether the sandbox is on or not. While
it's up, saving a file anywhere else fails. Until `:install` has made chat's own folder, the folder
it goes in (`~/.config`) stays writable. `:set sandbox off` (from the next start) or `--nosandbox`
(for one run) leave it down.

Nothing chat starts once the sandbox is up can get out of it, so just before it goes up, chat starts
itself again as the updater, a second process that `:update` asks to do the update. The process
list shows it as `chat-updater`, under chat. The updater holds none of chat's data: it's a new
process, without chat's keys, saves, messages or passwords. It has a sandbox of its own, which only
lets it write in the folder the executable is in and run curl, and it still installs only what the
release key signed. All chat can do with it is ask for an update, so a bug in chat can't use it to
get out of the sandbox. The updater ends with chat, once any update it's in the middle of has
finished. `:set updater off` stops it (after the update it's running, if there is one) and doesn't
start it again; `:update` then sends you to `chat --update`. `:set updater on` starts it from the
next start.

## What chat can't hide

Root and administrators can read any program's memory. Anyone on the computer can see that chat is
running, how much CPU time and memory it uses, and its network connections (in Tor mode, those only
reach Tor relays, never a peer). Your terminal holds what's on screen while it isn't locked, and the
desktop's notification service gets each notification. Programs running as you can watch chat's
files change, and can replace chat or tor before you next start them.

## See also

[The protocol](protocol.md) describes what chat sends over the network, byte by byte.
[SECURITY.md](../SECURITY.md) has the threat model (what chat protects, from whom, and where that
stops) and how to report a vulnerability.
