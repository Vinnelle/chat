# Saving settings and keys (`:install`)

`:install`, in the full screen UI, saves your settings, your signing key and the verified keys of
peers (see [Security](security.md#verified-keys)) so they're there next time chat starts. For a key
from a file it saves the file's path instead of the key, and reads the file again each time chat
starts. If the file is gone or holds a different key, the console says so. It asks first, and tells
you what it leaves on disk. The files tell anyone who can read the disk (an admin, malware, a
backup, forensics) that chat is used there. Before that it asks for the save's name, and leaving it
blank picks a random one, like `swift-otter42` (see [More than one save](#more-than-one-save)).

The files are sealed with one passphrase you pick, typed twice, even if there's no signing
key to save. Argon2id (512 MiB, same as for a session) makes a key from it with a salt, and
XChaCha20-Poly1305 seals each file with that key. Each file starts with what Argon2id needs
(its limits and the salt), and nothing else is readable: not your nick, routing or relays, and
not the key's public half, so neither file can be linked to the fingerprint peers know you by.

- `~/.config/chat/saves/NAME/settings` (with `$XDG_CONFIG_HOME/chat` for `~/.config/chat` if that's
  set, and `%LOCALAPPDATA%\chat` on Windows, which a roaming profile doesn't carry), NAME being the
  save's (see [More than one save](#more-than-one-save)): the settings you've changed from the
  defaults. Defaults aren't saved, so if a later version changes one, you get the new one. The Tor
  control password is never saved. Inside the seal it's TOML:

  ```toml
  [network]
  routing = "tor"
  lan = false
  relays = ["wss://relay.primal.net", "wss://nostr.mom"]

  [profile]
  nick = "alice"
  colour = "purple"

  [chat]
  filelimit = "64M"
  notify = "all"

  [rooms]
  1 = ["book club", "K7M2Q9XRT4", "correct horse battery staple", "start"]

  [open]
  1 = ["K7M2Q9XRT4", "correct horse battery staple"]
  2 = ["P3W8C6NHVA", "plum orbit lantern"]
  ```

  The keys are the names `:set` takes: the routing, Tor and relay ones in `[network]`, `nick`,
  `colour` and `autosave` in `[profile]`, and the rest in `[chat]`. A
  switch is `true` or `false`, `port` is a number, `relays` and `bridges` are lists, and the rest
  are strings, written the way `:set` takes them. A key chat can't use is skipped, and the console
  says so. `[rooms]` holds the rooms you `:keep`: each one's label, id and password, and `"start"`
  for one joined as chat starts. `[open]` holds the sessions open with `:set reopen on`: each
  one's id and password. `[ignored]` holds the signing keys you `:ignore`, with the nick each had. The file is padded with zeros to a multiple of 4 KB, so its size says
  little about how many rooms it keeps.
- `~/.config/chat/saves/NAME/key`: your signing key, what kind it is and where it came from.

Only you can open the folder and the files (`0700`, `0600`). Each file is written in full and
then renamed into place, so a crash can't leave half a file. A session's id and password are only
saved for a room you `:keep`, or for each session open with `:set reopen on` (see
[Kept rooms](#kept-rooms)). Peers and files are never saved, and messages only with history on
(see [History](#history)).

`settings` and `key` are the only files chat writes there (and the same two in `~/.config/chat`
itself for the save called `default`, see [More than one save](#more-than-one-save)), and both are
always sealed, as is `verified`. A save locked to the device also has a `device` file, sealed by the
device instead (see [Locking a save to this device](#locking-a-save-to-this-device)). One that needs
a security key has a `securitykey` file, with the key's credential and the save's secret wrapped
under the key's, and one that asks for an authenticator code has an `authenticator` file, sealed
like the rest (see [A security key and an authenticator
app](#a-security-key-and-an-authenticator-app)). Every save also has a `spare` and a `spare-lock`
file, and one that deletes itself after wrong passphrases a `tries` file (see [A shadow passphrase,
and self-destruct](#a-shadow-passphrase-and-self-destruct)). With history on, there's a
`history-...` file for each session it's kept for, sealed too, and with **Keep tor's guards** on, a
`cache` file (see [Routing](routing.md#keeping-tors-guards)). chat never writes your settings in
plain text, as `settings.toml` or anything else. The TOML above only exists inside the sealed file.
If there's a plain text file in that folder, like a `settings.toml`, it didn't come from chat. chat
doesn't read it, update it or delete it, and `:uninstall` leaves it and the folder alone. Delete it
yourself if you don't want it on disk.

On startup chat asks for the passphrase in a box (in the terminal with `--simple` or
`--update`), or reads it from `CHAT_INSTALL_PASSWORD`. One Argon2id run opens both files, and a
wrong passphrase tells you, unlike a native key where a typo quietly makes a different key. It
reads the settings first, so a command line option still overrides it for that run, and it starts on
your sessions instead of the settings page. `--identity` signs with a different key for that
run and leaves the saved one alone. `Esc` starts without what's saved: chat's defaults, on the
settings page, and nothing you change is saved unless `:install` opens a save later in that run
(see below). Since the saved routing might be Tor,
chat won't guess. If what's saved is still sealed, there's no terminal to ask on and no
`--routing`, it won't start, and `--update` won't download.

After that, a setting you change, on the settings page or with `:set`, is kept until chat exits,
and the reply on the bottom row ends in `· not saved (autosave is off)`. So is a key you verify
or forget. `:save` saves them. With `:set autosave on` (saved itself, so it lasts), they're saved
straight away instead and the reply ends in `· saved`; turning it on saves the ones made
meanwhile. chat keeps the key Argon2id made, locked in memory, until it exits, so saving doesn't
need the passphrase or another Argon2id run. Command line options aren't saved. They last for
that run, and what's saved comes back next time. The signing key is
only saved by `:save` or `:install`, with autosave on or off, so a key you're just trying out
isn't kept by accident. If you pick a key later, the console says so, and `:save` seals it under
the same passphrase without asking for it again. `:save`, or `:install` while a save is open,
says the save is already installed and offers to save everything in use to it, command line
options included. It keeps the saved key unless a different one is in use, in which case it
replaces it (and tells you first). With signing off, the saved key stays.

If you pressed `Esc` at the start, so nothing saved is open, `:install` first asks whether to use
what's saved. `y` asks for its passphrase (with more than one save, after you pick one from a list),
and from then on what's saved there is in use, the same as if you'd opened it at the start, and
`:save` (or autosave) saves what you change to it. Settings you changed before that which the save
doesn't have keep their value and are saved to it, and a command line option doesn't undo a setting
you changed. Keys you verified are saved to it too, except ones from a save you uninstalled in that
run: each save keeps its own. `n` makes a new save instead, with a name and a passphrase of its own
(see [More than one save](#more-than-one-save)). If you've forgotten a save's passphrase,
`:uninstall NAME` deletes it. `:uninstall` deletes chat's files, and the folder if nothing else is
in it. Deleting isn't the same as erasing: the disk (a journal, copy-on-write snapshots, an SSD's
spare blocks) and your backups can still have what was in them.

## More than one save

Each save has a name and its own folder, `~/.config/chat/saves/NAME` (the same `settings` and `key`
files), and is sealed with its own passphrase. A name is 1 to 32 letters, digits, `-` and `_`. When
`:install` makes a new save it asks for the name. Leave it blank and chat picks a random one, like
`swift-otter42`, which the box shows before you choose. `:install NAME` saves what's in use as a
separate save called NAME without asking. The save in `~/.config/chat` itself, which earlier
versions made, is called `default`, and typing `default` as the name makes it. The folder names are
readable on disk, so pick names that don't say more than you want them to, or let chat pick one.
Once a save is open, `:save` (or autosave) saves what you change to that one, and `:install` alone
saves to it too, after asking first, as above. `:install NAME` for a save that doesn't exist yet
makes it, with a new passphrase. For one that does, while another save is open, it asks whether to
save what's in use over it, and then asks for that save's passphrase. To use what's saved there as
it is instead, start chat with `--save NAME`. While no save is open, it asks whether to use it, as
above. From then on that save is the one in use. `:uninstall NAME` deletes that save, and
`:uninstall` alone deletes the one in use.

With more than one save, chat lists them when it starts: each one's name, whether it has
settings, a key or both, and when it was last opened or saved. Pick one with `j`/`k` and `Enter`,
and chat asks for that save's passphrase. `Esc` on the passphrase goes back to the list, and `Esc`
on the list starts without any of them. With `--simple` or `--update` the list is printed in the
terminal and you type a number or a name. `--save NAME` skips the list and opens that save.
Without `--save`, `CHAT_INSTALL_PASSWORD` is tried on each save in turn and opens the first one
it fits. A save it doesn't fit doesn't count it as a wrong passphrase, and it never opens a decoy
(see [A shadow passphrase, and self-destruct](#a-shadow-passphrase-and-self-destruct)). With only
one save, there's no list.

## Locking a save to this device

`:set devicelock on` (the **Device lock** row on the settings page) locks a save to the device
it's on. Its key then needs a secret only this device can unseal, as well as the passphrase, so
its files don't open anywhere else: not from a backup, a synced folder, a copy of the disk or a
stolen drive, even with the passphrase. With no save open, turning it on asks to install first:
yes goes through `:install`, which locks the new save as it makes it, or asks to lock the save it
opens. No leaves it off. For the open save, a box says what it means and asks first, then seals it
again. `:set devicelock off`, on this device, seals it with the passphrase alone again. When chat
starts, the list of saves says which ones are locked to a device. Where the device can't lock a
save at all (on Linux without systemd's credential service, below), the row is greyed out, and its
help on the settings page says why.

Ids like the machine id don't help here: anything that can read the save's files can read those
too. What holds the secret is something the device never lets out:

- **Linux**: systemd's credential service (systemd 256 or later). It runs as root and seals the
  secret with the computer's TPM 2.0 and systemd's own key in `/var/lib/systemd/credential.secret`,
  which only root can read, for your user only: your user id and name and the machine id go into
  its key, and it only unseals it for you. You don't need to be in the `tss` group. It binds to no
  PCRs, so firmware, bootloader and kernel updates don't lose it (unless you boot a signed UKI and
  its PCR public key is installed: then systemd binds it to that signed policy too), and from
  systemd 262 on it pins the TPM's storage key, so a chip spliced onto the TPM's bus can't pose as
  it. Without a TPM 2.0, it's systemd's key alone: then root, or anyone with a copy of the whole
  disk, could get past the device part, and only the passphrase would be left.
- **Linux without systemd's credential service** (runit, OpenRC, s6, or systemd before 256): chat
  speaks to the TPM 2.0 itself, through `/dev/tpmrm0`, the kernel's resource manager. The secret
  is sealed under the TPM's storage key, which the TPM makes again from its owner seed each time
  and never lets out, with no PCRs. It crosses the TPM's bus encrypted, in a session salted to that
  key, and every answer's HMAC is checked. The save keeps the key's name, so a cleared TPM, or
  something posing as the TPM, is refused. On a computer Windows set the TPM up on (dual booting),
  the TPM's owner has a password Windows forgot, so the key Windows keeps at `0x81000001` is used
  instead. `/dev/tpmrm0` is usually only open to the `tss` group: join it (as root, `usermod -aG
  tss NAME`) and log in again. Until then, the row is greyed out and says so.
- **Windows**: an RSA key the TPM makes for the save, for your Windows account, which never
  leaves the TPM (the Platform Crypto Provider). Unlocking or uninstalling the save deletes it, so
  copies of the files from while it was locked can't be opened again. Without a TPM, it's DPAPI,
  which ties it to your Windows account on this computer: an administrator, or anyone with a copy
  of the disk and your Windows password, could get past the device part.

A random 32-byte secret is sealed to the device and kept in the save's `device` file. The key the
other files are sealed with is BLAKE2b, keyed with the key Argon2id makes from the passphrase,
over that secret and the save's salt: without both, there's no way to it. Each file's header says
the save is locked to a device, and it's sealed with the file, so changing it to say otherwise
only makes the file unreadable. Opening a locked save asks the device first: anywhere else, no
passphrase is even tried. A save is only locked once the device has unsealed its secret again,
so a lock that can't be opened is never written, and its files are sealed again in an order that
leaves the save openable if chat stops halfway. A save found only part locked when it opens
(chat stopped halfway, or one of its files was swapped for one sealed with the passphrase alone)
is locked to the device again straight away, and the console says so.

Copies made before a save was locked, like old backups, are still sealed with the passphrase
alone. If one could be out there, move to a new passphrase: with the lock on, `:install NEWNAME`
makes a new save, locked too, with a passphrase of its own, and `:uninstall OLDNAME` deletes the
old one.

**There's no way back in from anywhere else.** A locked save is gone for good, and so is a
signing key that's only saved in it, if what the device keeps for it is wiped. That happens if:

- the TPM is cleared: in the firmware settings, from Windows (Clear TPM, in Windows Security), by
  a tool like `tpm2_clear`, or by a firmware update. Some BIOS and TPM firmware updates clear it,
  and a TPM that's part of the CPU (AMD's fTPM, Intel's PTT) is the one most often cleared that way
- the motherboard is replaced, or the CPU where the TPM is part of it, or the firmware is switched
  to another TPM (its own in place of a chip, or the other way round)
- the OS is reinstalled, or Windows is reset. Sealed by the TPM alone (through `/dev/tpmrm0`), a
  save only needs the TPM and its files, so a reinstall doesn't lose it if they come back from a
  backup
- on Linux with systemd's service: systemd's key, `/var/lib/systemd/credential.secret`, is
  deleted, or your user name, your user id or the machine id (`/etc/machine-id`) changes. Some
  privacy setups make a new machine id at every boot, and a save can't be locked there for long
- on Windows: your Windows profile is deleted, or, with DPAPI, an administrator resets your Windows
  password (changing it yourself is fine)
- the save's `device` file is deleted. A backup of the save needs that file too, and only opens on
  this device
- the computer breaks or is lost

Before one of those you can see coming, like a firmware update or a reinstall, `:set devicelock
off` first, and lock it again after. The box that locks a save lists all of this (for a new save,
`:install` shows it before asking for the passphrase), and the console says it again once it's
locked. Keep a key you can't lose somewhere else too. Versions of chat from before the device lock
can't open a locked save at all (they say it's damaged).

## A security key and an authenticator app

`:set securitykey on` (the **Security key** row on the settings page) makes a save need your FIDO2
security key as well as its passphrase, and `:set authenticator on` (the **Authenticator app**
row) makes it ask for the 6-digit code an authenticator app shows. A save can have one, the other,
both or neither, with the device lock or without. Like the device lock, turning one on with no save
open asks to install first: yes goes through `:install`, which sets it up for the new save before it
asks for the passphrase, or asks to set it up for the save it opens. For the open save, a box says
what it means and asks first, then seals it again. The list of saves says which ones need them.

**The security key** is any FIDO2 key with the `hmac-secret` extension, which most have: YubiKey 5,
Nitrokey 3, SoloKey 2, Google Titan, Token2 and others. Registering it takes two touches. The first
makes a credential for chat, of which the key keeps nothing: what it needs to use it again is in
the save's `securitykey` file. The second reads the secret that credential gives for a random salt.
That secret never crosses USB in the clear: for each request chat agrees a key with the security
key (ECDH on P-256, by CTAP's PIN/UV auth protocol 2, or 1 for older keys), and it comes back
encrypted under that. A random 32-byte secret for the save is wrapped under it
(XChaCha20-Poly1305) in the `securitykey` file, and goes into the key the save's files are sealed
with, together with the key Argon2id makes from the passphrase, and the device's secret if it's
locked to the device. Without the security key the passphrase opens nothing, wherever the files
are copied, and a guess at the passphrase can't even be checked. Opening the save asks for a touch
each time, after the passphrase. chat only asks for the key's PIN where the key wants it: a key
that wants it to make a credential gets it when it's registered, and one that wants it for
everything (`alwaysUv`) each time.

On Linux chat speaks CTAP itself, through `/dev/hidraw*`, which udev opens to whoever is at the
screen (systemd's rule for security keys, or libfido2's `70-u2f.rules`). With more than one
security key plugged in, only the one with the save's credential blinks, and one is registered
only while it's the only one plugged in. On Windows, which lets only administrators open a security
key directly, chat asks Windows (`webauthn.dll`), and its own window asks for the touch and any
PIN. Reading `hmac-secret` with a salt of chat's own needs its WebAuthn API version 4, which newer
versions of Windows have: where it's older, the row is greyed out and says so.

**The save is gone for good, with no way back, and so is a signing key only saved in it, if the
security key is lost or broken, if it's reset** (a FIDO reset, from its maker's app or with `ykman
fido reset`, wipes what it needs to give the secret back), **or if the save's `securitykey` file
is deleted** (a backup of the save needs that file too). `:set securitykey off` first, before you
reset the key or stop using it: it seals the save again without one. Turning on "always require
user verification" (`alwaysUv`) on the key after it's registered also changes the secret it gives,
so turn the security key off in chat before that too.

**The authenticator app** is a check chat makes, not a lock on the files. Turning it on shows a QR
code (an `otpauth://` link) and the secret in base32: scan it, or type it into the app, then type
the code the app shows, to be sure it has it. From then on, opening the save asks for the code
after the passphrase (and the touch). A code from 30 seconds before or after is taken too, for a
clock that's a little out, and after a wrong one chat waits a moment before it takes another. The
codes are standard TOTP (RFC 6238: HMAC-SHA1, 6 digits, 30 seconds), so any authenticator app works.

To check them, chat has to keep the secret they come from with the save, sealed in its
`authenticator` file under the same key as the rest. So whoever can open the save's files (with its
passphrase, and the device and the security key if those are on) can make the codes too: it stops
someone who knows your passphrase from opening the save in chat without your phone, but not someone
who copies the files and reads them with a program of their own. The security key and the device
lock protect the files themselves. Each file's header says the save asks for a code, sealed with
the file, so it can't be changed to say it doesn't. Lose the app's entry and chat won't open the
save: keep a copy of the secret somewhere safe, or `:set authenticator off` first.

Turning either on or off seals the save's files again in the same crash-safe order as the device
lock, and a save found part way through a change when it opens is finished with everything any of
its files needs. `CHAT_INSTALL_PASSWORD` gives the passphrase of a save that needs a security key or
a code, and chat still asks for those. With more than one save and no `--save`, it's only tried on
saves that need neither. Versions of chat from before these can't open a save that needs them
(they say it's damaged).

## History

Messages aren't kept unless you turn history on: `:set history on` (the **Keep history** row on the
settings page, under Chat). It needs a save open, since that's where it's kept: each session's
history is sealed with the save's other files, in a `history-...` file named from the session's id
and password, so the name doesn't say which session it is. Joining the same session again (the same
id and password) shows what was kept, above the new messages, under the day each came on. Up to 256
KB of each session's are kept, the oldest going first, written every 30 seconds and when the
session closes. The panic key skips that last write, unless `:set panichistory on`.

Everyone in the session is told while you keep it: they see `[keeps history]` when you join, and a
warning in the chat, and the sidebar and `:peers` say so. Turning it on or off tells them straight
away. You're told the same when someone else keeps one. Versions before 0.5.0 show it as
`[logging chat locally]`. What they keep, and how, is up to their copy of chat: you only have their
word for it, either way.

`:history` says whether this session's is kept, `:history forget` deletes it, and `:history forget
all` deletes every session's in the save. Turning history off keeps what was kept until you forget
it. Only the full-screen UI keeps history, not `--simple`. A room `:move` goes to has a new id and
password, so it gets a history of its own, and the old room's stays as it was.

## Message timer

`:timer 10m` (or `2h`, `1d`: from a minute to a week) asks for messages in this session to go after
that long. Once they're older, chat takes them off the screen and wipes them from memory, pictures
shown with them too, and a history keeps no more than that. It's announced to everyone in the
session the way history is, and every chat that keeps to timers takes the shortest one anyone whose
code you compared asks for: the chat's title says `messages go after 10m`, and the console says who
asked. `:timer` alone says which one is kept to, and `:timer off` stops asking. It's a request: a
modified chat, or a screenshot, can keep anything, and chat says when someone's chat is too old to
keep to it. `--simple` can't take back what it's printed to the terminal.

## Kept rooms

`:keep` keeps the room on screen in the open save: its id and password, under a label you give it
(`:keep book club`) or its id. `:keep LABEL` again changes the label, and `:keep forget` lets it go.
With rooms kept, `Ctrl+J` (or `:join`) lists them by label, without their ids or passwords, and
`Enter` joins one. `s` marks one to be joined as chat starts, `d` forgets one after asking, and
**another room...** at the bottom asks for an id as before. Up to 16 are kept.

They're kept in the sealed `settings` file, as its `[rooms]` table, so no file of their own says the
save keeps any, and the file is padded to a multiple of 4 KB. Anyone who can open the save can join
the rooms it keeps. Since nobody has to remember a kept room's password, a long random one costs
nothing. The decoy keeps none, and `:uninstall` deletes them with the rest. Only the full-screen UI
keeps rooms, not `--simple`.

### Reopening sessions

`:set reopen on` (the **Reopen sessions** row) keeps every session you have open in the open save,
and opens them all again when chat starts, or as soon as a save opens later on. The save follows
what's open: a session you open is added, `:quit` takes one out, and turning the setting off empties
the list. They're kept in the same sealed `settings` file, as its `[open]` table, apart from the
rooms `Ctrl+J` lists. Calls aren't kept, since `:call` finds the day's room again. A session that
can't open again (its port in use, say) stays kept for the next start. With autosave off, nothing is
kept until `:save` saves the setting.

With it on, `Ctrl+C` closes chat without leaving its sessions: each tells its peers it went offline
(`off`) instead of saying bye, and they show `* alice went offline`. Peers on 0.5.1-beta.1 or older
don't read that, so they're sent a bye and show you leaving, as before. `:quitall` still leaves
every session, and empties the list.

## A shadow passphrase, and self-destruct

`:set shadow on` (the **Shadow password** row on the settings page) gives the open save a second
passphrase, for when you're made to open it. Typed in place of the real one, it opens a decoy: a
clean save with chat's defaults, no signing key, verified keys or history, that needs the same
device, security key and code as the real one. The decoy takes the real save's place: the real
save's files are replaced or deleted, and from then on its passphrase opens nothing. The shadow
passphrase can't be the save's own, and `:set shadow off` removes the decoy. Typed on the [lock
screen](security.md#lock-screen), it puts the decoy in the save's place the same way, then panics.

As far as chat can manage, nothing on disk or on screen says whether a save has a decoy:

- Every save has a `spare` file of the same size, with the same header as its other files: the
  decoy, sealed under the shadow passphrase, or random bytes when there's no decoy. Its
  `spare-lock` file, sealed with the rest, says which, and keeps what chat needs to seal the decoy
  again when the save's device lock, security key or code changes, so the decoy always needs what
  the save does.
- Every passphrase typed runs Argon2id twice, once for the save and once for its spare, so the
  real passphrase, the shadow one and a wrong one all take as long.
- A save that opens is written the same way whichever passphrase opened it: its sealed files and
  its spare are written again, so their times don't say which. That's why the list of saves says
  when each was last opened.

What it can't do: deleting isn't erasing. A copy of the folder made before (a backup, a synced
folder, a copy of the disk) or the disk itself can still hold the real save's files, sealed under
the real passphrase, for anyone who later gets that passphrase too. And someone who knows chat has
decoys can wonder whether a save with no key and no verified keys is one.

`:set destroy 3` (or `5` or `10`, the **Self-destruct** row) deletes the save after that many
wrong passphrases in a row, when chat starts or on the lock screen, where the last one panics too.
The right passphrase, or the shadow one, starts the count again. The
count and the limit are in a `tries` file next to the save, not sealed, since chat has to read them
before any passphrase opens anything: anyone who can read the folder sees the limit, and anyone who
can copy or change it can put the count back. So it stops someone guessing at the keyboard, not
someone with a copy of the files. A save locked to the device on Windows can't be opened from a copy
either once it's deleted, since its TPM key goes with it. On Linux the device keeps nothing for a
save itself, so a copy that includes its `device` file still opens on that computer.

Saves made by the betas of 0.5.0 kept a decoy in files only a save with a decoy has. chat still
opens those, and says so when the save opens: `:set shadow off`, then `:set shadow on`, moves the
decoy to the `spare`.
