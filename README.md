# chat

An end-to-end encrypted group chat for the terminal, with no server and no accounts. Peers find
each other over the BitTorrent DHT (IPv4 and IPv6) and UDP broadcast on the LAN, then talk
directly. If a NAT gets in the way, chat asks the router to forward a port, and public Nostr
relays can carry the traffic. You can also send everything through Tor instead. Nothing is
written to disk unless you ask for it.

> This README was written by AI.

> Eventually, I will rewrite this myself, when I have more time.

> A big goal for this was to minimise the dependency requitements as much as possible. with this in mind, the src for this is quite heavy, since I had to write much of the tooling myself.

> Also, I am not Terry Davis (god rest his soul), and much of this may not be that good, I have optimised and improved where I can. Pretty much all the code (except for the TUI, because I suck at frontend) is hand written. I have used claude for documentation, review, (some) optimisation, sanity checking, commenting, test writing, and autocompletions where the suggestions were acceptable. Other than that, this is artisanal, organic, vegan, gluten free, etc. C code.

> Thank you for reading.

It's written in C, runs on Linux and Windows, and only links static crypto libraries.

## Security

Messages use a hybrid post-quantum setup:

- **X25519 + ML-KEM-768** for key agreement (classical and post-quantum together)
- **XChaCha20-Poly1305** for encryption
- a **ratchet per message** for forward secrecy

The session **id + password** key both the encryption and the DHT lookup, so you need both to
find the room or read it. A blank password still encrypts.

**Compare verify codes.** The id and password only prove someone is in the room. Any member
could sit between two others and read what they say. When a peer joins, chat shows a verify
code. Compare it with them over something else (in person, a call). It only matches on both
ends if nobody is in the middle. Mark it with `:verify NICK ok`, or `:verify NICK no` if it
didn't match, and then that peer gets nothing. By default, what you send goes to everyone
else whether you've compared or not. **Compare verify codes** on the settings page
(`:set verify required`, `--verify-required`) holds it back instead: nothing you send goes to
a peer until you've marked it `ok`. Until then, their messages show `(code not compared)`, the
sidebar says `compare code`, and the input box tells you your messages aren't going to them
(`:verify NICK` shows the code).

**Verified keys.** If the peer signs with an identity (below), `:verify NICK ok` also keeps
its signing key, with its nick, as verified. When a peer signs a handshake with a verified key,
in this session, another one or (after `:install`) a later run, the code doesn't need comparing
again: the signature covers that handshake's keys. When a peer has the nick of a verified key
but signs with another key, or with none, chat prints a warning in the chat and the console,
and the sidebar shows `key changed`. Their key changed, or someone else is using the nick.
They count as not compared until you compare codes again, and with **Compare verify codes**
set to required nothing you send goes to them. `:verify NICK ok` then replaces the key kept
for that nick. `:verified` lists the keys, with their nicks and fingerprints, and `:verified
forget NICK` (or `all`) removes them. A peer with no signing key has nothing to keep, so its
code is compared again each session.

**Identity signing** is optional, and lets peers check who they're talking to. Pick it under
**Signing identity** on the settings page (or `:set sign`), or with `--identity`:

- `age`: an Ed25519 identity made from a password, with an `age1...` recipient others can
  `age -r` encrypt files to (settings shows it and copies it to the clipboard)
- `pgp`: the same key as PGP. Settings copies the public key for others to `gpg --import`
- `age:KEYFILE`: sign with your own AGE key, as `age-keygen` writes it. Your `age1...` recipient
  doesn't change
- `pgp:KEYFILE`: sign with an unencrypted armored EdDSA secret key exported from gpg

The picker in settings lists **Off**, **AGE** and **PGP**. Each has **Native** (a key made
there), a key file (picked in a file browser, or its path typed) and a pasted key. chat needs
the secret key of your own key because it signs your handshakes with it, and only the secret key
can make a signature. It stays in memory and is never sent: peers get the public key and the
signatures. For a key file, `:install` saves the file's path, not the key. A pasted key is only
written to disk by `:install`, sealed (see [Installing](#installing)).

A **Native** key asks for a password. `--identity age` or `pgp` asks at startup, or reads
`CHAT_SIGN_PASSWORD`. The key comes from Argon2id over that password and the OS install's
machine id (`/etc/machine-id`, or `MachineGuid` on Windows). So the same password on the same
device and OS always gives the same key and fingerprint, and nothing is stored unless you
`:install`.
**Use the same password every time if you want to keep your signing identity.** A different
password, or a typo, gives a different key and peers see a new fingerprint. AGE and PGP give the
same key for the same password. Reinstalling the OS changes the machine id, so it changes the
key too.

The machine id isn't secret, any program on the device can read it, so the password is the
only thing protecting the key. Someone with your machine id can brute force passwords against
the public key you show peers, so use a long one. A blank password gives a random key that only
lasts until chat exits.

`:verify NICK` shows a peer's verify code and identity fingerprint to compare out of band.
Fingerprints and the verify codes in `:peers` are 128 bits, shown in groups of four hex digits.
0.1.9 and older show the first 16 digits of the same codes.

Each peer rekeys every few minutes. It sends its new key over the current encrypted session
first, so a room member in the middle can't swap in their own key at a rekey. If a peer drops
and comes back, chat tells you its verify code changed.

**Modified clients.** Each client sends its peers, over the encrypted session, its version and
the SHA-256 of its own executable. The hash is keyed with both peers' session ids, so a non
release build can't be recognised from one session or peer to the next. Release binaries also
carry a list of that release's binaries, signed with the release key, and send it too. Peers
check the list against the release key built into chat and look for the hash in it. Nothing is
downloaded and nobody else is asked, so the check doesn't tell anyone you met that peer. A peer
whose hash isn't in its release's list, or with no signed list (a build from source, for
example), is marked **modified**. You get a warning after it joins, the sidebar shows
`modified` next to its name, and `:peers` says `modified client`. One that passes shows as
`says official`, because that's only its word.

> This is not perfect as a client can be modified to send the correct SHA and will be marked as unmodified. I am working on a better solution for this

0.1.8 sent its hash without a list. chat has 0.1.8's published hashes built in and checks those
peers against them. 0.1.8 can't read the list, so it shows newer peers' builds as unknown.

Keys, and the conversation on screen, are locked in memory so they don't go to swap, as far as
the system's memory lock limit allows. Core dumps are off, and on Windows a crash ends chat
before Windows Error Reporting can dump its memory. Desktop notifications only say a message
came in, unless **Notification preview** (`:set preview nick` or `message`) is set to show who
sent it, or who and what. Desktops keep notifications (Windows writes them to disk), so it's
off by default. A notification never names the session, since the id is all you need to join
one with a blank password.

> **Note:** the cryptography here has not been independently audited.

## Routing

chat opens on its settings page, with **Routing** at the top. `--routing` presets it, and
`Ctrl+S` or `:set` opens the page again later. Once `:install` has saved your settings, chat
starts straight on your sessions instead.

1. **DHT + Nostr fallback** (recommended). Peers talk directly over UDP.
2. **DHT only.** Same, without relays. Some peers behind strict NATs won't connect, and Tor
   members can't reach you at all.
3. **Tor.** Onion services, plus the Nostr relays reached through Tor so DHT members can still
   meet you. Nothing else goes on the network.

DHT routing uses these, and you can turn each one off:

| Part | What it does | Who sees what |
| --- | --- | --- |
| BitTorrent DHT (IPv4) | finds peers on the internet | DHT nodes see your IP and port next to a lookup key only room members can work out, but anyone who sees it can look it up for the rest of the hour (see below) |
| IPv6 DHT ([BEP 32](https://www.bittorrent.org/beps/bep_0032.html)) | the same on the IPv6 DHT, where there's usually no NAT | as above, with your IPv6 address, which often stays the same for longer than an IPv4 one |
| Router port mapping | asks the router (PCP, NAT-PMP or UPnP-IGD) to forward the session's UDP port, so peers behind NATs that can't be hole punched still get in. Removed when the session ends | your router, which may log it, and any device on the LAN that asks it |
| LAN discovery | an encrypted broadcast beacon on the local network, to a UDP port picked from the room's id and password (49152-65535) | the local network sees something broadcasting, on the same port for every member of the room |
| Nostr relay fallback | public relays carry traffic when UDP can't get through | the relays (see below) |

Direct UDP is preferred. A peer only moves to the relays while UDP to it is quiet, and moves
back as soon as UDP works again. With DHT routing, chat only connects to the relays while it
needs them: before anyone is reached, while a peer is only reachable through them, or while a
peer's UDP has gone quiet. It disconnects a minute after. Tor members only meet DHT members on
the relays, so a room where all the DHT members already reach each other can't be found by a
Tor member. Setting **Nostr relays** to `always` (`:set nostr always`, `--nostr-always`) keeps
them connected.

**What the network sees of UDP.** Everything sent over UDP is masked with a key made from the
session id and password, so to anyone else each datagram is random bytes. There's no ratchet
counter that could follow a peer across addresses, no header on handshake pieces, and nothing
that repeats between packets. Every datagram is 1004 bytes. A session frame fills one, and a
handshake is split into pieces padded to that size. Every datagram to a connected peer goes in
one of that peer's slots, one every 1.5 to 1.9 seconds, whether there's anything to send or
not. Messages, acks, messages passed on to others and re-handshakes all wait for a slot, so the
timing and number of datagrams doesn't show when anyone typed. What still shows: the addresses
and ports, that two addresses are swapping a steady stream of same size datagrams (someone
determined could recognise that as chat), when a session starts and ends, a few seconds of
handshake pieces when someone joins, and a re-handshake about every five minutes. The DHT's own
messages are normal DHT traffic from the same port. 0.1.10 and older sent other sizes, so they
can't reach this version over UDP. They still meet through the Nostr relays, or over Tor.

**What the DHT sees.** Each lookup asks nodes for peers under the hour's lookup key and
announces this session's address under it. Only room members can work out the key, but a node
that sees it can also ask for it for the rest of the hour and get the addresses announced
under it. The key changes every hour, and so does the node id chat uses, so nothing in the DHT
messages links one hour's lookups to the next. The source address still does. Queries say
they're from a read only node (BEP 43). A lookup starts from nodes that answered before, and
only asks the four bootstrap servers (router.bittorrent.com, dht.transmissionbt.com,
router.utorrent.com, dht.libtorrent.org) while it knows fewer than eight.

**What a Nostr relay sees.** Each datagram is one ephemeral event, so relays pass it on without
storing it. Every event is signed with a throwaway key made just for it, has a random ephemeral
kind and a timestamp a few seconds off, and has one tag. The tag changes every ten minutes and
only room members can work it out. The content is always the same size: sender, recipient,
datagram and random padding, sealed together with XChaCha20-Poly1305 under a key from the
session id and password, with a fresh nonce each time. So a relay can't tell which events are
from the same person, who they're for, or what's in them. Each ten minute tag gets its own
connections: a new one to each relay, with a new subscription id and, over Tor, a new circuit,
asking for that tag only. It opens a minute or two before the ten minutes start and closes a
minute or two after they end, to allow for clock differences. A relay still sees the address
each connection comes from (the same one every ten minutes, unless it's a Tor exit), when
events come and go, and the tag, which every member of the room asks for. The events have their
own size and shape, so anyone who can subscribe to a relay can pick out chat's events and count
them per tag. The defaults are `wss://relay.primal.net`, `wss://nostr.mom` and
`wss://relay.nostr.net`. Use `--relay` or the settings page to pick others. A relay that rate
limits gets fewer events. A relay that refuses throwaway keys (web of trust, payment, proof of
work) is only read from.

**Tor** needs tor installed (Arch: `sudo pacman -S tor`, Debian/Ubuntu: `sudo apt install
tor`, Windows: the Tor Expert Bundle) or Tor Browser. There's nothing else to set up. Which tor
chat uses depends on `--tor-launch`, or **Start chat's own tor** in settings:

- **when none is running** (default): chat looks for a tor that's already running first, like
  the system service on 9050/9051 or Tor Browser on 9150/9151, with a control port it can log
  into. It logs in with tor's cookie file if it can read it (SAFECOOKIE only, so tor has to
  prove it read the cookie before chat sends anything), a password from the settings page, or
  no login if tor allows it. A running tor is the better option, since it keeps its entry
  guards between runs and uses any bridges in its torrc. If there isn't one, chat starts its
  own.
- **always**: always chat's own tor, separate from any other. It picks new entry guards every
  run and ignores your torrc, bridges included.
- **never**: only use a tor that's already running.

chat's own tor is whatever `tor` is on `PATH` or in the usual folders, or what you give
`--tor-path`. chat refuses to run one that anyone other than root or you could have replaced.
It runs with an empty config, so nothing in `/etc/tor/torrc` applies. Its SOCKS and control
ports are random ports on 127.0.0.1, and the control port only accepts the cookie in its own
folder. That folder holds its data and log. On Linux it's under `$XDG_RUNTIME_DIR`, which is
only yours and kept in memory. Otherwise it's a new 0700 folder in `/tmp`, or your temp folder
on Windows. chat deletes the folder when it stops tor. If chat crashes, tor notices and quits
within a few seconds, and on Windows a job object ends it straight away. The next run of chat
deletes the folder the crash left behind. A fresh private tor downloads the Tor directory every
time, so it can take a minute or more to connect.

> **Note:** Tor and DHT members of a room can only reach each other through the Nostr
> relays, so both need them on: a DHT member with option 1 (DHT + Nostr fallback), and a
> Tor member with the relays left on, as they are by default. With option 2 (DHT only) or
> `--nonostr` on either side, the room splits in two, and neither half sees the other.

**Tor and DHT members in the same room** can't reach each other over onion services or UDP.
They meet on the Nostr relays. A Tor session connects to the same relays as DHT ones, but only
through Tor's SOCKS port. Each relay gets its own circuit, and the relay's name is resolved at
the exit, so local DNS is never used. Until chat has a tor, it doesn't connect to any relay.
Relays see a Tor exit, never your address, and the events look the same whoever sends them.
Between two Tor members, traffic moves to their onion services as soon as those connect, with
the relays kept as a fallback. Turn the relays off with the **Nostr relays** setting (or
`--nonostr`) and only other Tor members can reach you. chat tells you if nobody answers.

Each session publishes its own onion service, plus one of six room onion services whose keys
come from the session id and password. People joining knock on those to find the room, then
connect to each member's own onion service. They all go away when the session ends. Each
session's streams get their own Tor circuits. In Tor mode chat never sends UDP, never connects
anywhere directly, and never looks up an `.onion` name or a relay's name through DNS.
Connecting takes a minute or two while the onion services get published and found.

Settings only last until chat exits. Like everything else, they aren't written to disk unless
you ask. `:install` saves them, and after that every change is saved (see
[Installing](#installing)).

## Files and pictures

`:send PATH` offers a file to everyone in the session whose verify code you've compared (and
anyone who joins or gets compared later). `:send` on its own opens a file browser to pick one.
Nothing is sent until someone fetches it. `:download N` saves it in `~/Downloads`, and for a
picture (PNG or JPEG) `:show N` draws it in the chat under the line that offered it. Pictures stay
hidden until you ask, and `:hide N` hides one again. While a file is coming in, a row under that
line shows the progress and roughly how long is left. `:files` lists what's been offered, how far
each fetch has got, and where each file was saved. `:cancel N` stops a fetch, or stops offering
one of your files.

- **Downloading.** `:download` without a number takes the newest file that isn't saved yet.
  `:download N FOLDER` saves in another folder, and `:saveto N` picks the folder in a file
  browser (`s` saves in the folder shown). One file comes from each sender at a time: asking for
  another queues it, and it starts by itself when the one before it is done. `:cancel N` takes a
  file off the queue.
- **No second fetch.** A picture that was shown is kept in memory, so `:download N` saves it
  straight away and `:show N` draws it again without fetching it. Asking for a file that's already
  saved says where it is, as long as the saved file still matches the offer's SHA-256. With a
  FOLDER it's copied from there, and a picture saved earlier is shown from the saved file.
  `:download N` while a picture is coming to be shown (or `:show N` while it's coming to be
  saved) does both once it's here.

- **What's on the wire.** Files go in the same slots as everything else, in space that would
  otherwise be empty. With **Fast file transfers** off, a transfer looks the same as any other
  time, about 25 KB a minute, so a photo takes minutes and a big file takes hours. With it on,
  your slots to the peer you're sending to come every few milliseconds while it runs. That's
  seconds instead of minutes, but anyone watching your network can see a burst about the size
  of the file (not what's in it). It's the sender's setting that makes it faster.
- **Through the relays.** Tor and DHT members only meet on the Nostr relays, where slots are a
  few seconds apart. Every relay event is sealed to the same size, so each slot fits two chunks
  at no extra cost, about 12 KB a minute. Fast transfers can't burst there, but your slots to that peer
  come as often as the relays allow, about twice the normal rate, and the relays can see that.
  Transfers carry on through rekeys. A fetch waits up to two minutes if the sender drops, and
  carries on from where it was if they come back (with a new verify code, once that's compared
  again).
- **What's kept.** Files come in a window of chunks at a time, written in order and hashed, and
  only kept if the SHA-256 matches the one in the offer. A file changed after it was offered,
  or tampered with, is thrown away. It's written to a new private hidden file in `~/Downloads`
  (or the folder you picked) that can't follow a link, then renamed to its real name only if
  nothing already has that name (`photo (2).jpg` next to an existing `photo.jpg`). Nothing ever
  gets overwritten. A picture fetched to show is never written to disk unless you save it. Its
  bytes stay in memory (up to 128 MB in all, the oldest dropped first) and are wiped when the
  session closes.
- **Names.** A name from a peer can't be a path, a hidden file, a Windows device (`CON`, `NUL`)
  or anything the terminal acts on. Folders, control and right-to-left characters, and
  `/ \ : * ? " < > |` are stripped. Nothing chat saves is executable.
- **Pictures.** Decoded by chat's own PNG and baseline JPEG readers. They check every length,
  table and dimension, inflate a PNG to exactly what its header says and no more, and never
  hold the full size image: each pixel goes straight into the thumbnail. Progressive JPEGs,
  GIFs and everything else aren't shown, download them instead.
- **Size.** **File size limit** (8 MB by default) is the biggest file chat fetches without
  asking. An offer over it says so, and `:download N anyway` (or `:show N anyway`) fetches it
  regardless. The max is 1 GB.

## Download

Prebuilt Linux and Windows x86_64 binaries are on the
[releases page](https://github.com/Vinnelle/chat/releases), with a `SHA256SUMS` file and its
[minisign](https://jedisct1.github.io/minisign/) signature. Check the signature against
[`minisign.pub`](minisign.pub), then the hashes:

```sh
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c --ignore-missing SHA256SUMS
```

## Installation

I'm not packaging chat on purpose. The point is to leave nothing behind: apart from the
executable, nothing stays on the machine unless you ask for it with `:install` (see
[Installing](#installing)). A package manager would record the install and put files outside
your control, so there are no packages (AUR or anything else).

Put the executable wherever you want. I'd recommend a folder you own that's on your `PATH`, like
`~/.local/bin`, because updating replaces the executable in place and needs write access to its
folder. Some systems already have an unrelated `chat` program (the modem dialer from `ppp`, for
example), so rename it if it clashes:

```sh
install -Dm755 chat-linux-x86_64 ~/.local/bin/chat   # or another name, e.g. ~/.local/bin/e2chat
```

If you put it in a system folder like `/usr/local/bin` or `/usr/bin` instead, you'll probably
need root to update it:

```sh
sudo chat --update
```

This depends on your system, and doesn't matter if you never plan on updating.

I might add opt-in **chat history** later, where the other members of the session are told
you're saving it. It would be off unless you turn it on.

### Installing

`:install`, in the full screen UI, saves your settings, your signing key and the verified keys
of peers (see [Security](#security)) so they're there next time chat starts. For a key from a
file it saves the file's path instead of the key, and reads the file again each time chat
starts. If the file is gone or holds a different key, the console says so. It asks first, and tells you what it leaves on disk. The files tell anyone who can read the
disk (an admin, malware, a backup, forensics) that chat is used there.

The files are sealed with one passphrase you pick, typed twice, even if there's no signing
key to save. Argon2id (512 MiB, same as for a session) makes a key from it with a salt, and
XChaCha20-Poly1305 seals each file with that key. Each file starts with what Argon2id needs
(its limits and the salt), and nothing else is readable: not your nick, routing or relays, and
not the key's public half, so neither file can be linked to the fingerprint peers know you by.

- `~/.config/chat/settings` (`$XDG_CONFIG_HOME/chat` if that's set, `%LOCALAPPDATA%\chat` on
  Windows, which a roaming profile doesn't carry): the settings you've changed from the
  defaults. Defaults aren't saved, so if a later version changes one, you get the new one. The
  Tor control password is never saved. Inside the seal it's TOML:

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
  ```

  The tables are the settings page's sections, and the keys are the names `:set` takes. A
  switch is `true` or `false`, `port` is a number, `relays` is a list, and the rest are strings,
  written the way `:set` takes them. A key chat can't use is skipped, and the console says so.
- `~/.config/chat/key`: your signing key, what kind it is and where it came from.

Only you can open the folder and the files (`0700`, `0600`). Each file is written in full and
then renamed into place, so a crash can't leave half a file. Sessions, their ids and passwords,
messages, peers and files are never saved.

`settings` and `key` are the only files chat writes there (and the same two in `saves/NAME` for
a save made with `:install NAME`, see [More than one save](#more-than-one-save)), and both are always sealed. chat
never writes your settings in plain text, as `settings.toml` or anything else. The TOML above
only exists inside the sealed file. If there's a plain text file in that folder, like a
`settings.toml`, it didn't come from chat. chat doesn't read it, update it or delete it, and
`:uninstall` leaves it and the folder alone. Delete it yourself if you don't want it on disk.

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

After that, any setting you change is saved straight away, on the settings page or with `:set`,
and the reply on the bottom row ends in `· saved`. chat keeps the key Argon2id made, locked in
memory, until it exits, so saving doesn't need the passphrase or another Argon2id run. Command
line options aren't saved. They last for that run, and what's saved comes back next time. The
signing key is only saved by `:install`, so a key you're just trying out isn't kept by
accident. If you pick a key later, the console says so, and `:install` seals it under the same
passphrase without asking for it again. Running `:install` again saves everything in use,
command line options included. It keeps the saved key unless a different one is in use, in
which case it replaces it (and tells you first). With signing off, the saved key stays.

If you pressed `Esc` at the start, so nothing saved is open, `:install` first asks whether to use
what's saved. `y` asks for its passphrase (with more than one save, after you pick one from a
list), and from then on what's saved there is in use, the same as if you'd opened it at the
start, and settings you change are saved to it. Settings you changed before that which the save
doesn't have keep their value and are saved to it, and a command line option doesn't undo a
setting you changed. Keys you verified are saved to it too, except ones from a save you
uninstalled in that run: each save keeps its own. `n` makes a new
save instead, with a name and a passphrase of its own (see
[More than one save](#more-than-one-save)). If you've forgotten a save's passphrase,
`:uninstall NAME` deletes it. `:uninstall` deletes
chat's files, and the folder if nothing else is in it. Deleting isn't the same as erasing: the
disk (a journal, copy-on-write snapshots, an SSD's spare blocks) and your backups can still
have what was in them.

#### More than one save

`:install NAME` saves what's in use as a separate save called NAME, in
`~/.config/chat/saves/NAME` (the same `settings` and `key` files), sealed with its own
passphrase. A name is 1 to 32 letters, digits, `-` and `_`. The save in `~/.config/chat` itself is
called `default`. The folder names are readable on disk, so pick names that don't say more than
you want them to. Once a save is open, settings you change are saved to that one, and `:install`
alone saves to it too, after asking first, as above. `:install NAME` for a save that doesn't exist
yet makes it, with a new passphrase. For one that does, while another save is open, it asks
whether to save what's in use over it, and then asks for that save's passphrase. To use what's
saved there as it is instead, start chat with `--save NAME`. While no save is open, it asks
whether to use it, as above. From then on that save is the one in use. `:uninstall NAME`
deletes that save, and `:uninstall` alone deletes the one in use.

With more than one save, chat lists them when it starts: each one's name, whether it has
settings, a key or both, and when it was last saved. Pick one with `j`/`k` and `Enter`, and chat
asks for that save's passphrase. `Esc` on the passphrase goes back to the list, and `Esc` on the
list starts without any of them. With `--simple` or `--update` the list is printed in the
terminal and you type a number or a name. `--save NAME` skips the list and opens that save.
Without `--save`, `CHAT_INSTALL_PASSWORD` is tried on each save in turn and opens the first one
it fits. With only one save, there's no list.

## Build

You need CMake ≥ 3.15 and a C compiler. CMake fetches and statically builds libsodium
(1.0.20), liboqs (0.16.0, ML-KEM-768 only), Mbed TLS (3.6.7, for the relays' `wss://`
connections) and libsecp256k1 (0.7.1, for Nostr's Schnorr signatures). TLS certificates are
checked against the system root store. Mbed TLS is set up as a TLS client with forward secret
key exchanges only ([`cmake/mbedtls-config.h`](cmake/mbedtls-config.h)), and libsecp256k1 only
keeps what's needed for signing, since chat never verifies Nostr signatures.

```sh
cmake -B build
cmake --build build
./build/chat --nick you
```

### Windows cross-build

`cmake/zig-*` use [zig](https://ziglang.org/) as a cross toolchain (with its bundled
mingw-w64), so libsodium's autotools and liboqs's CMake use the same compiler. With `zig` on
`PATH`:

```sh
cmake -B build-win -DCMAKE_TOOLCHAIN_FILE=cmake/zig-windows.cmake
cmake --build build-win
```

### With just

The [`justfile`](justfile) wraps the commands above:

```sh
just build              # native binary in build/
just build windows      # Windows binary in build-win/ (needs zig)
just run --nick you     # build, then run
just build test         # Linux and Windows binaries in test-builds/<date>-<time>/, offer to run this system's
just build test linux   # the same for one system (or: windows); the other system's needs zig
                        # (a test build says "testing <build id>" over its console, and in --version)
just clean              # remove build directories and test builds
```

Test builds are called `chat-<build id>-<system>-<arch>`, for example
`chat-v0.1.9-3-g1a2b3c4-20260929-141502-linux-x86_64`. The build id is the source it was built
from (`git describe`) and when, in UTC. That's the same as `chat --version` prints, so a copy on
another machine still tells you which build it is.

### Tests

`tests/` runs real sessions against each other over an in-memory network. It covers the
handshake, the verify code gate, verified keys and the warning when one changes, message delivery with a dropped packet, rekeys (and a message
lost right as the peer rekeys), replayed hellos and junk from outside the room, a third peer
joining, that nothing goes over UDP unmasked, that every datagram is one cell sent in a slot no
matter how many messages are sent, and that the DHT queries as a read only node and stops using
the bootstrap servers once it knows enough nodes. It also tests the parsers for what relays,
routers and Tor send, the hourly DHT keys, that key files are only read from regular files, the
PNG and JPEG readers (and what they reject), file names from peers, and files end to end:
offered, saved next to a file with the same name, over the size limit, shown from memory,
changed after being offered (thrown away), sent fast, cancelled and withdrawn. The fuzz targets
(libFuzzer, so clang) cover bencode and DHT replies (IPv4 and IPv6), relay JSON and UPnP gateway
replies, PGP and AGE key import, PNG and JPEG images, text cleaning, file names, the input line,
pictures drawn in the chat, and everything a session receives, including messages from a room
member or a connected peer, and datagrams that unmask to anything at all. GitHub Actions runs
the engine test, and each fuzz target for a minute, on every push and pull request.

```sh
just test               # build and run the engine test
just test -v            # the same, printing every session line and every check before the summary
just fuzz engine 600    # fuzz one target (bencode, json, pgp, text, engine, image) for 600 seconds
```

### Releases

```sh
just dist               # static musl Linux + Windows binaries and SHA256SUMS in dist/ (needs zig)
just release            # release CHANGELOG.md's Unreleased section: tag, dist, sign, publish (needs minisign, gh)
just release 0.2.0      # the same, as a version other than the next patch
```

Changes go under `## Unreleased` at the top of [CHANGELOG.md](CHANGELOG.md). `just release`
renames that heading to the new version, sets the version in `CMakeLists.txt`, commits both as
`Release VERSION` and tags `vVERSION`. It only pushes the branch and tag once `SHA256SUMS` is
signed. If a step fails, run it again and it picks up from the tag.

It signs twice, so minisign asks for the key's password twice. First it signs the list of the
release's binaries (`dist/BUILDS`) and appends it to each binary, so peers can check builds.
Then it signs `SHA256SUMS` of the published binaries, list included, for downloads and
`:update`.

Releases are signed offline with the release key, never in CI, so even if someone takes over
the GitHub account they can't publish an update chat will install. `just keygen` makes the key.
Commit `minisign.pub`, and keep the secret key backed up and off GitHub.

## Usage

```
chat [--nick NAME] [--colour NAME|#HEX] [--identity age|pgp[:KEYFILE]] [--simple]
     [--routing dht+nostr|dht|tor] [--nodht] [--noipv6] [--nolan]
     [--noportmap] [--nonostr] [--nostr-always] [--relay wss://HOST ...]
     [--tor-launch auto|always|never] [--tor-path PATH] [--tor-socks HOST:PORT]
     [--tor-control HOST:PORT] [--verify-required] [--file-limit SIZE]
     [--fast-files]
     [--session ID --port UDP_PORT --peer HOST:PORT ...]
chat --update | --version
```

In a terminal, `chat` opens a full screen UI. The sidebar on the left lists your sessions
(switch with Tab / Shift+Tab), the peers in the selected one and how each is verified, and how
that session reaches them: route, port or tor, relays, port mapping, DHT and traffic. The rest
of the screen is the selected session's chat, with its console above it, and you type in the
box at the bottom.

> NOTE: This TUI was heavily assisted by UI, as I have mentioned across most my projects, I hate, and suck at, UI / Front-End development. If any front-end devs would like to improve the functionality, performance, and/or aesthetic of this, be my guest!

A session with unread messages shows how many next to its name, in yellow with an `@` if one
mentions you. With the sidebar hidden, the chat's title shows how many are new in other
sessions. When you go back to that session, a `N new` line marks where they start, until you
leave or send something. Your nick is highlighted wherever someone mentions it.

It uses the terminal's own colours (foreground, background and the 16 colour palette), so it
matches whatever theme the terminal has, light or dark, and follows it if it changes. Peers'
colours are exact, but chat asks the terminal for its background colour and adjusts any that
wouldn't be readable on it. `NO_COLOR` limits it to bold, faint and reverse.

It starts on the settings page, so routing, nickname, colour, signing identity and the rest are
all set up in one place. **Start chatting** at the bottom (or `Esc`) goes to your sessions.
Nothing goes on the network before that: no tor is looked for or started, and no `--peer` name
is looked up (in Tor mode it never is, since that would go around Tor). Once `:install` has
saved your settings, it starts on your sessions, and `Ctrl+S` opens the page.

| Key | Action |
| --- | --- |
| `Ctrl+N` | create a new session (asks for a password) |
| `Ctrl+J` | join an existing session (id, then password) |
| `Tab` / `Shift+Tab` | next / previous session (`j` / `k` in NORMAL too) |
| `PgUp` / `PgDn` | scroll the chat back / forward (`Ctrl+U` / `Ctrl+D` in NORMAL, `G` the newest) |
| `Ctrl+B` / `Ctrl+O` / `Ctrl+T` | toggle sidebar / console / chat pane (`s` / `c` / `C` in NORMAL) |
| `Ctrl+S` | settings |
| `F1` | every key and command on one page (`?` in NORMAL, and `:help`, too) |
| `Ctrl+C` | quit (every session leaves cleanly first) |

The bottom row is the same on every screen: a chip for where you are (`INSERT`, `NORMAL`,
`COMMAND`, `SETTINGS`, ...), whether you're signing, your nick, the reply to what you just did
(until your next key), and what the keys do there.

The input line is a small vim. It starts in NORMAL (`h`/`l` move, `0`/`$` go to the ends, `x`
deletes, `j`/`k` switch session, `s`/`c`/`C` toggle the sidebar/console/chat). `i`/`a`/`I`/`A`
go to INSERT, where Enter sends, `Ctrl+W` deletes the word before the cursor and `Ctrl+U`
everything before it, and `Esc` goes back to NORMAL. The input box border is the mode's colour,
and the box grows a row at a time as what you type wraps, up to six rows (fewer on a short
terminal). The count under it goes red once a message is over 250 bytes, and `Enter` then
leaves it in the box instead of sending it cut off. Anything chat asks for (a password, a
session id, a new setting value, whether to carry on) comes up in a box over the screen, titled
with what it's for and with its keys on the bottom edge. `Enter` confirms, `Esc` cancels, and
your draft comes back after. Yes/no questions take `y` or `n`.

Typing `@` and the start of a nick shows the rest of the name dimmed, and `Tab` completes it.

`/` on an empty line, in INSERT or NORMAL (or `:` in NORMAL), opens the command line, with a
menu of matching commands. After `set ` it lists the settings and their current values, and
after `set NAME ` the values that setting takes. After a command that takes a nick (`verify `)
it lists online peers whose nick starts with what you've typed, with the rest dimmed like with
`@`. `Up` / `Down` pick from the menu, `Tab` completes, `Enter` runs (a part typed command runs
whatever the menu has picked, so `/se` runs `/set`) and `Esc` goes back. A line starting with
`/` that can't be a command (`/shrug`, `/usr/bin`) turns back into text as you type, and
`Enter` sends it like a normal message. `//` does the same straight away. Anything else is sent
as a message. `:help` opens a page with every key and command, and `Enter` on a command there
puts it on the command line.

| Command | Action |
| --- | --- |
| `:new`, `:join` | create / join a session (same as `Ctrl+N` / `Ctrl+J`) |
| `:quit` (`:q`) | leave this session; quits when none is open |
| `:quitall` (`:qa`) | leave every session and quit |
| `:set [NAME [VALUE]]` | change a setting (see below); on its own, opens the settings page (`Ctrl+S`) |
| `:verify NICK [ok\|no]` | show a peer's verify code and identity fingerprint; `ok` once the code matches theirs, `no` if it doesn't |
| `:verified [forget NICK\|all]` | list the signing keys you verified, with nicks and fingerprints, or remove them |
| `:peers` | who's online, with verify codes and builds |
| `:net` | network report and diagnosis |
| `:port [N]` | show or change this session's UDP port (`0` picks a free one) |
| `:copyid` | copy the session id to the clipboard |
| `:update` | install the latest release |
| `:install [NAME]` | save your settings and signing key on this computer, after telling you what that leaves on disk; with NAME, as a save of that name (see [Installing](#installing)) |
| `:uninstall [NAME]` | delete what `:install` saved (the save in use, or the one called NAME) |
| `:changelog` | what changed in each version (`:news`); built in, so it works offline |
| `:send [PATH]` | offer a file, or pick one in a file browser without PATH (see [Files and pictures](#files-and-pictures)) |
| `:files` | the files offered here, and how each fetch is going |
| `:download [N] [anyway] [FOLDER]` | save file N in `~/Downloads` or FOLDER (`:dl`); the newest file without N; `anyway` if it's over your size limit |
| `:saveto N [anyway]` | pick a folder in a file browser and save file N there |
| `:show N [anyway]`, `:hide N` | draw picture N in the chat where it was offered, or hide it |
| `:cancel N` | stop fetching file N or take it off the queue, or stop offering one of yours |

### Settings

Every setting is a row on the settings page, and applies straight away to every open session
and any you open after. `:set NAME VALUE` sets a row without opening the page, and `:set NAME`
opens the page on that row. The command line menu lists the names after `:set `, and the values
after a name. Under each row's help, the page shows the `:set` command that does the same thing.

| Name | Values |
| --- | --- |
| `routing` | `dht`, `tor` |
| `dht`, `dht6`, `portmap`, `lan` | `on`, `off` |
| `nostr` | `on` (only while needed), `always`, `off` |
| `relays` | up to 6 `wss://` URLs |
| `torlaunch` | `auto`, `always`, `never` |
| `torpath`, `torsocks`, `torcontrol` | a path, `HOST:PORT`, `HOST:PORT` |
| `torpassword` | only on the page, where it's hidden |
| `nick`, `colour` | a name; a colour name or `#RRGGBB` |
| `sign` | `off`, an `age` or `pgp` key made from a password typed on the page, or `age:PATH` / `pgp:PATH` for a key file; a pasted key is picked on the page |
| `verify` | `required` (nothing goes to a peer until you've compared its code), `optional` |
| `filelimit` | the biggest file fetched without `anyway`: `8M`, `500K`, `1G` |
| `fastfiles` | `on` (what you send goes in quick bursts; through the relays, as fast as they allow), `off` (chat's regular slots) |
| `notify` | `all`, `mentions`, `none` |
| `preview` | what a notification shows: `off` (only that a message came), `nick` (who from), `message` (who, and what); never the session |
| `net` | `normal`, `verbose` (every handshake packet, relay and Tor event) |
| `port` | the UDP port for new sessions (`0` picks a free one) |

The settings page, the pages under it (the signing identity picker and the key file browser)
and the help page all use the same keys: `j`/`k` move, `g`/`G` go to the top/bottom, `Tab` /
`Shift+Tab` go to the next / previous section, `Enter` picks, `h`/`l` change a value or go out
of / into a page, `Esc` goes back and `q` closes the page. In the file browser, `~` goes to the
home folder, and in the key file browser `/` types a path instead.

With `--simple`, `:set` only covers `nick`, `colour`, `notify`, `preview` and `net`.

### Updating

`:update` in chat, or `chat --update` from the shell without opening chat, checks the
[latest GitHub release](https://github.com/Vinnelle/chat/releases/latest). If it's newer than
the build you're running, chat checks the release's `SHA256SUMS` has a valid signature from the
release key built into chat, downloads the binary for your platform, checks its SHA-256 against
`SHA256SUMS`, and replaces the executable in place. A release without a valid signature is
refused. Restart chat to run the new version. In chat, `:update` shows each step in a box as it
goes, with a progress bar for the download. Esc hides the box and the update keeps going.
`chat --update` exits with status 1 if the update failed. It needs `curl` (on `PATH` on Linux,
or on Windows the one built into Windows 10+ in `System32`) and write access to the folder the
executable is in.

### Options

Options given here override what `:install` saved, for that run.

| Option | Meaning |
| --- | --- |
| `--nick NAME` | Display name (random `swift-otter42` style name if left out) |
| `--colour NAME\|#HEX` | Display colour (random by default; `--color` works too) |
| `--routing` | `dht+nostr`, `dht` or `tor` (`direct+nostr` and `direct` still work), preset on the settings page (see [Routing](#routing)) |
| `--nodht` | Don't use the BitTorrent DHT (IPv4 and IPv6) |
| `--noipv6` | Don't use the IPv6 DHT |
| `--nolan` | Don't use LAN broadcast discovery |
| `--noportmap` | Don't ask the router to forward a port |
| `--nonostr` | No Nostr relay fallback |
| `--nostr-always` | Stay on the relays all the time, not just while they're needed |
| `--verify-required` | Send nothing to a peer until you've compared its verify code |
| `--file-limit SIZE` | The biggest file fetched without `anyway` (default `8M`, up to `1G`) |
| `--fast-files` | Send files in quick bursts instead of chat's regular slots (through the relays, as fast as they allow) |
| `--relay URL` | A Nostr relay (`wss://...`) to use instead of the defaults; up to 6 |
| `--tor-launch auto\|always\|never` | Which tor Tor mode uses: a running one if there is one, otherwise chat's own (`auto`); always chat's own; or only a running one |
| `--tor-path PATH` | The tor program chat starts (default: `tor` on `PATH` or in the usual folders) |
| `--tor-socks`, `--tor-control` | Where to look for a running tor's SOCKS and control ports (`HOST:PORT`) |
| `--identity ...` | `age` or `pgp` for a key made from a password (asked for, or `CHAT_SIGN_PASSWORD`), or `age:KEYFILE` or `pgp:KEYFILE` for your own (see [Security](#security)); for that run, instead of a key `:install` saved |
| `--save NAME` | Open the save `:install NAME` made, without the list of saves (`default` is the one in `~/.config/chat` itself); if there isn't one, start from the defaults and let `:install` make it (see [Installing](#installing)) |
| `--simple` | Plain `[HH:MM] ...` lines, one session, stdin, `:name` runs a command. Used automatically when stdout isn't a tty |
| `--session ID` | Join a session at startup (with `--port`, `--peer`) |
| `--update` | Install the latest release and exit, without opening chat (see [Updating](#updating)) |
| `--version` | Print the version and exit |

## License

[GPL-3.0-only](LICENSE). Copyright © 2026 finlay@tuta.com.
