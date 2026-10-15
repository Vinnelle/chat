# Security

## Reporting a vulnerability

Please email **finlay@tuta.com** with "chat security" in the subject. Don't open a public issue
for something that could be used against people before it's fixed. Include:

- the version (`chat --version`) and the OS;
- what an attacker needs: a position on the network, membership of the room, access to the
  computer, and so on;
- what they get from it;
- how to reproduce it, if you can.

Fixes go into the next release. Older versions don't get fixes, so updating (`chat --update`) is
how a fix reaches you.

> Neither chat's cryptography nor its code has been independently audited.

## Threat model

This section describes what chat is meant to protect, from whom, and where that protection stops.
[PROTOCOL.md](PROTOCOL.md) describes what goes on the wire. The README describes each feature
from a user's side.

### What's protected

- **What's said**: messages, files, nicks and colours.
- **Who is talking to whom, and when**, as far as the network can tell.
- **Who you are**: your IP address, in Tor mode.
- **That you use chat at all**, on the computer you use it on: nothing is written to disk unless
  you ask for it.

### Who it's protected from

The table says what each kind of attacker can and can't do. "Room member" means anyone with the
session id and password, whether they were invited or the password leaked.

| Attacker | Can't | Can |
| --- | --- | --- |
| Someone watching the network (an ISP, public Wi-Fi, a passive global observer) | Read anything. Tell messages from cover traffic: every datagram is 1004 random-looking bytes, and each peer gets one every 1.5 to 1.9 seconds whatever is said. Link a peer's datagrams across address changes. | See the IP addresses and ports, and that two of them swap a steady stream of same-size datagrams, which someone determined could recognise as chat. See when a session starts and ends, a few seconds of handshake when someone joins, and a re-handshake about every five minutes. In Tor mode, see only traffic to Tor relays, or with bridges, only to the bridges, which obfs4, webtunnel and snowflake disguise as other traffic. |
| Someone who can also change traffic | Forge, change or replay frames: each is authenticated, and a chain never goes back. Use a recorded `hi` from another address, since cookies stop that. Change a session's keys by replaying a `kx`: the session's own frames show which one is right. | Drop or delay traffic, so a peer gets cut off or moves to the relays. |
| DHT nodes | Work out which room a lookup is for. Link one hour's lookups to the next by anything in the DHT messages. | See your address next to a lookup key. For the rest of that hour, anyone who has seen the key can look it up and get the addresses announced under it. |
| Nostr relays, and anyone who subscribes to them | Read events, tell who sent one or who it's for, or link two events to the same person. | See the address each connection comes from (a Tor exit in Tor mode), when events come and go, and the tag, which every member asks for. Count chat's events per tag, since their size and shape stand out. |
| Room member | Read what two other members say to each other, unless it sat in the middle of their handshake, which comparing verify codes rules out. Read traffic from before it had the keys: session keys come from ephemeral keys that are wiped. Follow members who `:move` away from it: the new room's id and password only go, over their sessions, to peers whose verify codes the mover compared. | See every room frame: every member's public keys and id, the LAN port and the relays' events with their sender and recipient ids. Learn every member's IP address (outside Tor mode), from `px` and by connecting to them. In Tor mode, learn every member's onion address, and tell whether they're online, even after leaving, until their session ends or `:newtor` gives it a new one. Sit in the middle between two members who **haven't compared verify codes**, reading and changing what they say. Pass on messages with any origin and nick to peers that aren't directly connected to that origin; these show as `nick#id (via relayer)`. Stay in the room for as long as it likes, and see everyone who `:move`s leave together. |
| Someone with a quantum computer, later | Read traffic recorded today: key agreement mixes ML-KEM-768 with X25519. | Break X25519 and the Ed25519 identity signatures. Recognising a peer by its verified key relies on Ed25519, so it doesn't stand up to an attacker with a quantum computer at the time of the handshake. Comparing verify codes still does, since the code comes from the full hybrid key. |
| Other programs on the computer, running as you | Read or change chat's memory, or on Linux its environment and open files. Find a password in the environment of chat, tor or curl, or the command line once chat has read it. Find bridge lines on tor's command line or on disk: they go to chat's own tor over its control port. Find a session id or invite you copied on the clipboard after 30 seconds, or on Windows in clipboard history or the cloud clipboard. | See that chat is running, its CPU time, memory and network connections. Read the command line in the moment chat starts. Watch its files change. Replace chat or tor before you next start them. Read the clipboard in the 30 seconds a copied id or invite is on it, and outside Windows, a clipboard manager can keep it. |
| A bug in chat, set off by a peer, a DHT node or a relay | On Linux 5.13 or later with the sandbox on: write outside the folders in your home that aren't hidden or on PATH, chat's own folder and the temporary folders, so nothing it plants runs later; run anything but tor; trace or read other processes; have the updater install anything but a newer release the release key signed. On Linux, a bug in the picture readers, which decode in a child process of their own: do anything but hand back a thumbnail, so it can't reach a file, the network or the keys. | Read anything you can and send it out, and do anything chat itself can, with the keys it holds. Without Landlock, write anywhere you can. |
| Root, or an administrator | Nothing chat can stop. | Read chat's memory, and everything above. |
| Someone with the disk, or a backup (no save) | Find anything but the executable and the files you downloaded: chat writes nothing else unless you `:install`. Its own tor's folder is deleted when it stops. | See the executable, and that something downloaded those files. |
| Someone with the disk, or a backup (with a save) | Read the save without its passphrase, and also the device or the security key if the save needs them: the bridges, tor's guards, the rooms you `:keep`, the keys you `:ignore` and the sessions kept to reopen are sealed in it too. Tell how many rooms it keeps, since the settings are padded to 4 KB steps. Link the files to your fingerprint. Tell from the files alone whether a save has a decoy. | See that chat is used there, the saves' folder names, which factors each save needs, whether self-destruct is on, how many sessions a save keeps a history for, and from a `cache` file of tens of MB, that it keeps tor's guards. With **Reopen sessions** on, the `settings` file is written as each session opens and closes, so its time says when that last happened. Guess passphrases offline, at the cost of a 512 MiB Argon2id run for each guess, unless the save needs the device or a security key too. |
| Someone at the keyboard while you're away | Read the screen, scroll back or type as you once chat is locked (the lock key, `:lock`, or `:set lock` after a while without a key): it shows nothing but a box for the save's passphrase, or a PIN. Try passphrases there faster than one every second or two, or past the self-destruct limit. | See what's on screen until it locks, and notifications, which only say that a message came while it's locked. End chat with the panic key, which works on the lock screen too, and with `:set panicwipe on`, delete the save with it. |
| Someone who makes you open a save | See what the real save holds, if you type the shadow passphrase: when chat starts it opens the decoy, and on the lock screen it panics with the decoy in the save's place. | Wonder whether a save with no key and no verified keys is a decoy. Find the real save's files in a backup or on the disk, since deleting isn't erasing. |

### Things that are easy to get wrong

- **The id and password are the only way in.** With a blank password, the session id alone is
  enough to join. A notification never names the session for that reason. An invite (`:invite`)
  holds both, so it's as secret as the password: chat only copies it, and never shows it.
- **A weak password can be guessed offline.** Anyone who has captured a single datagram, DHT
  lookup key or relay tag, and knows or guesses the session id, can test passwords against it. Each
  guess costs one Argon2id run (512 MiB). The session id is the salt, so the work for one id
  doesn't help with another. The NEW SESSION box starts with a random password of eight words (64
  bits), which is far out of reach at that cost. One you type instead is only as strong as you make
  it.
- **Compare verify codes.** Being in the room only proves someone knows the password. Without a
  compared code, or a verified signing key, any member could be in the middle. **Compare verify
  codes** (`:set verify required`) holds back everything you send until you have.
- **A leaked password means `:move`.** Nobody can be put out of a room, and anyone with the id and
  password can come back whenever they like. To leave someone behind, or after a leak, `:move` takes
  the peers whose verify codes you compared to a new room and leaves the rest. Those left keep the
  old room, and everything said in it.
- **Messages passed on by others aren't proof of who wrote them.** Only the peer a frame came from
  is authenticated. A message from someone you aren't connected to directly is that peer's word for
  who wrote it, and chat shows it that way.
- **Ignoring is only on your screen.** `:ignore` hides what a peer says from you. It doesn't keep
  them out of the room, stop what they say reaching anyone else, or tell them: `:move` is how to leave
  someone behind.
- **History is the other side's choice.** A peer that says it keeps a history is shown as keeping
  one, but chat can't check what anyone's copy of chat does, or whether they take screenshots.
- **A stolen signing key finds your calls.** Someone who gets your signing key, or a contact's, can
  work out the room of every call between the two of you (`:call`), past and future, and wait there
  posing as the key's owner. They can't read what was said before: the sessions' keys are
  ephemeral.
- **A kept room is as safe as the save.** Anyone who can open the save can join the rooms it keeps
  (`:keep`), with their ids and passwords. The save's passphrase then guards every one of them.
  With **Reopen sessions** on, that's every session you have open, and `Ctrl+C` doesn't leave them:
  your peers see you go offline, and the save can come back to them. `:quit` leaves one for good,
  and `:quitall` every one.
- **A bridge sees you.** Whoever runs a bridge sees your IP address and that you use Tor, as an
  entry guard does, and a bridge that's handed out widely gets found and blocked. With **Keep tor's
  guards** on, the save holds which guards or bridges you use, for anyone who can open it.
- **`:newtor` isn't a new you.** It gives every Tor session new circuits and a new onion address,
  so whoever kept the old address can't tell when you're online. Your peers still know it's you.
  The streams they opened to you keep their circuits, the room's onion services stay the same,
  since the id and password make them, and so do tor's entry guards: changing those often would
  make you easier to find, not harder.
- **A message timer is a request.** `:timer` wipes messages from your chat, and asks everyone else's
  to do the same, but a modified chat, a screenshot or a camera can keep anything, and `--simple`
  can't take back what it printed.
- **"Modified client" is a hint, not a check.** A client says which build it runs, and chat checks
  that against the signed list of release binaries. A modified client can still send a release
  binary's hash.
- **Only pictures are cleaned.** A PNG, JPEG or GIF goes without its location, camera details,
  times, text and anything tucked in with it, and a JPEG gets noise so no two copies match. Every
  other file goes as it is: HEIC, raw photos, videos, PDFs and office documents usually say where,
  when and with what they were made. The noise doesn't stop someone recognising a picture by what's
  in it, or linking photos to one camera by its sensor's noise.
- **Deleting isn't erasing.** `:uninstall`, self-destruct, the panic key with `:set panicwipe on`
  and a decoy taking a save's place delete files. A journal, a copy-on-write snapshot, an SSD's
  spare blocks or a backup can still hold them. Only a save locked to a Windows computer's TPM is
  gone once deleted, since its TPM key goes with it.
- **The self-destruct count isn't sealed.** chat has to read the count before any passphrase
  opens anything. Anyone who can read the folder sees the limit, and anyone who can copy or change
  the folder can put the count back. It stops someone guessing at the keyboard, not someone with a
  copy of the files.
- **The lock screen only covers chat.** It hides what chat draws from the moment it locks: not what
  was on screen before, a terminal that copies the full screen UI into its scrollback, or the
  window's title. Anything that can read chat's memory can read past it. The panic key works on it,
  so anyone at the keyboard can end chat, and with `:set panicwipe on`, delete the save.

### Forward secrecy

- **Chains move forward.** Each frame's key comes from a chain that steps forward with a hash, and
  old chain keys are wiped. Someone who gets a chain's current state can't read the frames sent
  before it.
- **Rekeys replace the keys.** Every five minutes each member makes new X25519 and ML-KEM keys and
  re-handshakes. Someone who got a session's keys and only watches loses access at the next rekey.
  Someone who can also change traffic could use those keys to take part in the rekey.
- **The password doesn't open old traffic.** Learning the id and password later only opens the room
  frames: the handshakes and the beacons. The conversations need the ephemeral keys, which are
  gone.

### Updates and releases

- **Releases.** The release binaries are built from the tagged commit with zig, against
  dependencies pinned by hash. `SHA256SUMS` is signed with minisign, offline, so someone who takes
  over the GitHub account can't publish an update that chat installs.
- **Updates.** `chat --update` checks that signature against the release key built into chat. The
  signed comment has to name the release being installed, so an older release's signature can't be
  passed off as a newer one's.
- **Over Tor.** In Tor mode, the update check and the download go through Tor.
- **A backup key.** A build made with `minisign-backup.pub` also takes a release signed by the backup
  key, kept offline apart from the release key. If the release key is lost, the backup signs the
  next release; if it's stolen, that release also stops taking the stolen key. Builds older than
  that release still take a stolen key until they update, and a thief who has both keys has
  everything.

### Out of scope

chat can't protect against any of these:

- a compromised operating system, terminal or desktop;
- the other people in the room;
- Tor's own limits: an adversary who can watch both ends of a circuit can match traffic up.
