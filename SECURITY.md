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
| Someone watching the network (an ISP, public Wi-Fi, a passive global observer) | Read anything. Tell messages from cover traffic: every datagram is 1004 random-looking bytes, and each peer gets one every 1.5 to 1.9 seconds whatever is said. Link a peer's datagrams across address changes. | See the IP addresses and ports, and that two of them swap a steady stream of same-size datagrams, which someone determined could recognise as chat. See when a session starts and ends, a few seconds of handshake when someone joins, and a re-handshake about every five minutes. In Tor mode, see only traffic to Tor relays. |
| Someone who can also change traffic | Forge, change or replay frames: each is authenticated, and a chain never goes back. Use a recorded `hi` from another address, since cookies stop that. Change a session's keys by replaying a `kx`: the session's own frames show which one is right. | Drop or delay traffic, so a peer gets cut off or moves to the relays. |
| DHT nodes | Work out which room a lookup is for. Link one hour's lookups to the next by anything in the DHT messages. | See your address next to a lookup key. For the rest of that hour, anyone who has seen the key can look it up and get the addresses announced under it. |
| Nostr relays, and anyone who subscribes to them | Read events, tell who sent one or who it's for, or link two events to the same person. | See the address each connection comes from (a Tor exit in Tor mode), when events come and go, and the tag, which every member asks for. Count chat's events per tag, since their size and shape stand out. |
| Room member | Read what two other members say to each other, unless it sat in the middle of their handshake, which comparing verify codes rules out. Read traffic from before it had the keys: session keys come from ephemeral keys that are wiped. | See every room frame: every member's public keys and id, the LAN port and the relays' events with their sender and recipient ids. Learn every member's IP address (outside Tor mode), from `px` and by connecting to them. Sit in the middle between two members who **haven't compared verify codes**, reading and changing what they say. Pass on messages with any origin and nick to peers that aren't directly connected to that origin; these show as `nick#id (via relayer)`. |
| Someone with a quantum computer, later | Read traffic recorded today: key agreement mixes ML-KEM-768 with X25519. | Break X25519 and the Ed25519 identity signatures. Recognising a peer by its verified key relies on Ed25519, so it doesn't stand up to an attacker with a quantum computer at the time of the handshake. Comparing verify codes still does, since the code comes from the full hybrid key. |
| Other programs on the computer, running as you | Read or change chat's memory, or on Linux its environment and open files. Find a password in the environment of chat, tor or curl, or the command line once chat has read it. | See that chat is running, its CPU time, memory and network connections. Read the command line in the moment chat starts. Watch its files change. Replace chat or tor before you next start them. |
| Root, or an administrator | Nothing chat can stop. | Read chat's memory, and everything above. |
| Someone with the disk, or a backup (no save) | Find anything but the executable and the files you downloaded: chat writes nothing else unless you `:install`. Its own tor's folder is deleted when it stops. | See the executable, and that something downloaded those files. |
| Someone with the disk, or a backup (with a save) | Read the save without its passphrase, and also the device or the security key if the save needs them. Link the files to your fingerprint. Tell from the files alone whether a save has a decoy. | See that chat is used there, the saves' folder names, which factors each save needs, whether self-destruct is on, and how many sessions a save keeps a history for. Guess passphrases offline, at the cost of a 512 MiB Argon2id run for each guess, unless the save needs the device or a security key too. |
| Someone who makes you open a save | See what the real save holds, if you type the shadow passphrase. | Wonder whether a save with no key and no verified keys is a decoy. Find the real save's files in a backup or on the disk, since deleting isn't erasing. |

### Things that are easy to get wrong

- **The id and password are the only way in.** With a blank password, the session id alone is
  enough to join. A notification never names the session for that reason.
- **A weak password can be guessed offline.** Anyone who has captured a single datagram, DHT
  lookup key or relay tag, and knows or guesses the session id, can test passwords against it. Each
  guess costs one Argon2id run (512 MiB). The session id is the salt, so the work for one id
  doesn't help with another.
- **Compare verify codes.** Being in the room only proves someone knows the password. Without a
  compared code, or a verified signing key, any member could be in the middle. **Compare verify
  codes** (`:set verify required`) holds back everything you send until you have.
- **Messages passed on by others aren't proof of who wrote them.** Only the peer a frame came from
  is authenticated. A message from someone you aren't connected to directly is that peer's word for
  who wrote it, and chat shows it that way.
- **History is the other side's choice.** A peer that says it keeps a history is shown as keeping
  one, but chat can't check what anyone's copy of chat does, or whether they take screenshots.
- **"Modified client" is a hint, not a check.** A client says which build it runs, and chat checks
  that against the signed list of release binaries. A modified client can still send a release
  binary's hash.
- **Deleting isn't erasing.** `:uninstall`, self-destruct and a decoy taking a save's place delete
  files. A journal, a copy-on-write snapshot, an SSD's spare blocks or a backup can still hold
  them. Only a save locked to a Windows computer's TPM is gone once deleted, since its TPM key goes
  with it.
- **The self-destruct count isn't sealed.** chat has to read the count before any passphrase
  opens anything. Anyone who can read the folder sees the limit, and anyone who can copy or change
  the folder can put the count back. It stops someone guessing at the keyboard, not someone with a
  copy of the files.

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

### Out of scope

chat can't protect against any of these:

- a compromised operating system, terminal or desktop;
- the other people in the room;
- Tor's own limits: an adversary who can watch both ends of a circuit can match traffic up.
