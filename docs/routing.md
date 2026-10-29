# Routing

chat opens on its settings page, with **Routing** at the top. `--routing` presets it, and
`Ctrl+S` or `:set` opens the page again later. Once `:install` has saved your settings, chat
starts straight on your sessions instead.

Two settings decide how a session reaches peers, named the same on the settings page, with
`:set` and on the command line:

- **Routing** (`routing`, `--routing`):
  - `udp` (recommended): peers talk straight to each other over UDP, so they see your IP
    address.
  - `tor`: onion services, which hide your IP address from peers and everyone else. Nothing
    goes on the network except through Tor.
- **Nostr relays** (`nostr`, `--nostr`), the same with either routing:
  - `fallback` (default): public relays carry the traffic while the routing can't, and are where
    UDP and Tor members meet. chat connects to them only while it needs them.
  - `always`: stays connected to them.
  - `off`: no relays. Some peers behind strict NATs won't connect, and members using the other
    routing can't reach you at all.

## UDP routing

UDP routing finds peers with these, and you can turn each one off:

| Part | What it does | Who sees what |
| --- | --- | --- |
| BitTorrent DHT (IPv4) | finds peers on the internet | DHT nodes see your IP and port next to a lookup key only room members can work out, but anyone who sees it can look it up for the rest of the hour (see below) |
| IPv6 DHT ([BEP 32](https://www.bittorrent.org/beps/bep_0032.html)) | the same on the IPv6 DHT, where there's usually no NAT | as above, with your IPv6 address, which often stays the same for longer than an IPv4 one |
| Router port mapping | asks the router (PCP, NAT-PMP or UPnP-IGD) to forward the session's UDP port, so peers behind NATs that can't be hole punched still get in. Removed when the session ends | your router, which may log it, and any device on the LAN that asks it |
| LAN discovery | an encrypted broadcast beacon on the local network, to a UDP port picked from the room's id and password (49152-65535) | the local network sees something broadcasting, on the same port for every member of the room |

UDP is preferred. A peer only moves to the relays while UDP to it is quiet, and moves back as
soon as UDP works again. With the relays on `fallback`, chat only connects to them while it
needs them: before anyone is reached, while a peer is only reachable through them, or while a
peer's own path (UDP, or its onion service) has gone quiet. It disconnects a minute after. Tor
routing does the same. UDP and Tor members only meet on the relays, so a room whose members on
one routing already reach each other can't be found by a member on the other. `:set nostr
always` (`--nostr always`) on their side keeps the relays connected, so they can be.

## What the network sees of UDP

Everything sent over UDP is masked with a key made from the session id and password, so to anyone
else each datagram is random bytes. There's no ratchet counter that could follow a peer across
addresses, no header on handshake pieces, and nothing that repeats between packets. Every datagram
is 1004 bytes. A session frame fills one, and a handshake is split into pieces padded to that size.
Every datagram to a connected peer goes in one of that peer's slots, one every 1.5 to 1.9 seconds,
whether there's anything to send or not. Messages, acks, messages passed on to others and
re-handshakes all wait for a slot, so the timing and number of datagrams doesn't show when anyone
typed. What still shows: the addresses and ports, that two addresses are swapping a steady stream of
same size datagrams (someone determined could recognise that as chat), when a session starts and
ends, a few seconds of handshake pieces when someone joins, and a re-handshake about every five
minutes. The DHT's own messages are normal DHT traffic from the same port. 0.3.1 and older sent
other sizes, so they can't reach this version over UDP. They still meet through the Nostr relays, or
over Tor.

## What the DHT sees

Each lookup asks nodes for peers under the hour's lookup key and announces this session's address
under it. Only room members can work out the key, but a node that sees it can also ask for it for
the rest of the hour and get the addresses announced under it. The key changes every hour, and so
does the node id chat uses, so nothing in the DHT messages links one hour's lookups to the next. The
source address still does. Queries say they're from a read only node (BEP 43). A lookup starts from
nodes that answered before, and only asks the four bootstrap servers (router.bittorrent.com,
dht.transmissionbt.com, router.utorrent.com, dht.libtorrent.org) while it knows fewer than eight.

## What a Nostr relay sees

Each datagram is one ephemeral event, so relays pass it on without storing it. Every event is signed
with a throwaway key made just for it, has a random ephemeral kind and a timestamp a few seconds
off, and has one tag. The tag changes every ten minutes and only room members can work it out. The
content is always the same size: sender, recipient, datagram and random padding, sealed together
with XChaCha20-Poly1305 under a key from the session id and password, with a fresh nonce each time.
So a relay can't tell which events are from the same person, who they're for, or what's in them.
Each ten minute tag gets its own connections: a new one to each relay, with a new subscription id
and, over Tor, a new circuit, asking for that tag only. It opens a minute or two before the ten
minutes start and closes a minute or two after they end, to allow for clock differences. A relay
still sees the address each connection comes from (the same one every ten minutes, unless it's a Tor
exit), when events come and go, and the tag, which every member of the room asks for. The events
have their own size and shape, so anyone who can subscribe to a relay can pick out chat's events and
count them per tag. The defaults are `wss://relay.primal.net`, `wss://relay.snort.social` and
`wss://relay.nostr.net`. Use `--relay` or the settings page to pick others. A relay that rate limits
gets fewer events. A relay that refuses throwaway keys (web of trust, payment, proof of work) is
only read from.

## Tor

Tor routing needs tor installed (Arch: `sudo pacman -S tor`, Debian/Ubuntu: `sudo apt install
tor`, Windows: the Tor Expert Bundle) or Tor Browser. There's nothing else to set up. Which tor
chat uses depends on `--tor-launch`, or **Start chat's own tor** in settings:

- **when none is running** (default): chat looks for a tor that's already running first, like
  the system service on 9050/9051 or Tor Browser on 9150/9151, with a control port it can log
  into. It logs in with tor's cookie file if it can read it (SAFECOOKIE only, so tor has to
  prove it read the cookie before chat sends anything), a password from the settings page, or
  no login if tor allows it. A running tor keeps its entry guards between runs and uses any
  bridges in its torrc. If there isn't one, chat starts its own. With bridges set (below), chat
  always starts its own, since a tor that's already running may not use them.
- **always**: always chat's own tor, separate from any other. It ignores your torrc, bridges
  included, so give it its own (below), and it picks new entry guards every run unless **Keep
  tor's guards** is on (below).
- **never**: only use a tor that's already running.

chat's own tor is whatever `tor` is on `PATH` or in the usual folders, or what you give
`--tor-path`. chat refuses to run one that anyone other than root or you could have replaced.
It runs with an empty config, so nothing in `/etc/tor/torrc` applies. Its SOCKS and control
ports are random ports on 127.0.0.1, and the control port only accepts a password chat makes
when it starts tor. tor only gets the password's hash, and there's no cookie file for another
program to log in with (the control port shows which onion services chat uses). tor has a
private folder for its data and log. On Linux it's under `$XDG_RUNTIME_DIR`, which is
only yours and kept in memory. Otherwise it's a new 0700 folder in `/tmp`, or your temp folder
on Windows. chat deletes the folder when it stops tor. If chat crashes, tor notices and quits
within a few seconds, and on Windows a job object ends it straight away. The next run of chat
deletes the folder the crash left behind. A fresh private tor downloads the Tor directory every
time, so it can take a minute or more to connect.

## Bridges

Bridges are for a network that blocks Tor, or where using it stands out. Get bridge lines from
[bridges.torproject.org](https://bridges.torproject.org) or a friend, and give them to
**Bridges** in settings (`:set bridges LINE; LINE`), separated by `;`. A line can start with
`Bridge`, as in a torrc. With any set, chat starts its own tor with its network off, gives it the
bridges over its control port (`SETCONF`), and only then lets it connect, so it never reaches the
Tor network except through them. If tor won't take them, chat stops it rather than connect
without. The lines never go on tor's command line, which other programs can read, or into a
file. They're sealed in the save with your other settings, and the console only says how many
there are and their transports. obfs4, webtunnel and meek_lite bridges need lyrebird (obfs4proxy
works too, but has no webtunnel), and snowflake ones need snowflake-client. chat looks for them
in **Transport programs** (`:set transports FOLDER`), or else next to tor, where the Tor Expert
Bundle and Tor Browser keep them (a `pluggable_transports` or `PluggableTransports` folder), then
on `PATH` and in the usual folders. Like tor, they have to be programs only root or you can
change, and tor can't run one from a path with a space in it. chat doesn't come with bridge lines
of its own: ones that are handed out to everyone get blocked.

## Keeping tor's guards

chat's own tor picks new entry guards every run, and Tor's guards are meant to last for months: each
new pick is another chance of a malicious one. With a save open, **Keep tor's guards** (`:set
torguards on`) seals tor's `state` file (its guards) and its copy of the directory (`cached-certs`,
`cached-microdesc-consensus` and `cached-microdescs`) into the save when tor stops, in a file called
`cache`. The next run puts them in tor's new private folder before it starts, so it keeps the same
guards and connects in seconds. They're only kept from a tor that connected, so a run that never
does leaves the last ones. It adds tens of MB to the save, and anyone who can open the save sees
which guards you use. The decoy never gets them, and turning it off deletes them.

## UDP and Tor members in the same room

> **Note:** UDP and Tor members of a room can only reach each other through the Nostr
> relays, so both need them on. With `nostr off` on either side, the room splits in two, and
> neither half sees the other.

UDP and Tor members in the same room can't reach each other over onion services or UDP.
They meet on the Nostr relays. A Tor session connects to the same relays as UDP ones, but only
through Tor's SOCKS port. Each relay gets its own circuit, and the relay's name is resolved at
the exit, so local DNS is never used. Until chat has a tor, it doesn't connect to any relay.
Relays see a Tor exit, never your address, and the events look the same whoever sends them.
Between two Tor members, traffic moves to their onion services as soon as those connect, with
the relays kept as a fallback. Turn the relays off (`:set nostr off`, `--nostr off`) and
only other Tor members can reach you. chat tells you if nobody answers.

## Onion services

Each session publishes its own onion service, plus one of six room onion services whose keys
come from the session id and password. People joining knock on those to find the room, then
connect to each member's own onion service. They all go away when the session ends. Each
session's streams get their own Tor circuits. In Tor mode chat never sends UDP, never connects
anywhere directly, and never looks up an `.onion` name or a relay's name through DNS.
Connecting takes a minute or two while the onion services get published and found.

## New circuits

A session's streams to other members' onion services stay open, on the same circuits, for as long as
it runs, and its onion address doesn't change, so anyone who has it can tell whether you're online.
`:newtor` gives every Tor session new ones: it closes its streams and relay connections, which open
again with new SOCKS logins, so on new circuits and through new exits, and each session publishes a
new onion address, sends it to its peers, then removes the old one. Streams peers opened to you stay
as they are, and so do the room's onion services, since the session id and password make their keys,
and tor's entry guards (see **Keeping tor's guards**). Your peers still know it's you, since the
session stays the same. What you send waits a few seconds while the new circuits are built.

## Keeping these settings

Settings only last until chat exits. Like everything else, they aren't written to disk unless
you ask. `:install` saves them, and after that `:save` saves what you change, or turn
`autosave` on to save every change as you make it (see [Installing](saves.md)).
