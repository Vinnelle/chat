# Files and pictures

`:send PATH` offers a file to everyone in the session whose verify code you've compared (and anyone
who joins or gets compared later). `:send` on its own opens a file browser to pick one. Nothing is
sent until someone fetches it. A picture you send shows in your own chat straight away. `:download
N` saves a file in `~/Downloads`, and for a picture (PNG, JPEG or GIF) `:show N` draws it in the
chat under the line that offered it. Pictures from others stay hidden until you ask, and `:hide N`
hides one again. `:cancel N` stops a fetch, or stops offering one of your files.

## What a picture says about you

A phone's photo carries where it was taken, to a few metres, the time to the second, the camera's
make and model and often its serial number, and sometimes a second picture or a whole video after
the image. Screenshots and edited pictures carry text, editing history and times. So a PNG, JPEG or
GIF you send goes without any of that: chat keeps only what drawing it needs (the image data, its
colour profile, and the Orientation alone, so a portrait photo still shows upright), and offers that
copy, from memory, in place of the file. A name a camera or a screenshot tool gave it
(`IMG_20261012_143022.jpg`, `Screenshot 2026-10-12 at 14.30.22.png`, `DSC_0412.JPG`) gives away the
time too, so the picture goes as `photo.jpg` or `image.png` instead. The reply says what was taken
out and whether it was renamed. `:send asis PATH` (or `:send asis` for the file browser) sends a
file exactly as it is.

With **Noise in pictures** on (the default), a baseline JPEG, which most photos are, also gets noise
nobody can see: some of its coefficients move one step. No two copies you send are the same bytes or
pixels, so the same photo sent twice, or to two rooms, doesn't match itself. Progressive JPEGs, PNGs
and GIFs are cleaned without it. What it can't do: it doesn't hide which camera took a photo from
someone who studies its sensor's noise, a JPEG's quantisation tables still hint at the camera or app
that wrote it, and a picture can still be recognised by what's in it. A picture over 64 MB can't be
cleaned, so it's only sent with `asis`. Other files keep whatever they hold: HEIC and AVIF photos,
WebP, TIFF and raw files, videos, PDFs and office documents usually say where, when and with what
they were made, and chat says so when you send one. Convert a photo to JPEG first if that matters.

## Following a transfer

A row under the line that offered a file says what's happening to it: how far a fetch has got and
roughly how long is left, where it was saved, or why it failed. Under one of yours, it says who's
fetching it and who it has gone to in full. The reply to `:download`, `:show`, `:cancel` and
`:send` goes on the bottom bar as well as the console, so you see it with the console hidden.

## The files page

`Ctrl+F` (`f` in NORMAL, or `:files`) lists the files offered in the session, theirs then yours,
newest first, with what each one is doing, and the selected one's details beside the list. `Enter`
shows a picture on a page of its own, as big as the terminal allows (fetching it first if it isn't
here), or saves a file in Downloads. `d` saves in Downloads, `s` in a folder you pick, `v` shows or
hides a picture in the chat, `y` copies where a file was saved and `n` sends one. `x` stops a fetch
or stops offering one of yours, after a box asks, since what's come so far is thrown away. On a
picture's page, `j` / `k` go to the next and previous picture, and `Esc` goes back to the list.

## Downloading

`:download` without a number takes the newest file that isn't saved yet. `:download N FOLDER` saves
in another folder, and `:saveto N` picks the folder in a file browser (`s` saves in the folder
shown). One file comes from each sender at a time: asking for another queues it, and it starts by
itself when the one before it is done. `:cancel N` takes a file off the queue.

## No second fetch

A picture that was shown is kept in memory, so `:download N` saves it straight away and `:show N`
draws it again without fetching it. Asking for a file that's already saved says where it is, as long
as the saved file still matches the offer's SHA-256. With a FOLDER it's copied from there, and a
picture saved earlier is shown from the saved file. `:download N` while a picture is coming to be
shown (or `:show N` while it's coming to be saved) does both once it's here.

## What's on the wire

Files go in the same slots as everything else, in space that would otherwise be empty. With **Fast
file transfers** off, a transfer looks the same as any other time, about 25 KB a minute, so a photo
takes minutes and a big file takes hours. With it on, your slots to the peer you're sending to come
every few milliseconds while it runs. That's seconds instead of minutes, but anyone watching your
network can see a burst about the size of the file (not what's in it). It's the sender's setting
that makes it faster.

## Through the relays

Tor and UDP members only meet on the Nostr relays, where slots are a few seconds apart. Every relay
event is sealed to the same size, so each slot fits two chunks at no extra cost, about 12 KB a
minute. Fast transfers can't burst there, but your slots to that peer come as often as the relays
allow, about twice the normal rate, and the relays can see that. Transfers carry on through rekeys.
A fetch waits up to two minutes if the sender drops, and carries on from where it was if they come
back (with a new verify code, once that's compared again).

## What's kept

Files come in a window of chunks at a time, written in order and hashed, and only kept if the
SHA-256 matches the one in the offer. A file changed after it was offered, or tampered with, is
thrown away. It's written to a new private hidden file in `~/Downloads` (or the folder you picked)
that can't follow a link, then renamed to its real name only if nothing already has that name
(`photo (2).jpg` next to an existing `photo.jpg`). Nothing ever gets overwritten. A picture fetched
to show is never written to disk unless you save it. Its bytes stay in memory (up to 128 MB in all,
the oldest dropped first) and are wiped when the session closes.

## Names

A name from a peer can't be a path, a hidden file, a Windows device (`CON`, `NUL`)
or anything the terminal acts on. Folders, control and right-to-left characters, and
`/ \ : * ? " < > |` are stripped. Nothing chat saves is executable.

## Pictures

Decoded by chat's own PNG, JPEG and GIF readers, on Linux in a child process that can't do anything
but hand the thumbnail back (see [Sandbox](security.md#sandbox-linux)). They check every length,
table and dimension, inflate a PNG to exactly what its header says and no more, and never hold the
full size image: each pixel goes straight into the thumbnail. A JPEG can be baseline or progressive,
and an animated GIF shows its first frame, still. WebP, HEIC, lossless and arithmetic coded JPEGs
and everything else aren't shown, download them instead.

## Size

**File size limit** (8 MB by default) is the biggest file chat fetches without asking. An offer over
it says so, and `:download N anyway` (or `:show N anyway`) fetches it regardless. On the files page
a box asks first, with roughly how long it takes. The max is 1 GB.
