# Enchive : encrypted personal archives

Enchive is a tool to encrypt files to yourself for long-term archival.
It's a focused, simple alternative to more complex solutions such as
GnuPG or encrypted filesystems. Enchive has no external dependencies
and is trivial to build for local use. Portability is emphasized over
performance.

Supported platforms: Linux, BSD, macOS, Windows

The name is a portmanteau of "encrypt" and "archive," pronounced
en'kīv.

Files are secured with ChaCha20, Curve25519, and HMAC-SHA256.

Manual page: [`enchive(1)`](http://nullprogram.com/enchive/)

## Port Notes

Portability? Let's see if we can move a copy to Swift 5.6+?

test passphrase is `winniethepooh`

- first encrypt/decrypt (archive/extract) of enchive archives
- second perform keygen on untrusted boxes
- third keygen derive

