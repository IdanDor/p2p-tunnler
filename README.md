Tunnels packets p2p from two instances of this, using OpenDHT for ip exchange.

Version 0.1.0 was the last version written fully by humans. Starting with
version 0.2.0, AI has been used to write and modify this code.

Each instance of this program can create multiple tunnels (different src ports, and different peer public keys) per single private key, of which their can be multiple, which is a bit over-engineered.
NOTE: only the ip exchange is encrypted and verified, the traffic is NOT verfied or encrypted at all.
NOTE: encrypted address exchange uses the pure-Rust `crypto_box`
Curve25519/XSalsa20-Poly1305 construction, which is wire-compatible with the
legacy libsodium implementation.

I made this to be able to freely run wireguard p2p behind NATs.
Specifically, I inted to run this service in a sandboxed systemd service to connect from my laptop to PC.

Use on your own risk.

Based on the inactive project of [wireguard-p2p](https://github.com/manuels/wireguard-p2p) by manuels.

To compile, I recommend the devshell and nix builders on my other [repository](https://github.com/IdanDor/p2p-tunnler-nix).
