# Packet Portfolio

A personal portfolio drawn like a network packet header, with working network tools and a mini capture-the-flag game built in. Hosted on AWS Amplify Hosting.

No framework, no dependencies, no build step. Only the `site/` folder is published.

## The Lab

- Subnet Lab: an IPv4 subnet calculator that shows the network and host bits.
- IPv4 Packet Dissector: turns header hex into a field diagram and verifies the checksum.
- Live Header Report: requests this site and grades the security headers that come back.
- Live Route Trace: shows which AWS edge location answered and whether it was a cache hit, read from the real response headers.

All four run in the browser. The header report and route trace only check this site.

## The game

Press "Play the mini-CTF" and find five flags. The FLAGS field in the header flips from `00000` to `11111` as you go. Everything is simulated and runs in the browser.

Spoiler warning: this repository contains the answers. The game holds no secrets, and flags are stored as SHA-256 hashes only to avoid printing them in the page script.

## Run locally

Needs Node.js 20 or newer.

```
node tests/serve.mjs
```

Then open http://localhost:4173. This server sends the same headers as `customHttp.yml`, so the game and the Content Security Policy behave as they do when deployed.

## Test

```
node --test tests/ctf.test.mjs tests/lab.test.mjs
```

## Deploy

Connect this repository in the AWS Amplify console. `amplify.yml` publishes `site/` with no build step, and `customHttp.yml` sets the response headers.
