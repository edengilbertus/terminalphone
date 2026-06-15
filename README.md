# TerminalPhone

Encrypted push-to-talk voice communication over Tor hidden services.

TerminalPhone is a single, self-contained Bash script that provides anonymous, end-to-end encrypted voice and text communication between two or more parties over the Tor network. It operates as a walkie-talkie: you record a voice message, and it is compressed, encrypted, and transmitted to the remote party as a single unit. You can also send encrypted text messages during a call. No server infrastructure, no accounts, no phone numbers. Your Tor hidden service `.onion` address is your identity.

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Linux](#linux)
  - [macOS](#macos)
  - [Termux (Android)](#termux-android)
- [Quick Start](#quick-start)
- [Usage](#usage)
  - [Menu Options](#menu-options)
  - [In-Call Controls](#in-call-controls)
  - [CLI Mode](#cli-mode)
- [How It Works](#how-it-works)
- [Security Model](#security-model)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Features

- **Walkie-Talkie Voice Messaging** -- Record a complete voice message and transmit it on release. No live streaming, no clipping.
- **In-Call Encrypted Chat** -- Send and receive encrypted text messages during a call. Press `T` to type a message.
- **Caller ID** -- Both parties automatically exchange `.onion` addresses on connect. The remote address is displayed in the call header.
- **Auto-Hangup Detection** -- When one party hangs up, the other is notified immediately and the call ends automatically.
- **Configurable Cipher** -- Choose from 21 curated ciphers ranked by strength (256-bit → 128-bit). Includes AES, ChaCha20, Camellia, and ARIA families. Weak ciphers (DES, RC4, ECB modes) are excluded.
- **Live Cipher Negotiation** -- Both parties exchange cipher information on connect. The call header shows both local and remote ciphers with green (match) or red (mismatch) indicators, updated in real time.
- **Mid-Call Settings** -- Press `S` during a call to access settings. Change your cipher on the fly; the remote party's display updates automatically.
- **Snowflake Bridge Info** -- When using Snowflake for censorship circumvention, the call page displays the bridge descriptor name, fingerprint, and transport connection status parsed from Tor's logs.
- **Auto-Listen** -- When enabled, a background listener starts automatically when Tor boots. Incoming calls are detected and accepted from the main menu without needing to manually select "Listen for calls". After a call ends, the listener restarts.
- **Configurable PTT Key** -- Change the push-to-talk key from the default spacebar to any key via the Settings menu.
- **Message Stats** -- The call screen displays the encrypted payload size for sent and received messages, updated in-place.
- **Remote PTT Status** -- The call screen shows a static indicator for the remote party's state: "Idle" (green) or "● Recording" (red). Resets immediately when audio data arrives, before playback begins.
- **PTT Chime** -- Optional notification sound when the remote party starts recording. Five built-in presets (tone, double, chirp, ding, click) generated with sox, plus the ability to record a custom 2-second chime. Configurable via Settings.
- **Connecting Animation** -- When calling a remote address, a cycling animation plays until the call interface loads.
- **Voice Changer** -- Apply voice effects to outgoing audio. Includes 6 presets (deep, high, robot, echo, whisper) and a fully configurable custom mode with pitch shift, overdrive, flanger, echo, highpass filter, and tremolo. Effects are processed using sox before Opus encoding.
- **Volume PTT (Termux)** -- Experimental mode that lets you double-tap the Volume Down button to toggle recording, even when Termux is in the background. Requires `jq` (installed on demand). Volume is automatically restored after each trigger.
- **Tor Hidden Service** -- Each instance runs its own Tor hidden service. Your `.onion` address serves as a permanent, routable endpoint. No port forwarding or public IP required.
- **End-to-End Encryption** -- All audio and text is encrypted using a configurable cipher (default: AES-256-CBC) with PBKDF2 key derivation from a pre-shared secret before entering the Tor network.
- **Passphrase-Protected Secret** -- The shared secret can be encrypted at rest using a user-chosen passphrase (AES-256-CBC, 100,000 PBKDF2 iterations). Existing plaintext secrets are automatically detected with an offer to migrate.
- **Low Bandwidth** -- Opus codec at 16kbps, 8kHz mono. A typical 10-second voice message is under 20KB, well within Tor's capacity.
- **QR Code Sharing** -- Option 3 can display your `.onion` address as a scannable QR code in the terminal. If `qrencode` is not installed, you are prompted to install it. The QR code renders on the alternate screen buffer and is destroyed when dismissed. A note warns that some QR scanners auto-prepend `http://`; this prefix is automatically stripped when dialing.
- **Opaque Temporary Files** -- All temp files use generic `.tmp` extensions and random hex identifiers. No file type or timing metadata is leaked to the filesystem.
- **Circuit Hop Display** -- Opt-in display of your Tor circuit path during calls, showing relay names and full country names. Auto-refreshes every 60 seconds. Configurable via Settings → Tor Settings.
- **Exclude Countries** -- Exclude specific countries from your Tor circuits. Presets for Five Eyes, Nine Eyes, and Fourteen Eyes alliances, or enter custom country codes. Uses `ExcludeNodes` with `StrictNodes` in the torrc.
- **HMAC Protocol Authentication** -- Optional HMAC-SHA256 signing of all protocol messages (voice, text, control signals) using the shared secret. A random nonce is included per message, and seen nonces are tracked to reject replays. Unsigned, forged, or replayed messages are silently dropped. HMAC state is frozen at call start to prevent mid-call desync. Configurable via Settings → Security.
- **Relay Mode (Group Bridge)** -- Run a zero-knowledge relay that bridges N anonymous callers. The relay forwards encrypted audio and chat without decrypting, requires no shared secret or audio hardware. Clients auto-detect relay mode via `RELAY:1` handshake and display live group caller count. One caller leaving does not disconnect others. Operator dashboard shows caller count, uptime, and data throughput.
- **Single-Hop Tor Mode** -- Optional reduced-latency mode for relay operators. Uses 1 Tor hop instead of 3 for the hidden service, sacrificing server anonymity for lower latency. Ideal for relay operators who don't need to hide their own IP.
- **Port Configuration** -- Configure listen port and SOCKS port together via Settings → Tor Settings. Enables running multiple instances on the same device with separate Tor processes. Primarily useful for relay operators who also want to join their own group call -- run the relay on one instance, change the SOCKS port on a second instance, and dial in as a caller.
- **Cross-Platform** -- Runs on standard Linux distributions, macOS, and Android via Termux. Platform-specific audio backends are handled transparently.
- **No Root Required** -- PTT input uses terminal raw mode. No special permissions or kernel modules needed.
- **Single Script** -- One Bash file. No build system, no runtime, no framework.

---

## Installation

### Linux

**Supported distributions:** Debian/Ubuntu (apt), Fedora/RHEL (dnf), Arch (pacman).

``` bash

git clone https://gitlab.com/here_forawhile/terminalphone.git
cd terminalphone
bash terminalphone.sh

```

Select option **7** from the menu to install all dependencies automatically. The following packages will be installed:

| Package | Purpose |
|---|---|
| `tor` | Onion routing and hidden service |
| `opus-tools` | Voice compression (Opus codec) |
| `sox` | Audio processing utilities |
| `socat` | Bidirectional TCP relay through Tor SOCKS proxy |
| `openssl` | AES-256-CBC encryption and decryption |
| `pulseaudio-utils` / `libpulse` | Preferred audio capture/playback on PipeWire/PulseAudio (`parec`, `pacat`) |
| `alsa-utils` | Audio recording/playback fallback (`arecord`, `aplay`) |

> On modern Linux desktops (PipeWire/PulseAudio), TerminalPhone uses `parec`/`pacat` by default and falls back to ALSA (`arecord`/`aplay`) automatically. If you previously got silent calls on Linux, this is the fix for [issue #2](https://github.com/edengilbertus/terminalphone/issues/2).

### macOS

``` bash

git clone https://gitlab.com/here_forawhile/terminalphone.git
cd terminalphone
bash terminalphone.sh

```

Select option **7** to install all dependencies automatically. If [Homebrew](https://brew.sh) is not installed, the script will install it first, then install the following packages:

| Package | Purpose |
|---|---|
| `tor` | Onion routing and hidden service |
| `opus-tools` | Voice compression (Opus codec) |
| `sox` | Audio recording and playback (`rec`, `play`) |
| `socat` | Bidirectional TCP relay through Tor SOCKS proxy |
| `openssl` | AES-256-CBC encryption and decryption |

**Note:** macOS uses `sox` for both recording (`rec`) and playback (`play`) instead of ALSA. No additional audio packages are needed.

### Termux (Android)

TerminalPhone supports Android devices through Termux. Due to Android's sandboxed audio architecture, two additional components are required.

**Step 1: Install Termux**

Install [Termux](https://f-droid.org/en/packages/com.termux/) from F-Droid. Do not use the Play Store version, as it is outdated and no longer receives updates.

**Step 2: Install the Termux:API app**

Install [Termux:API](https://f-droid.org/en/packages/com.termux.api/) from F-Droid. This is a separate Android application (not a Termux package) that provides a bridge between Termux and Android system APIs. TerminalPhone requires it to access the device microphone and media playback.

Without the Termux:API app installed on the device, the `termux-microphone-record` and `termux-media-player` commands will not function, and audio recording and playback will fail silently.

After installing the Termux:API app, grant it microphone permissions when prompted.

**Step 3: Install the Termux:API package inside Termux**

```bash
pkg install termux-api
```

This installs the command-line utilities that communicate with the Termux:API app.

**Step 4: Run TerminalPhone**

```bash
git clone https://gitlab.com/here_forawhile/terminalphone.git
cd terminalphone
bash terminalphone.sh
```

Select option **7** to install all remaining dependencies. The installer will run `pkg upgrade` first to resolve any package linking issues, then install `tor`, `opus-tools`, `sox`, `socat`, `openssl-tool`, `ffmpeg`, and `termux-api`.

**Termux-specific dependencies:**

| Package | Purpose |
|---|---|
| `termux-api` | CLI bridge to Android microphone and media player |
| `ffmpeg` | Converts Android's M4A recordings to raw PCM for Opus encoding |

---

## Quick Start

```
1. Run:                bash terminalphone.sh
2. Install deps:       Select option 7
3. Start Tor:          Select option 8 (wait for 100% bootstrap)
4. Set shared secret:  Select option 4 (both parties must use the same secret)
5. Share your .onion address with the other party (option 3)

To receive a call:     Select option 1 (Listen for calls)
To make a call:        Select option 2 (Call an onion address)
```

Both parties must have Tor running and the same shared secret configured before initiating a call.

---

## Usage

### Menu Options

```
 1  Listen for calls          Wait for an incoming connection
 2  Call an onion address     Connect to a remote .onion endpoint
 3  Show my onion address     Display your .onion address (with optional QR code)
 4  Set shared secret         Configure the pre-shared encryption key
 5  Test audio (loopback)     Record and play back audio locally
 6  Show status               Display Tor, secret, and connection status
 7  Install dependencies      Install all required packages
 8  Start Tor                 Start the Tor process and hidden service
 9  Stop Tor                  Stop the Tor process
10  Restart Tor               Stop and restart Tor
11  Rotate onion address      Generate a new .onion address (destroys the old one)
12  Settings                  Configure Opus quality, PTT chime, Snowflake, auto-listen, PTT key, voice changer, security, Tor settings
13  Relay mode                Start a zero-knowledge group bridge for N callers
 0  Quit                      Stop Tor and exit
```

### In-Call Controls

**Linux (hold-to-talk):**

| Key | Action |
|---|---|
| Hold SPACE | Record voice message. Sends automatically on release. |
| T | Send an encrypted text message. |
| S | Open settings mid-call (change cipher, adjust quality). |
| Q | Hang up and return to the menu. |

**Termux (toggle mode):**

Android's software keyboard sends key events on release, not on press. TerminalPhone adapts by using toggle mode on Termux.

| Key | Action |
|---|---|
| Tap SPACE | Start recording. Tap again to stop and send. |
| T | Send an encrypted text message. |
| S | Open settings mid-call (change cipher, adjust quality). |
| Q | Hang up and return to the menu. |
| Vol Down ×2 | Toggle recording via volume button (requires Volume PTT enabled in settings). |

### CLI Mode

```bash
bash terminalphone.sh install       # Install dependencies
bash terminalphone.sh test          # Audio loopback test
bash terminalphone.sh status        # Show status
bash terminalphone.sh listen        # Listen for incoming calls
bash terminalphone.sh call ADDRESS  # Call a .onion address
bash terminalphone.sh relay         # Start relay mode (group bridge)
```

---

## How It Works

TerminalPhone uses a record-then-send model. When you activate PTT, the microphone records continuously until you release. The complete recording is then processed through the following pipeline:

```
SENDER                                          RECEIVER
──────                                          ────────
Microphone                                      Speaker
    │                                               ▲
    ▼                                               │
Raw PCM (8kHz, 16-bit, mono)                    Opus decode
    │                                               ▲
    ▼                                               │
Opus encode (16kbps)                            AES-256-CBC decrypt
    │                                               ▲
    ▼                                               │
AES-256-CBC encrypt                             Base64 decode
    │                                               ▲
    ▼                                               │
Base64 encode ──▶ socat ──▶ Tor ──▶ socat ──▶ Receive
```

The wire protocol is line-based text over a TCP connection:

| Message | Description |
|---|---|
| `ID:<onion>` | Caller ID -- sender's `.onion` address |
| `CIPHER:<name>` | Sender's encryption cipher. Exchanged on connect and on change. |
| `PTT_START` | Sender has begun recording |
| `PTT_STOP` | Sender has finished; audio follows or has been sent |
| `AUDIO:<base64>` | Complete encrypted audio message |
| `MSG:<base64>` | Encrypted text message |
| `HANGUP` | Sender is disconnecting |
| `PING` | Keepalive signal |
| `RELAY:1` | Relay greeting -- sent by relay on connect, triggers group mode |
| `GROUP:<n>` | Group size update -- broadcast by relay when callers join or leave |

On Termux, an additional conversion step handles Android's native M4A recording format, using `ffmpeg` to convert to raw PCM before Opus encoding.

---

## Security Model

**Encryption:** All audio is encrypted with a user-configurable cipher (default: AES-256-CBC) before transmission. 21 curated ciphers are available, ranked from strongest (256-bit) to adequate (128-bit). The key is derived from a pre-shared secret using PBKDF2 with 10,000 iterations. The encryption is applied at the application layer, independent of Tor's transport encryption. Secrets are passed to OpenSSL via file descriptors (`-pass fd:3`), not command-line arguments, so they are never exposed in the process table.

**Cipher negotiation:** Both parties exchange cipher names on connect and whenever a cipher is changed mid-call. Cipher names are not secret (Kerckhoffs's principle). If the local and remote ciphers do not match, both parties see red indicators in the call header.

**Transport:** All data is routed through Tor hidden service circuits. Neither party's IP address is exposed. There is no clearnet traffic. The connection cannot be attributed to either party by a network observer.

**Traffic analysis resistance:** The record-then-send model produces irregular transmission patterns (variable-length messages at irregular intervals), which are harder to fingerprint than continuous streaming.

**Authentication:** The shared secret serves as implicit authentication. If both parties do not have the same secret, decryption fails and no audio is played. On connect, both parties exchange `.onion` addresses for caller identification. The secret can optionally be encrypted at rest with a passphrase; on launch, the script prompts for the passphrase to unlock it.

**HMAC protocol signing (optional):** When enabled, every wire protocol message -- including control signals like HANGUP, PTT_START, and PING -- is signed with HMAC-SHA256 derived from the shared secret. A random nonce is included per message so that identical commands produce unique signatures. Seen nonces are tracked per call and duplicates are rejected, preventing replay attacks. The HMAC setting is frozen at call start via a runtime file so that both the send and receive paths always agree, even if the setting is toggled mid-call (changes take effect on the next call). On the receiving end, any message with an invalid, missing, or replayed signature is silently dropped. This prevents an attacker who compromises the Tor circuit (but does not have the shared secret) from injecting or replaying commands. Both parties must enable HMAC for calls to work. Not compatible with versions prior to 1.1.3.

**Limitations:**

- The shared secret must be exchanged out-of-band through a secure channel (in person, encrypted messaging, etc.).
- There is no forward secrecy. If the shared secret is compromised, all past and future communications using that secret can be decrypted.
- The protocol does not protect against a compromised endpoint. If either device is compromised, the attacker has access to the plaintext audio.

**Relay mode security:** The relay is architecturally zero-knowledge. It never possesses the shared secret and cannot decrypt any content. Audio data flows through kernel pipe buffers (FIFOs) that exist only in memory -- nothing is written to disk. When the relay stops, all temporary files are deleted. The relay operator cannot determine what was said, who the callers are, or read any messages. The relay filters all control signals (HANGUP, ID:, CIPHER:, PTT_START, PTT_STOP) and only forwards AUDIO:, MSG:, and PING. A global passive adversary could perform traffic correlation analysis to associate callers with the relay, but message content remains opaque.

**Relay capacity:** The primary bottleneck is Tor bandwidth. Tor hidden service throughput is highly variable and depends on circuit quality, relay congestion, and geographic distance. A typical 10-second voice message is ~20KB encrypted, and each transmission fans out to N-1 listeners.

| Callers | Outbound per message | Expected experience |
|---|---|---|
| 2--3 | 20--40KB | Reliable on most connections |
| 3--5 | 40--80KB | Good on stable circuits, delays possible on mobile data |
| 5--10 | 80--180KB | Pushing limits, noticeable delays between transmissions |
| 10+ | 180KB+ | Unreliable, significant queuing and potential message loss |

Realistic capacity is **3--5 callers** for a relay running on a phone (Termux), or **5--10 callers** on a dedicated Linux machine with a stable connection. Relays running on mobile devices face additional constraints: mobile data adds latency on top of Tor, Android may kill background Termux processes to reclaim memory, and battery drain increases with each connected caller. Tor circuit bandwidth can vary from 50KB/s to 500KB/s depending on path quality, and circuits can degrade or rotate mid-session. Single-hop mode improves throughput but does not eliminate Tor relay congestion. These estimates assume the PTT model where only one person transmits at a time -- simultaneous transmissions would degrade performance further. Callers in a group call should consider lowering their Opus bitrate (Settings → Opus encoding) to reduce message sizes and lighten the load on the relay.

---

## Configuration

All configuration is stored in `.terminalphone/` relative to the script location:

```
.terminalphone/
  tor_data/            Tor data directory and hidden service keys
  audio/               Temporary audio files (cleaned on exit)
  pids/                Process ID tracking
  shared_secret        Encrypted shared secret file
  torrc                Generated Tor configuration
```

Default audio parameters (defined at the top of the script):

| Parameter | Default | Description |
|---|---|---|
| `LISTEN_PORT` | 7777 | TCP port for incoming connections |
| `TOR_SOCKS_PORT` | 9050 | Tor SOCKS proxy port |
| `OPUS_BITRATE` | 16 | Opus encoding bitrate in kbps |
| `CIPHER` | aes-256-cbc | Encryption cipher (configurable via Settings) |
| `SNOWFLAKE_ENABLED` | 0 | Snowflake bridge for censorship circumvention |
| `AUTO_LISTEN` | 0 | Auto-listen for calls when Tor starts |
| `PTT_KEY` | SPACE | Push-to-talk key (configurable via Settings) |
| `VOL_PTT` | 0 | Volume-down double-tap PTT, Termux only (experimental) |
| `EXCLUDE_NODES` | (empty) | Tor ExcludeNodes country list (e.g. `{US},{GB}`) |
| `HMAC_AUTH` | 0 | HMAC-sign all protocol messages (optional, both sides must match) |
| `PTT_CHIME` | off | PTT notification chime preset (off, tone, double, chirp, ding, click, custom) |
| `SINGLE_HOP` | 0 | Single-hop Tor mode for lower latency (disables server anonymity) |
| `SAMPLE_RATE` | 8000 | Audio sample rate in Hz |
| `CHUNK_DURATION` | 1 | Duration for audio test chunks in seconds |

---

## Troubleshooting

**Tor fails to bootstrap:**
Check the Tor log at `.terminalphone/tor_data/tor.log`. Common causes include clock skew, network restrictions blocking Tor, or another Tor instance using the same SOCKS port.

**No audio on Termux:**
Verify that the Termux:API app is installed from F-Droid (not just the `termux-api` package). Grant microphone permissions to the Termux:API app in Android settings. Run the audio loopback test (option 5) to verify.

**ffmpeg installation fails on Termux:**
Run `pkg upgrade` before installing dependencies. The installer does this automatically, but if you installed packages manually, outdated shared libraries can cause linking errors.

**Audio test works but calls are silent:**
Confirm that both parties are using the same shared secret. Mismatched secrets will result in decryption failure with no error message -- the call connects but no audio is heard.

**Snowflake bridge is slow to connect:**
Snowflake routes traffic through WebRTC proxies, which adds extra bootstrapping time. It is normal for Tor to take 30--60 seconds (or more) to reach 100% when Snowflake is enabled. The script will display a patience notice during bootstrap.

**First Tor bootstrap is slow:**
On first launch, Tor must download the full network consensus from scratch, which can take a minute or two. The script detects this and displays a notice. The bootstrap timeout is automatically extended from 120 to 300 seconds on first run. Subsequent launches use cached consensus data and are much faster.

**Hang up does not return to menu:**
If the script hangs after pressing Q, press Ctrl+C to force cleanup and return to the shell.

---

[MIRROR V1.0.0](https://bin.disroot.org/?e1356291b098cb75#FMQ4gxFwgdr3rjR1dpGS2csLmDPzDEkQW16fQ5P2Vt4y)

[MIRROR V1.0.1](https://bin.disroot.org/?d3bc0b8976113f58#AuUm4ev4vfeVmPyrh2KjAdhDP6WN4UX6yKQh9ERGD5Qt)

[MIRROR V1.0.2](https://bin.disroot.org/?6bc5b2fd046de1d7#G7TmnytrMeaM5AZYWth6BjjdqUb9RDf3K9erHUExKcGX)

[MIRROR V1.0.3](https://bin.disroot.org/?c5010f039e4693fd#Brp1w7LRQH9d5Ye5npZDPxNVR855SW9QUAk9cJaUuLYX)

[MIRROR V1.0.4](https://bin.disroot.org/?1831f6b78e349142#7zaAMVPNJL3MfbGJzjtm6cCPcvQftf4ULXupdne5dRKw)

[MIRROR V1.0.5](https://bin.disroot.org/?edfcfc844987ed03#56LuBbqbkfNDXfHpydyaB3VcWYhYenX18dtSvNumERY9)

[MIRROR V1.0.6](https://bin.disroot.org/?6c7b4774108b0c1c#GQPst46zjAYidndmNvytforX7MK2LyHanL4d829vVcv4)

[MIRROR V1.0.7](https://bin.disroot.org/?047003637623b4fa#EwmaysciDpiDkht8xV7ce3QcR9oxFXaxSikh4cLheXBB)

[MIRROR V1.0.8](https://bin.disroot.org/?06e38bd64e6fbdad#88MYs3dmq9rSMkmocpW3NYaaG4YfSdRCc9LJnEEzqGYp)

[MIRROR V1.0.9](https://bin.disroot.org/?950218a9a7c71c66#E7Z94VCGBZozrfXYhGwKyAdMeTxuavg92tA1pn2DbrrB)

[MIRROR V1.1.0](https://bin.disroot.org/?0b0da14f31521b3a#B1c23J8xFoZZKErvGG28PgbtfgtMUcDABWmQEoSZfXgh)

[MIRROR V1.1.1](https://bin.disroot.org/?d8e2d4f0300eb5af#9Y1C8CkcH9jAmv1fh4GZs1yYpJmWCG5xG3SvDYdwnJam)

[MIRROR V1.1.2](https://bin.disroot.org/?b1059616f880925f#8ef2oscZXUkPAsJZwGfWvLPQagVAk5GgW4DyssmLvQpG)

[MIRROR V1.1.3](https://bin.disroot.org/?b02658801518aaa7#JE6CsBLWUwAnTdBqeHgeXL7QF5UExgi9rnygcfyMZjCJ)

[MIRROR V1.1.4](https://bin.disroot.org/?d31248fc44c287a0#HQELFWFEMpM9kfTZSGDXTdGFMVKTejox5CajF9Vm4Www)

[MIRROR V1.1.5](https://bin.disroot.org/?284b723ed6aad15f#8VCrrri6yRpdg3uVDSY94wpx7LYkw5uYhm4Vbhka83sM)

[MIRROR V1.1.5.1](https://bin.disroot.org/?26aaef1eff20c271#4GxQQPSDhrszTu1RmERySNVqD2fZW5GZwm3JeL1parpB)

---

## License

MIT
