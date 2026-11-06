# Streamlink Updated Plugins – Chaturbate & Stripchat

This repository contains **updated Streamlink plugins** for **Chaturbate** and **Stripchat**.  
These plugins are maintained to ensure they continue working even after the platforms release updates that break official or older versions.

---

## ✅ What this repository does
- Provides fixed and updated Streamlink plugins  
- Restores functionality when websites change their APIs or streaming endpoints  
- Allows you to continue using Streamlink to watch or record streams from:
  - **Chaturbate**
  - **Stripchat**

---

## 🔧 Installation & Usage

### 1. Download the updated plugin files
Clone or download this repository, then copy the plugin files (`chaturbate.py`, `stripchat.py`) into your Streamlink plugins directory:

| OS | Plugins directory |
|---|---|
| Windows | `%APPDATA%\streamlink\plugins` |
| Linux | `~/.local/share/streamlink/plugins` |
| macOS | `~/Library/Application Support/streamlink/plugins` |

### 2. Watch or record a stream

```bash
# open the best quality in your player
streamlink https://stripchat.com/<username> best

# record to a file
streamlink -o recording.ts https://stripchat.com/<username> 1080p60

# wait until the room is public, checking every 30 s
streamlink --retry-streams 30 https://stripchat.com/<username> best
```

Qualities are named after the real resolution (`240p`, `480p`, `720p`, `1080p60`...); `best` and `worst` work as usual.

---

## 🎥 Stripchat plugin

`stripchat.py` is **self-contained**: it only needs Python's standard library and what Streamlink already ships. No Node.js, no extra `pip` packages and no external tools.

How it works, in short:
- **Room check**: before opening anything, it reads the room state and only offers streams when the model is broadcasting publicly. Private shows, group shows, offline rooms and unknown users are reported with a clear message. If the room goes private while you are watching, the plugin tells you why the stream stopped.
- **Encrypted segment names**: Stripchat's player (Mouflon v2) encrypts the names of the video parts. The plugin decrypts them in pure Python, the same way the official player does.
- **Low-latency playback**: the low-latency HLS playlist is converted into a regular playlist that Streamlink can follow without stalls or skipped segments.
- **HTTP/2**: video traffic uses a small built-in HTTP/2 client. The HTTP/2 libraries (`h2`, `hpack`, `hyperframe`, MIT licensed) are embedded at the end of the file. If HTTP/2 is not available it falls back to HTTP/1.1; set `STRIPCHAT_HTTP1=1` to force HTTP/1.1.

---

## ⚠️ Notes
- These plugins are unofficial and may break again if the sites change; updates will follow.
