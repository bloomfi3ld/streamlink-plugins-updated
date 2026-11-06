"""Streamlink plugin for Stripchat — **self-contained** (no Node).

Everything needed is embedded in this file: the Mouflon v2 decoder (it used to
live in `mouflon_py.py`), the CDN HTTP adapter, the blocking-reload warm-up and
the manifest rewriting. Neither `mouflon_py.py`, Node nor the player bundle
are needed. (The old Node fallback that decrypted with the real player was
removed; see "Fallback Node" in the README if it has to come back.)

Mouflon v2 scheme (`PSCH=v2`) of the MMP player:

- The master (`edge-hls.doppiocdn.<tld>/hls/<id>/master/<id>_auto.m3u8`) is
  requested without a key and publishes the rotating pool in
  `#EXT-X-MOUFLON:PSCH:v2:<pkey>`. The variants it lists without a key come with
  `playlistType=standard` and without `psch/pkey`; requesting them like that
  makes the CDN serve the ad (`cpa/v2/...`). That's why the pool is read and the
  master is requested again with
  `?playlistType=lowLatency&psch=v2&pkey=<key>` to get the signed variants. The
  decryption key (`NTK9aqcLmNFMWrpQ`) always goes first.
- Each variant publishes the real parts in `#EXT-X-MOUFLON:URI:` or in
  `#EXT-X-PART`, with the encrypted segment name:
  `<id>_<msn>_<token>_<ts>_partN.mp4`. The real name is obtained by decrypting
  the token (`base64(reversed) XOR keystream`) and the init (`#EXT-X-MAP`) is
  literal.
- The keystream depends on the `pkey` used to sign the request:
  `keystream = SHA-256(secret)`, where `secret` comes from a `pkey -> secret`
  table hidden (obfuscated) in the player; the CDN encrypts with it and the
  player only decrypts the keys present in that table. MMP v2.15.0 (the
  current one) only has `NTK9aqcLmNFMWrpQ -> tOcYOap4Ty1l9Jzb`, so that key is
  always in the pool and this plugin signs with it (`PSCH_SECRETS`).
- This plugin rewrites each manifest as a classic playlist of 0.5 s parts and
  adds `_HLS_msn/_HLS_part` (blocking-reload) to always request the block after
  the last one seen (a fresh URL each time, so the CDN can't answer from
  cache); the newest blocks are held back so streamlink only downloads files
  that already exist.
- Transport: the CDN works better over HTTP/2, so doppiocdn traffic goes
  through a small HTTP/2 client (`_H2Client`) built on the `h2` protocol stack,
  which is vendored at the end of this file. If a host doesn't negotiate
  HTTP/2 (ALPN) the client falls back to HTTP/1.1 with `requests`; setting the
  environment variable `STRIPCHAT_HTTP1=1` forces HTTP/1.1 for comparisons.

File layout:

- PART 1 -- the plugin (this is the code to read and edit).
- PART 2 -- vendored libraries `hyperframe`, `hpack` and `h2` (MIT), flattened
  into plain code by `tools/vendor_h2.py`. Do not edit by hand: regenerate.
  Nothing outside Streamlink's own dependencies is required.
"""

from __future__ import annotations

# ===========================================================================
# PART 1 -- STRIPCHAT PLUGIN
# ===========================================================================

import base64
import hashlib
import json
import logging
import os
import re
import socket
import ssl
import threading
import zlib

import requests
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from requests.adapters import HTTPAdapter

from streamlink.plugin import Plugin, pluginmatcher
from streamlink.plugin.api import validate
from streamlink.stream.hls import HLSStream


log = logging.getLogger(__name__)

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36")

DEFAULT_PKEY = "B0p93vi8Uj6AYyZb"   # hardcoded in the MMP player; last resort
PKEY_DECODE = "NTK9aqcLmNFMWrpQ"    # pool key with which the player derives correctly
MOUFLON_PREFIX = "#EXT-X-MOUFLON:"
HOST_PREFIXES = tuple(
    f"https://{kind}.doppiocdn{tld}/"
    for kind in ("edge-hls", "media-hls")
    for tld in (".com", ".org", ".net", ".media", ".live", ".dev", "1.com")
)

# ===========================================================================
# Embedded Mouflon v2 decoder (formerly `mouflon_py.py`)
#
#   keystream = SHA-256(PSCH_SECRETS[pkey])
#   real_name = base64(reversed token) XOR keystream
#
# The token is reversed inside the segment URI. `pkey` is the key the request
# is signed with (it is also echoed in the variant's `#EXT-X-MOUFLON:PSCH`
# tag). The player keeps the `pkey -> secret` table as an obfuscated
# "pkey:secret;pkey:secret" string that it splits at runtime; it was read out
# by running the player under Node and watching its SHA-256 input
# (`tools/player/secret_probe.js`). The init (`EXT-X-MAP`) is NOT encrypted.
# ===========================================================================

# pkey -> secret, as in the MMP player's table (v2.15.0 has only this entry).
# If Stripchat ships a player with new keys, add the pairs here (run
# `node tools/player/secret_probe.js <variant.m3u8>` on the new player).
PSCH_SECRETS = {
    PKEY_DECODE: "tOcYOap4Ty1l9Jzb",
}


def keystream_for(pkey):
    """Keystream for a signing key, or `None` if its secret is unknown."""
    secret = PSCH_SECRETS.get(pkey)
    return hashlib.sha256(secret.encode()).digest() if secret else None


# known keystreams per signing key (the first one is the default)
KEYSTREAMS = {pkey: keystream_for(pkey) for pkey in PSCH_SECRETS}

KS_DEFAULT = KEYSTREAMS[PKEY_DECODE]

# token = 22 base64 chars before _<ts>[_partN].mp4; the URI may end the line
# (`#EXT-X-MOUFLON:URI:`) or be quoted inside an attribute list (`URI="..."`)
_TOKEN_RE = re.compile(r"_(\d+)_([A-Za-z0-9+/]{15,26})_(\d+)((?:_part\d+)?\.mp4)(?=[?#\",\s]|$)", re.MULTILINE)
_PSCH_TAG_RE = re.compile(r"#EXT-X-MOUFLON:PSCH:[^:\s]+:([A-Za-z0-9]+)")
_PLAUSIBLE_RE = re.compile(r"^[A-Za-z0-9]{15,17}$")

# optional manual keystream override: {"ks": "<32 hex chars>"} next to the plugin
KEYS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ks.json")


def _b64(s):
    return base64.b64decode(s + "=" * ((4 - len(s) % 4) % 4))


def _xor(data, ks):
    return bytes(b ^ ks[i % len(ks)] for i, b in enumerate(data))


def decode_token(tok, ks=KS_DEFAULT):
    """Decrypts the token (reversed + base64 + XOR). `None` if it doesn't fit."""
    raw = _b64(tok[::-1])
    if not raw:
        return None
    return _xor(raw, ks).decode("latin-1")


def decode_uri(uri, ks=KS_DEFAULT):
    """Rewrites the URI with the real name (if the token fits)."""
    m = _TOKEN_RE.search(uri)
    if not m:
        return uri
    real = decode_token(m.group(2), ks)
    if not real or not _PLAUSIBLE_RE.match(real):
        return uri
    return f"{uri[:m.start(2)]}{real}{uri[m.end(2):]}"


def looks_decoded(text, ks=KS_DEFAULT):
    """True if ALL tokens in the manifest decrypt to something plausible."""
    tokens = [m.group(2) for m in _TOKEN_RE.finditer(text)]
    if not tokens:
        return False
    for t in tokens:
        r = decode_token(t, ks)
        if not (r and _PLAUSIBLE_RE.match(r)):
            return False
    return True


def load_cache():
    """Manual keystream override (`ks.json` next to the plugin). `None` if absent."""
    try:
        with open(KEYS_PATH, encoding="utf-8") as fh:
            return bytes.fromhex(json.load(fh)["ks"])
    except Exception:  # noqa: BLE001
        return None


def current_keystream(text):
    """Keystream that decrypts `text`, chosen like the player does.

    `ks.json` override → keystream of the key in the manifest's PSCH tag →
    any other known keystream. If none fits, it returns the default keystream
    and `decode_manifest` serves the manifest as is.
    """
    cache = load_cache()
    if cache and looks_decoded(text, cache):
        return cache
    m = _PSCH_TAG_RE.search(text)
    tagged = keystream_for(m.group(1)) if m else None
    if tagged and looks_decoded(text, tagged):
        return tagged
    for ks in KEYSTREAMS.values():
        if looks_decoded(text, ks):
            return ks
    # NOTE -- there is no Node fallback any more: the keystream derivation is
    # known (SHA-256 of the key's secret), so a key we can't decrypt only means
    # its secret is missing from `PSCH_SECRETS`. Get it from the current player
    # with `node tools/player/secret_probe.js <variant.m3u8>` (research tool,
    # not needed at runtime). See "Fallback Node" in README.md.
    log.warning("unknown keystream (pkey %s): serving the manifest without decrypting",
                m.group(1) if m else "?")
    return KS_DEFAULT


def decode_manifest(text, ks=None):
    """Decrypts all URIs (`MOUFLON:URI` and `EXT-X-PART`) in the manifest.

    If no known keystream fits, returns the manifest as is.
    """
    ks = ks or current_keystream(text)
    if not looks_decoded(text, ks):
        return text
    output = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#EXT-X-MOUFLON:URI:"):
            s = "#EXT-X-MOUFLON:URI:" + decode_uri(s[len("#EXT-X-MOUFLON:URI:"):].strip(), ks)
        elif s.startswith("#EXT-X-PART:"):
            m = re.search(r'URI="([^"]+)"', s)
            if m:
                s = s[: m.start(1)] + decode_uri(m.group(1), ks) + s[m.end(1):]
        # EXT-X-MAP (init) is left literal on purpose
        output.append(s)
    return "\n".join(output) + "\n"


# ===========================================================================
# CDN adapter + plugin
# ===========================================================================

_UA_HDR = {"Referer": "https://es.stripchat.com/", "User-Agent": UA}


class _CdnClient:
    """HTTP/1.1 with `requests` (always available: it's a Streamlink dependency).

    It is a separate session on purpose: `session.http` has this plugin's
    adapter mounted on the doppiocdn hosts, so using it here would recurse
    into the adapter, and its default headers include things the CDN rejects.
    """

    def __init__(self, verify=True):
        self._s = requests.Session()
        self._s.verify = verify
        self._s.headers.update(_UA_HDR)

    def get(self, url, headers=None, timeout=20.0):
        return self._s.get(url, headers=headers, timeout=timeout)


# ---------------------------------------------------------------------------
# HTTP/2 client (socket + TLS/ALPN + the vendored `h2` state machine)
#
# One connection per (thread, host): Streamlink fetches playlists and segments
# from different threads, and a blocking-reload playlist request must not hold
# up segment downloads. Requests on a connection are sequential and the
# connection is kept alive between them.
# ---------------------------------------------------------------------------

_H2_WINDOW = 16 * 1024 * 1024        # receive window (stream and connection)
_H2_SKIP_HEADERS = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"}


class _H2Unsupported(Exception):
    """The server didn't negotiate HTTP/2 through ALPN."""


class _H2Retry(Exception):
    """The connection went away before the response; safe to retry (GET)."""


class _H2Response:
    """The subset of `requests.Response` the adapter uses."""

    def __init__(self, status_code, headers, content):
        self.status_code = status_code
        self.headers = headers
        self.content = content
        self.reason = ""

    @property
    def text(self):
        return self.content.decode("utf-8", "replace")


def _ssl_context(verify):
    """TLS context like `requests`: system store + certifi; `verify` as in requests."""
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif isinstance(verify, str):
        ctx = ssl.create_default_context(cafile=verify if os.path.isfile(verify) else None,
                                         capath=verify if os.path.isdir(verify) else None)
    else:
        ctx = ssl.create_default_context()
        try:
            import certifi
            ctx.load_verify_locations(certifi.where())
        except Exception:  # noqa: BLE001
            pass
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    return ctx


def _decode_body(body, encoding):
    encoding = (encoding or "").strip().lower()
    if encoding == "gzip":
        return zlib.decompress(body, 16 + zlib.MAX_WBITS)
    if encoding == "deflate":
        try:
            return zlib.decompress(body)
        except zlib.error:
            return zlib.decompress(body, -zlib.MAX_WBITS)
    return body


class _H2Connection:
    """A single HTTP/2 connection, used by one thread at a time."""

    def __init__(self, host, port, ctx, timeout):
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            self._sock = ctx.wrap_socket(raw, server_hostname=host)
        except Exception:
            raw.close()
            raise
        if self._sock.selected_alpn_protocol() != "h2":
            self._sock.close()
            raise _H2Unsupported(host)
        self._conn = H2Connection(config=H2Configuration(client_side=True, header_encoding=None))
        self._conn.initiate_connection()
        self._conn.update_settings({
            SettingCodes.INITIAL_WINDOW_SIZE: _H2_WINDOW,
            SettingCodes.ENABLE_PUSH: 0,
        })
        self._conn.increment_flow_control_window(_H2_WINDOW - 65535)
        self._flush()
        self.closed = False

    def _flush(self):
        data = self._conn.data_to_send()
        if data:
            self._sock.sendall(data)

    def close(self):
        self.closed = True
        try:
            self._conn.close_connection()
            self._flush()
        except Exception:  # noqa: BLE001
            pass
        try:
            self._sock.close()
        except Exception:  # noqa: BLE001
            pass

    def get(self, authority, path, headers, timeout):
        self._sock.settimeout(timeout)
        sid = self._conn.get_next_available_stream_id()
        hdrs = [(b":method", b"GET"), (b":scheme", b"https"),
                (b":authority", authority.encode()), (b":path", path.encode())]
        hdrs += [(k.lower().encode(), str(v).encode())
                 for k, v in headers.items() if k.lower() not in _H2_SKIP_HEADERS]
        self._conn.send_headers(sid, hdrs, end_stream=True)
        self._flush()

        status, resp_headers, body = None, {}, bytearray()
        while True:
            data = self._sock.recv(65536)
            if not data:
                self.closed = True
                raise _H2Retry("connection closed by the server")
            for ev in self._conn.receive_data(data):
                if isinstance(ev, ResponseReceived) and ev.stream_id == sid:
                    for k, v in ev.headers:
                        k, v = k.decode("latin-1"), v.decode("latin-1")
                        if k == ":status":
                            status = int(v)
                        else:
                            resp_headers[k] = f"{resp_headers[k]}, {v}" if k in resp_headers else v
                elif isinstance(ev, DataReceived):
                    if ev.stream_id == sid:
                        body += ev.data
                    self._conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, StreamEnded) and ev.stream_id == sid:
                    self._flush()
                    enc = resp_headers.pop("content-encoding", None)
                    content = _decode_body(bytes(body), enc)
                    resp_headers["content-length"] = str(len(content))
                    return _H2Response(status, resp_headers, content)
                elif isinstance(ev, StreamReset) and ev.stream_id == sid:
                    raise IOError(f"HTTP/2 stream reset by the server (error {ev.error_code})")
                elif isinstance(ev, ConnectionTerminated):
                    self.closed = True
                    raise _H2Retry(f"HTTP/2 GOAWAY (error {ev.error_code})")
            self._flush()


class _H2Client:
    """HTTP/2 GET client with the same interface as `_CdnClient`."""

    def __init__(self, verify=True):
        self._ctx = _ssl_context(verify)
        self._verify = verify
        self._local = threading.local()
        self._h1 = None
        self._h1_hosts = set()
        self._announced = False

    def _fallback(self, url, headers, timeout):
        if self._h1 is None:
            self._h1 = _CdnClient(self._verify)
        return self._h1.get(url, headers=headers, timeout=timeout)

    def get(self, url, headers=None, timeout=20.0):
        p = urlsplit(url)
        host, port = p.hostname, p.port or 443
        if p.scheme != "https" or host in self._h1_hosts:
            return self._fallback(url, headers, timeout)

        merged = dict(_UA_HDR)
        merged["Accept-Encoding"] = "gzip, deflate"
        merged.update(headers or {})
        authority = host if p.port is None else f"{host}:{p.port}"
        path = (p.path or "/") + (f"?{p.query}" if p.query else "")

        conns = getattr(self._local, "conns", None)
        if conns is None:
            conns = self._local.conns = {}
        key = (host, port)
        for attempt in range(2):
            conn = conns.get(key)
            reused = conn is not None
            if conn is None:
                try:
                    conn = conns[key] = _H2Connection(host, port, self._ctx, timeout)
                except _H2Unsupported:
                    log.info("%s doesn't offer HTTP/2: using HTTP/1.1", host)
                    self._h1_hosts.add(host)
                    return self._fallback(url, headers, timeout)
                if not self._announced:
                    self._announced = True
                    log.info("doppiocdn transport: HTTP/2")
            try:
                resp = conn.get(authority, path, merged, timeout)
            except (_H2Retry, OSError) as err:
                conns.pop(key, None).close()
                if reused and attempt == 0 and not isinstance(err, TimeoutError):
                    continue            # stale keep-alive connection (GOAWAY/reset): retry once
                if isinstance(err, _H2Retry):
                    raise IOError(f"HTTP/2 connection to {host} lost: {err}") from err
                raise
            except BaseException:
                conns.pop(key, None).close()
                raise
            if conn.closed:
                conns.pop(key, None)
            return resp
        raise IOError(f"HTTP/2 connection to {host} lost")


def _new_client(verify=True):
    """HTTP/2 client unless `STRIPCHAT_HTTP1=1` forces HTTP/1.1."""
    if os.environ.get("STRIPCHAT_HTTP1", "").strip() not in ("", "0"):
        log.info("doppiocdn transport: HTTP/1.1 (forced by STRIPCHAT_HTTP1)")
        return _CdnClient(verify)
    return _H2Client(verify)


SITE = "https://es.stripchat.com"
_STATE_RE = re.compile(r"window\.__PRELOADED_STATE__\s*=\s*")
_STATUS_TEXT = {
    "public": "broadcasting publicly but the cam isn't available",
    "private": "in a private show",
    "virtualPrivate": "in a private show",
    "p2p": "in a private show",
    "groupShow": "in a group show",
    "idle": "online but not broadcasting",
    "off": "offline",
}


def _describe_status(status):
    return _STATUS_TEXT.get(status, f"not public (status: {status})")


_MAX_PARTS = 12        # parts (0.5 s each) listed in each rewritten playlist
_PART_RE = re.compile(r"_(\d+)_[^_/]*_(\d{10})_part(\d+)\.mp4$")

_cam_schema = validate.Schema(
    {
        "cam": validate.Schema({
            "isCamAvailable": bool,
            "streamName": validate.any(str, None),
            "isCamActive": bool,
        }),
        "user": validate.Schema({
            "user": validate.Schema({"status": str}),
        }),
    }
)


class _MouflonAdapter(HTTPAdapter):
    """Adapter for all doppiocdn traffic.

    - Adds `psch/pkey` to `.m3u8` requests that lack them.
    - Referer/Origin/User-Agent like the browser.
    - Blocking-reload: adds `_HLS_msn/_HLS_part` of the next part seen.
    - Rewrites the manifest as a classic playlist of parts (see plugin).
    """

    def __init__(self, plugin, psch, pkey):
        super().__init__()
        self._plugin = plugin
        self._psch = psch
        self._pkey = pkey
        self._block = None          # (msn, part) of the next expected part
        self._seq_state = {}        # per variant path: part numbering (see `_number_parts`)
        self._refused = False       # playlist refused (403/404) and already reported
        verify = True
        try:
            verify = plugin.session.options.get("http-ssl-verify")
        except Exception:  # noqa: BLE001
            pass
        self._http = _new_client(verify)

    def _fetch(self, url, headers):
        return self._http.get(url, headers=headers)

    def _explain_refusal(self, code):
        """The CDN refused the playlist: say why (once per streak of refusals).

        The usual cause is the room leaving public mode (private/group show,
        offline) after the stream was opened; Streamlink then stops the
        stream. With `--retry-streams <s>` Streamlink keeps checking until the
        room is public again (the plugin only offers streams while it is).
        """
        if self._refused:
            return
        self._refused = True
        username = self._plugin.match["username"]
        try:
            state = self._plugin.room_state(username)
        except Exception:  # noqa: BLE001
            state = None
        if state and not state["online"]:
            log.info("Playlist refused (HTTP %s): %s is now %s; the stream will stop",
                     code, username, _describe_status(state["status"]))
        else:
            log.warning("Playlist refused (HTTP %s) although %s looks public; "
                        "the CDN rejected the request", code, username)

    def send(self, request, **kwargs):
        url = request.url
        if "doppiocdn." not in url:
            return super().send(request, **kwargs)

        final = url
        if ".m3u8" in url:
            if "psch=" not in url and self._psch and self._pkey:
                sep = "&" if "?" in url else "?"
                final = f"{url}{sep}psch={self._psch}&pkey={self._pkey}"
            if self._block and "_HLS_msn" not in url:
                msn, part = self._block
                sep = "&" if "?" in final else "?"
                final = f"{final}{sep}_HLS_msn={msn}&_HLS_part={part}"

        # Minimal headers (streamlink's include things the CDN rejects)
        headers = {
            "Referer": self._plugin.url,
            "Origin": "https://stripchat.com",
            "User-Agent": UA,
            "Accept": "*/*",
        }

        try:
            h2r = self._fetch(final, headers)
        except Exception as err:  # noqa: BLE001
            raise IOError(f"doppiocdn: {err}") from err

        body = h2r.content
        text = body.decode("utf-8", "replace")
        if ".m3u8" in url:
            if h2r.status_code in (403, 404, 410):
                self._explain_refusal(h2r.status_code)
            elif h2r.status_code == 200:
                self._refused = False
        if ".m3u8" in url and "#EXT-X-MOUFLON" in text:
            if self._block is None:
                # first manifest of the variant: jump to the live edge with blocking
                msns = [int(n) for n in re.findall(r"_(\d+)_[A-Za-z0-9+/]{15,26}_\d{10}(?:_part\d+)?\.mp4", text)]
                if msns:
                    sep = "&" if "?" in final else "?"
                    try:
                        log.info("blocking warm-up to msn %s", max(msns) + 1)
                        h2b = self._fetch(f"{final}{sep}_HLS_msn={max(msns) + 1}&_HLS_part=0", headers)
                        if h2b.status_code == 200 and "#EXT-X-MOUFLON" in h2b.text:
                            body = h2b.content
                            text = h2b.text
                        else:
                            log.info("warm-up returned no manifest (%s)", h2b.status_code)
                    except Exception as err:  # noqa: BLE001
                        log.debug("blocking warm-up failed: %s", err)
            body = self._plugin.rewrite_m3u8(text, self, url).encode("utf-8")

        response = requests.Response()
        response.status_code = h2r.status_code
        response.url = url
        response.request = request
        response.reason = getattr(h2r, "reason", None) or getattr(h2r, "reason_phrase", None) or ""
        response.encoding = "utf-8"
        response._content = body
        response._content_consumed = True   # body already in memory (also for stream=True)
        for k, v in h2r.headers.items():
            response.headers[k] = v
        response.headers["Content-Length"] = str(len(body))
        return response


@pluginmatcher(re.compile(r"https?://(\w+\.)?stripchat\.com/(?P<username>[a-zA-Z0-9_-]+)"))
class Stripchat(Plugin):

    @classmethod
    def can_handle_url(cls, url):
        return cls._re_url.match(url) is not None

    def rewrite_m3u8(self, text, adapter=None, base=None):
        """Decrypts the names and converts the LL-HLS manifest into a playlist of parts.

        - Decrypts each token (`decode_uri`) before reading it.
        - Keeps EXTM3U / MEDIA-SEQUENCE / MAP (init).
        - Collects the part URIs from `MOUFLON:URI:` (dialect A) and from
          `#EXT-X-PART` (dialect B), in order and without duplicates, making them
          absolute against `base` (some come relative).
        - Each part is emitted as a 0.5 s segment (parts are the only files
          guaranteed to exist; full segments sometimes return 404).
        - Lists every part of the complete blocks outside the propagation
          margin (contiguous, up to `_MAX_PARTS`).
        - Numbers the parts in order of appearance (the number of parts per
          block varies: 4 at 0.5 s, 5 at ~0.53 s...), keeping the numbering
          across reloads in the adapter.
        - Points the adapter's blocking-reload at the next block.
        """
        text = decode_manifest(text)
        media_seq = None
        init_line = None
        parts = []          # [((msn, part), url)]
        seen = set()

        def add(u):
            if base:
                u = urljoin(base, u)
            m = _PART_RE.search(u)
            if not m or u in seen:
                return
            seen.add(u)
            msn, part = int(m.group(1)), int(m.group(3))
            parts.append(((msn, part), u))
            return (msn, part)

        for line in text.splitlines():
            s = line.strip()
            if s.startswith("#EXT-X-MEDIA-SEQUENCE:"):
                media_seq = s.split(":", 1)[1]
            elif s.startswith("#EXT-X-MAP:"):
                init_line = s
            elif s.startswith(MOUFLON_PREFIX):
                tag = s[len(MOUFLON_PREFIX):]
                if tag.startswith("URI:"):
                    add(tag[4:].strip())
            elif s.startswith("#EXT-X-PART:"):
                m = re.search(r'URI="([^"]+)"', s)
                if m:
                    add(m.group(1))

        if not parts:
            return text    # no parts: return the manifest as is

        parts.sort(key=lambda p: p[0])
        # The block in progress and the one before it are left out: their parts
        # may still be propagating through the CDN and requesting them right
        # away gives 404. Everything older that is still in the window is
        # listed (not just the last block), so consecutive playlists overlap
        # and Streamlink never has to skip segments when a reload is late.
        last_block = parts[-1][0][0]
        complete = [p for p in parts if p[0][0] < last_block - 1] or parts
        # Streamlink numbers segments as MEDIA-SEQUENCE + position, so the list
        # must be contiguous: keep the unbroken run that ends with the newest
        # (the next part is `part + 1` in the same block, or part 0 of the
        # next block).
        run = [complete[-1]]
        for p in reversed(complete[:-1]):
            (msn, part), (nmsn, npart) = p[0], run[0][0]
            if not ((msn == nmsn and part == npart - 1) or (msn == nmsn - 1 and npart == 0)):
                break
            run.insert(0, p)
        parts = run[-_MAX_PARTS:]
        parts, first = Stripchat._number_parts(parts, adapter, base)

        out = ["#EXTM3U", "#EXT-X-VERSION:6"]
        if media_seq is not None:
            out.append(f"#EXT-X-MEDIA-SEQUENCE:{first}")
        out.append("#EXT-X-TARGETDURATION:2")
        if init_line:
            out.append(init_line)
        for _idx, url in parts:
            out.append("#EXTINF:0.500,")
            out.append(url)
        playlist = "\n".join(out) + "\n"

        if adapter is not None:
            # Block on the first part of the NEXT block: the CDN holds the
            # request until that block starts and then returns a fresh
            # playlist. Asking for a part that already exists returns at once,
            # and the CDN keeps serving a cached copy of that same URL, so the
            # playlist would stop changing and Streamlink would give up after
            # 6 s ("No new segments in playlist").
            adapter._block = (last_block + 1, 0)
        return playlist

    @staticmethod
    def _number_parts(parts, adapter, base):
        """Stable sequence numbers for `parts` ([((msn, part), url)], sorted).

        Each new part gets the next number, so the same part keeps its number
        across reloads and consecutive parts get consecutive numbers whatever
        the number of parts per block. Returns the parts that could be numbered
        consecutively (ending with the newest) and the first number.
        """
        states = adapter._seq_state if adapter is not None else {}
        state = states.setdefault(urlsplit(base or "").path, {"map": {}, "next": None, "last": None})
        numbers = state["map"]
        for key, _url in parts:
            if key in numbers or (state["last"] is not None and key < state["last"]):
                continue    # already numbered, or older than what was numbered: leave out
            if state["next"] is None:
                state["next"] = key[0] * 8 + key[1]
            numbers[key] = state["next"]
            state["next"] += 1
            state["last"] = key
        parts = [p for p in parts if p[0] in numbers]
        if not parts:       # stale playlist older than the window: list nothing new
            return [], state["next"] or 0
        i = len(parts) - 1
        while i > 0 and numbers[parts[i - 1][0]] == numbers[parts[i][0]] - 1:
            i -= 1
        parts = parts[i:]
        for key in [k for k in numbers if k < parts[0][0]]:
            del numbers[key]    # forget parts that left the window
        return parts, numbers[parts[0][0]]

    @staticmethod
    def _sign(url, key):
        """Adds psch/pkey and forces playlistType=lowLatency (without duplicating parameters)."""
        p = urlsplit(url)
        q = [(k, v) for k, v in parse_qsl(p.query) if k not in ("playlistType", "psch", "pkey")]
        q += [("playlistType", "lowLatency"), ("psch", "v2"), ("pkey", key)]
        return urlunsplit((p.scheme, p.netloc, p.path, urlencode(q), p.fragment))

    def _parse_variants(self, master_text):
        """[(quality_name, url, is_auto)] from the signed master.

        The quality name comes from `NAME` or, if missing, from the variant's
        real `RESOLUTION` (with the frame rate when it is high, e.g.
        `1080p60`). The `_auto` rendition is flagged as `is_auto` so it is also
        exposed under the `source` alias.
        """
        variants = []
        info = None
        for line in master_text.splitlines():
            s = line.strip()
            if s.startswith("#EXT-X-STREAM-INF:"):
                info = s
            elif s and not s.startswith("#"):
                variants.append((info, s))
                info = None

        result = []
        for info, url in variants:
            name = None
            resolution = None
            fps = None
            if info:
                m = re.search(r'NAME="([^"]*)"', info)
                name = m.group(1) if m else None
                mr = re.search(r"RESOLUTION=(\d+)x(\d+)", info)
                if mr:
                    resolution = min(int(mr.group(1)), int(mr.group(2)))
                mf = re.search(r"FRAME-RATE=([\d.]+)", info)
                if mf:
                    try:
                        fps = float(mf.group(1))
                    except ValueError:
                        fps = None

            is_auto = bool(re.search(r"_[^/]*_?auto\.m3u8", url)) or "/master/" in url
            if name and re.fullmatch(r"\d+p\d*", name):
                quality = name            # the CDN already names the quality
            elif resolution:
                quality = f"{resolution}p{int(fps)}" if fps and fps > 30 else f"{resolution}p"
            elif is_auto:
                quality = "source"
            else:
                quality = name or "live"
            result.append((quality, url, is_auto))
        return result


    def room_state(self, username):
        """Room state, read like `strip_alerts.py` does.

        Returns `{"status", "online", "stream"}` (`online` = status "public"
        and the cam available and active, the same rule as strip_alerts),
        `{"status": "missing", ...}` if the user doesn't exist, or `None` if
        nothing could be read.

        1. `/api/front/users/user-ids/<username>` -> numeric id, then
           `/api/front/v2/models/<id>/cam`. (The by-username cam endpoint
           answers 418 to non-browser clients; the by-id one doesn't.)
        2. Fallback: the room page's `window.__PRELOADED_STATE__` JSON, whose
           `viewCam` holds the same fields.
        """
        hdr = {"User-Agent": UA, "Accept": "application/json"}
        try:
            res = self.session.http.get(f"{SITE}/api/front/users/user-ids/{username}",
                                        headers={**hdr, "Referer": f"{SITE}/{username}"},
                                        acceptable_status=(404,))
            if res.status_code == 404:
                return {"status": "missing", "online": False, "stream": None}
            uid = res.json().get("id")
            if isinstance(uid, int):
                res = self.session.http.get(f"{SITE}/api/front/v2/models/{uid}/cam",
                                            headers={**hdr, "Referer": f"{SITE}/"})
                data = self.session.http.json(res, schema=_cam_schema)
                cam, status = data["cam"], data["user"]["user"]["status"]
                return {"status": status,
                        "online": status == "public" and cam["isCamAvailable"] and cam["isCamActive"],
                        "stream": cam["streamName"] or str(uid)}
        except Exception as err:  # noqa: BLE001
            log.debug("cam API failed: %s", err)
        try:
            htm = self.session.http.get(f"{SITE}/{username}", headers={"User-Agent": UA, "Accept": "text/html"}).text
            m = _STATE_RE.search(htm)
            cam = json.JSONDecoder().raw_decode(htm, m.end())[0].get("viewCam") or {}
            model = cam.get("model") or {}
            status = model.get("status")
            return {"status": status,
                    "online": status == "public" and bool(cam.get("isCamAvailable")) and bool(cam.get("isCamActive")),
                    "stream": cam.get("streamName") or model.get("streamName")}
        except Exception as err:  # noqa: BLE001
            log.debug("room page state failed: %s", err)
        return None

    def _resolve_stream_id(self, username):
        """Stream id of the room, only if it is broadcasting publicly right now."""
        state = self.room_state(username)
        if state is None:
            log.error("Could not read the state of %s", username)
            return None
        if state["status"] == "missing":
            log.error("%s doesn't exist on Stripchat", username)
            return None
        if not state["online"]:
            log.info("%s is %s: nothing to record right now", username, _describe_status(state["status"]))
            return None
        if not state["stream"]:
            log.error("Could not resolve the stream id for %s", username)
        return state["stream"]

    def _mount_adapter(self, psch, pkey):
        adapter = _MouflonAdapter(self, psch, pkey)
        for prefix in HOST_PREFIXES:
            self.session.http.mount(prefix, adapter)

    def _get_streams(self):
        username = self.match["username"]
        sid = self._resolve_stream_id(username)
        if not sid:
            return

        host = "edge-hls.doppiocdn.media"
        master_url = f"https://{host}/hls/{sid}/master/{sid}_auto.m3u8"
        try:
            master0 = self.session.http.get(master_url, headers={"Referer": self.url}).text
        except Exception as err:  # noqa: BLE001
            log.error("Could not fetch the master: %s", err)
            return

        pool = re.findall(r"PSCH:v2:([A-Za-z0-9]+)", master0)
        # keys we can decrypt (secret known) go first, those in the pool before
        # the rest; keys without a secret only as a last resort
        known = sorted(PSCH_SECRETS, key=lambda k: (k not in pool, k != PKEY_DECODE))
        keys = known + [k for k in pool if k not in PSCH_SECRETS]
        if pool and not set(pool) & set(PSCH_SECRETS):
            log.warning("No key with a known secret in the pool %s: segment names may "
                        "not decrypt (update PSCH_SECRETS from the current player)", pool)
        if DEFAULT_PKEY not in keys:
            keys.append(DEFAULT_PKEY)

        streams = {}
        for key in keys[:5]:
            signed = self._sign(master_url, key)
            try:
                mtext = self.session.http.get(signed, headers={"Referer": self.url}).text
            except Exception as err:  # noqa: BLE001
                log.debug("Master with key %s failed: %s", key[:6], err)
                continue
            has_variants = any(l.strip() and not l.strip().startswith("#") for l in mtext.splitlines())
            if "cpa/v2" in mtext or not has_variants:
                continue  # expired key: the CDN serves the ad

            self._mount_adapter("v2", key)
            for quality, url, is_auto in self._parse_variants(mtext):
                # start_offset 0: the playlist is already trimmed to the live block
                stream = HLSStream(self.session, self._sign(url, key), start_offset=0)
                if is_auto and quality in streams:
                    streams["source"] = stream        # don't overwrite the real variant
                else:
                    streams[quality] = stream
                if is_auto and quality != "source" and "source" not in streams:
                    streams["source"] = stream        # legacy alias

            if streams:
                log.info("Pool key used: %s", key[:6])
                if key not in PSCH_SECRETS:
                    log.warning("Signed with %s, whose secret is unknown: segments will "
                                "probably 404", key[:6])
                break

        if not streams:
            log.error("No streams obtained (room private/offline?)")
            return

        for quality in sorted(streams, key=lambda n: (self.stream_weight(n), n != "source")):
            yield quality, streams[quality]


__plugin__ = Stripchat


# >>> VENDORED LIBRARIES (generated by tools/vendor_h2.py, do not edit by hand) <<<
# ===========================================================================
# PART 2 -- VENDORED LIBRARIES: hyperframe 6.1.0, hpack 4.2.0, h2 4.4.1
#
# Pure-Python HTTP/2 protocol stack used by the plugin's HTTP/2 client
# (PART 1). Original code, flattened into this module: imports between these
# packages removed and only these clashing module-level names renamed:
#   h2.connection: _decode_headers -> _h2_connection_decode_headers
#   h2.stream: _decode_headers -> _h2_stream_decode_headers
#   h2.utilities: _to_bytes -> _h2_utilities_to_bytes
#   hpack.hpack: _to_bytes -> _hpack_hpack_to_bytes
#   hpack.hpack: log -> _hpack_hpack_log
#   hpack.table: log -> _hpack_table_log
# Modules appear in dependency order; each starts with a banner naming the
# original file. Regenerate with `python tools/vendor_h2.py`.
#
# Licenses (MIT):
#
# hyperframe 6.1.0 -- https://pypi.org/project/hyperframe/
#   The MIT License (MIT)
#
#   Copyright (c) 2014 Cory Benfield
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#   THE SOFTWARE.
#
# hpack 4.2.0 -- https://pypi.org/project/hpack/
#   The MIT License (MIT)
#
#   Copyright (c) 2014 Cory Benfield
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#   THE SOFTWARE.
#
# h2 4.4.1 -- https://pypi.org/project/h2/
#   The MIT License (MIT)
#
#   Copyright (c) 2015-2020 Cory Benfield and contributors
#
#   Permission is hereby granted, free of charge, to any person obtaining a copy
#   of this software and associated documentation files (the "Software"), to deal
#   in the Software without restriction, including without limitation the rights
#   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#   copies of the Software, and to permit persons to whom the Software is
#   furnished to do so, subject to the following conditions:
#
#   The above copyright notice and this permission notice shall be included in
#   all copies or substantial portions of the Software.
#
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
#   THE SOFTWARE.
#
# ===========================================================================


# ---------------------------------------------------------------------------
# hyperframe/__init__.py  (hyperframe 6.1.0)
# ---------------------------------------------------------------------------

"""
Provides a pure-Python HTTP/2 framing layer.
"""


# ---------------------------------------------------------------------------
# hyperframe/exceptions.py  (hyperframe 6.1.0)
# ---------------------------------------------------------------------------

"""
Exceptions that can be thrown by hyperframe.
"""


class HyperframeError(Exception):
    """
    The base class for all exceptions for the hyperframe module.

    .. versionadded:: 6.0.0
    """


class UnknownFrameError(HyperframeError):
    """
    A frame of unknown type was received.

    .. versionchanged:: 6.0.0
        Changed base class from `ValueError` to :class:`HyperframeError`
    """

    def __init__(self, frame_type: int, length: int) -> None:
        #: The type byte of the unknown frame that was received.
        self.frame_type = frame_type

        #: The length of the data portion of the unknown frame.
        self.length = length

    def __str__(self) -> str:
        return (
            f"UnknownFrameError: Unknown frame type 0x{self.frame_type:X} received, length {self.length} bytes"
        )


class InvalidPaddingError(HyperframeError):
    """
    A frame with invalid padding was received.

    .. versionchanged:: 6.0.0
        Changed base class from `ValueError` to :class:`HyperframeError`
    """


class InvalidFrameError(HyperframeError):
    """
    Parsing a frame failed because the data was not laid out appropriately.

    .. versionadded:: 3.0.2

    .. versionchanged:: 6.0.0
        Changed base class from `ValueError` to :class:`HyperframeError`
    """


class InvalidDataError(HyperframeError):
    """
    Content or data of a frame was is invalid or violates the specification.

    .. versionadded:: 6.0.0
    """


# ---------------------------------------------------------------------------
# hyperframe/flags.py  (hyperframe 6.1.0)
# ---------------------------------------------------------------------------

"""
Basic Flag and Flags data structures.
"""

from collections.abc import Iterable, Iterator, MutableSet
from typing import NamedTuple


class Flag(NamedTuple):
    name: str
    bit: int


class Flags(MutableSet):  # type: ignore
    """
    A simple MutableSet implementation that will only accept known flags as
    elements.

    Will behave like a regular set(), except that a ValueError will be thrown
    when .add()ing unexpected flags.
    """

    def __init__(self, defined_flags: Iterable[Flag]) -> None:
        self._valid_flags = {flag.name for flag in defined_flags}
        self._flags: set[str] = set()

    def __repr__(self) -> str:
        return repr(sorted(self._flags))

    def __contains__(self, x: object) -> bool:
        return self._flags.__contains__(x)

    def __iter__(self) -> Iterator[str]:
        return self._flags.__iter__()

    def __len__(self) -> int:
        return self._flags.__len__()

    def discard(self, value: str) -> None:
        return self._flags.discard(value)

    def add(self, value: str) -> None:
        if value not in self._valid_flags:
            msg = f"Unexpected flag: {value}. Valid flags are: {self._valid_flags}"
            raise ValueError(msg)
        return self._flags.add(value)


# ---------------------------------------------------------------------------
# hyperframe/frame.py  (hyperframe 6.1.0)
# ---------------------------------------------------------------------------

"""
Framing logic for HTTP/2.

Provides both classes to represent framed
data and logic for aiding the connection when it comes to reading from the
socket.
"""

import binascii
import struct
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Iterable  # pragma: no cover


# The maximum initial length of a frame. Some frames have shorter maximum
# lengths.
FRAME_MAX_LEN = (2 ** 14)

# The maximum allowed length of a frame.
FRAME_MAX_ALLOWED_LEN = (2 ** 24) - 1

# Stream association enumerations.
_STREAM_ASSOC_HAS_STREAM = "has-stream"
_STREAM_ASSOC_NO_STREAM = "no-stream"
_STREAM_ASSOC_EITHER = "either"

# Structs for packing and unpacking
_STRUCT_HBBBL = struct.Struct(">HBBBL")
_STRUCT_LL = struct.Struct(">LL")
_STRUCT_HL = struct.Struct(">HL")
_STRUCT_LB = struct.Struct(">LB")
_STRUCT_L = struct.Struct(">L")
_STRUCT_H = struct.Struct(">H")
_STRUCT_B = struct.Struct(">B")


class Frame:
    """
    The base class for all HTTP/2 frames.
    """

    #: The flags defined on this type of frame.
    defined_flags: list[Flag] = []

    #: The byte used to define the type of the frame.
    type: int | None = None

    # If 'has-stream', the frame's stream_id must be non-zero. If 'no-stream',
    # it must be zero. If 'either', it's not checked.
    stream_association: str | None = None

    def __init__(self, stream_id: int, flags: Iterable[str] = ()) -> None:
        #: The stream identifier for the stream this frame was received on.
        #: Set to 0 for frames sent on the connection (stream-id 0).
        self.stream_id = stream_id

        #: The flags set for this frame.
        self.flags = Flags(self.defined_flags)

        #: The frame length, excluding the nine-byte header.
        self.body_len = 0

        for flag in flags:
            self.flags.add(flag)

        if not self.stream_id and self.stream_association == _STREAM_ASSOC_HAS_STREAM:
            msg = f"Stream ID must be non-zero for {type(self).__name__}"
            raise InvalidDataError(msg)
        if self.stream_id and self.stream_association == _STREAM_ASSOC_NO_STREAM:
            msg = f"Stream ID must be zero for {type(self).__name__} with stream_id={self.stream_id}"
            raise InvalidDataError(msg)

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(stream_id={self.stream_id}, flags={self.flags!r}): {self._body_repr()}"
        )

    def _body_repr(self) -> str:
        # More specific implementation may be provided by subclasses of Frame.
        # This fallback shows the serialized (and truncated) body content.
        return _raw_data_repr(self.serialize_body())

    @staticmethod
    def explain(data: memoryview) -> tuple[Frame, int]:
        """
        Takes a bytestring and tries to parse a single frame and print it.

        This function is only provided for debugging purposes.

        :param data: A memoryview object containing the raw data of at least
                     one complete frame (header and body).

        .. versionadded:: 6.0.0
        """
        frame, length = Frame.parse_frame_header(data[:9])
        frame.parse_body(data[9:9 + length])
        print(frame)  # noqa: T201
        return frame, length

    @staticmethod
    def parse_frame_header(header: memoryview, strict: bool = False) -> tuple[Frame, int]:
        """
        Takes a 9-byte frame header and returns a tuple of the appropriate
        Frame object and the length that needs to be read from the socket.

        This populates the flags field, and determines how long the body is.

        :param header: A memoryview object containing the 9-byte frame header
                       data of a frame. Must not contain more or less.

        :param strict: Whether to raise an exception when encountering a frame
            not defined by spec and implemented by hyperframe.

        :raises hyperframe.exceptions.UnknownFrameError: If a frame of unknown
            type is received.

        .. versionchanged:: 5.0.0
            Added ``strict`` parameter to accommodate :class:`ExtensionFrame`
        """
        try:
            fields = _STRUCT_HBBBL.unpack(header)
        except struct.error as err:
            msg = "Invalid frame header"
            raise InvalidFrameError(msg) from err

        # First 24 bits are frame length.
        length = (fields[0] << 8) + fields[1]
        typ_e = fields[2]
        flags = fields[3]
        stream_id = fields[4] & 0x7FFFFFFF

        try:
            frame = FRAMES[typ_e](stream_id)
        except KeyError as err:
            if strict:
                raise UnknownFrameError(typ_e, length) from err
            frame = ExtensionFrame(type=typ_e, stream_id=stream_id)

        frame.parse_flags(flags)
        return (frame, length)

    def parse_flags(self, flag_byte: int) -> Flags:
        for flag, flag_bit in self.defined_flags:
            if flag_byte & flag_bit:
                self.flags.add(flag)

        return self.flags

    def serialize(self) -> bytes:
        """
        Convert a frame into a bytestring, representing the serialized form of
        the frame.
        """
        body = self.serialize_body()
        self.body_len = len(body)

        # Build the common frame header.
        # First, get the flags.
        flags = 0

        for flag, flag_bit in self.defined_flags:
            if flag in self.flags:
                flags |= flag_bit

        header = _STRUCT_HBBBL.pack(
            (self.body_len >> 8) & 0xFFFF,  # Length spread over top 24 bits
            self.body_len & 0xFF,
            self.type,
            flags,
            self.stream_id & 0x7FFFFFFF,  # Stream ID is 32 bits.
        )

        return header + body

    def serialize_body(self) -> bytes:
        raise NotImplementedError

    def parse_body(self, data: memoryview) -> None:
        """
        Given the body of a frame, parses it into frame data. This populates
        the non-header parts of the frame: that is, it does not populate the
        stream ID or flags.

        :param data: A memoryview object containing the body data of the frame.
                     Must not contain *more* data than the length returned by
                     :meth:`parse_frame_header
                     <hyperframe.frame.Frame.parse_frame_header>`.
        """
        raise NotImplementedError


class Padding:
    """
    Mixin for frames that contain padding. Defines extra fields that can be
    used and set by frames that can be padded.
    """

    def __init__(self, stream_id: int, pad_length: int = 0, **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)  # type: ignore

        #: The length of the padding to use.
        self.pad_length = pad_length

    def serialize_padding_data(self) -> bytes:
        if "PADDED" in self.flags:  # type: ignore
            return _STRUCT_B.pack(self.pad_length)
        return b""

    def parse_padding_data(self, data: memoryview) -> int:
        if "PADDED" in self.flags:  # type: ignore
            try:
                self.pad_length = struct.unpack("!B", data[:1])[0]
            except struct.error as err:
                msg = "Invalid Padding data"
                raise InvalidFrameError(msg) from err
            return 1
        return 0

    #: .. deprecated:: 5.2.1
    #:    Use self.pad_length instead.
    @property
    def total_padding(self) -> int:  # pragma: no cover
        import warnings
        warnings.warn(
            "total_padding contains the same information as pad_length.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.pad_length


class Priority:
    """
    Mixin for frames that contain priority data. Defines extra fields that can
    be used and set by frames that contain priority data.
    """

    def __init__(self,
                 stream_id: int,
                 depends_on: int = 0x0,
                 stream_weight: int = 0x0,
                 exclusive: bool = False,
                 **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)  # type: ignore

        #: The stream ID of the stream on which this stream depends.
        self.depends_on = depends_on

        #: The weight of the stream. This is an integer between 0 and 256.
        self.stream_weight = stream_weight

        #: Whether the exclusive bit was set.
        self.exclusive = exclusive

    def serialize_priority_data(self) -> bytes:
        return _STRUCT_LB.pack(
            self.depends_on + (0x80000000 if self.exclusive else 0),
            self.stream_weight,
        )

    def parse_priority_data(self, data: memoryview) -> int:
        try:
            self.depends_on, self.stream_weight = _STRUCT_LB.unpack(data[:5])
        except struct.error as err:
            msg = "Invalid Priority data"
            raise InvalidFrameError(msg) from err

        self.exclusive = bool(self.depends_on >> 31)
        self.depends_on &= 0x7FFFFFFF
        return 5


class DataFrame(Padding, Frame):
    """
    DATA frames convey arbitrary, variable-length sequences of octets
    associated with a stream. One or more DATA frames are used, for instance,
    to carry HTTP request or response payloads.
    """

    #: The flags defined for DATA frames.
    defined_flags = [
        Flag("END_STREAM", 0x01),
        Flag("PADDED", 0x08),
    ]

    #: The type byte for data frames.
    type = 0x0

    stream_association = _STREAM_ASSOC_HAS_STREAM

    def __init__(self, stream_id: int, data: bytes = b"", **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The data contained on this frame.
        self.data = data

    def serialize_body(self) -> bytes:
        padding_data = self.serialize_padding_data()
        padding = b"\0" * self.pad_length
        if isinstance(self.data, memoryview):
            self.data = self.data.tobytes()
        return b"".join([padding_data, self.data, padding])

    def parse_body(self, data: memoryview) -> None:
        padding_data_length = self.parse_padding_data(data)
        self.data = (
            data[padding_data_length:len(data)-self.pad_length].tobytes()
        )
        self.body_len = len(data)

        if self.pad_length and self.pad_length >= self.body_len:
            msg = "Padding is too long."
            raise InvalidPaddingError(msg)

    @property
    def flow_controlled_length(self) -> int:
        """
        The length of the frame that needs to be accounted for when considering
        flow control.
        """
        padding_len = 0
        if "PADDED" in self.flags:
            # Account for extra 1-byte padding length field, which is still
            # present if possibly zero-valued.
            padding_len = self.pad_length + 1
        return len(self.data) + padding_len


class PriorityFrame(Priority, Frame):
    """
    The PRIORITY frame specifies the sender-advised priority of a stream. It
    can be sent at any time for an existing stream. This enables
    reprioritisation of existing streams.
    """

    #: The flags defined for PRIORITY frames.
    defined_flags: list[Flag] = []

    #: The type byte defined for PRIORITY frames.
    type = 0x02

    stream_association = _STREAM_ASSOC_HAS_STREAM

    def _body_repr(self) -> str:
        return f"exclusive={self.exclusive}, depends_on={self.depends_on}, stream_weight={self.stream_weight}"

    def serialize_body(self) -> bytes:
        return self.serialize_priority_data()

    def parse_body(self, data: memoryview) -> None:
        if len(data) > 5:
            msg = f"PRIORITY must have 5 byte body: actual length {len(data)}."
            raise InvalidFrameError(msg)

        self.parse_priority_data(data)
        self.body_len = 5


class RstStreamFrame(Frame):
    """
    The RST_STREAM frame allows for abnormal termination of a stream. When sent
    by the initiator of a stream, it indicates that they wish to cancel the
    stream or that an error condition has occurred. When sent by the receiver
    of a stream, it indicates that either the receiver is rejecting the stream,
    requesting that the stream be cancelled or that an error condition has
    occurred.
    """

    #: The flags defined for RST_STREAM frames.
    defined_flags: list[Flag] = []

    #: The type byte defined for RST_STREAM frames.
    type = 0x03

    stream_association = _STREAM_ASSOC_HAS_STREAM

    def __init__(self, stream_id: int, error_code: int = 0, **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The error code used when resetting the stream.
        self.error_code = error_code

    def _body_repr(self) -> str:
        return f"error_code={self.error_code}"

    def serialize_body(self) -> bytes:
        return _STRUCT_L.pack(self.error_code)

    def parse_body(self, data: memoryview) -> None:
        if len(data) != 4:
            msg = f"RST_STREAM must have 4 byte body: actual length {len(data)}."
            raise InvalidFrameError(msg)

        try:
            self.error_code = _STRUCT_L.unpack(data)[0]
        except struct.error as err:  # pragma: no cover
            msg = "Invalid RST_STREAM body"
            raise InvalidFrameError(msg) from err

        self.body_len = 4


class SettingsFrame(Frame):
    """
    The SETTINGS frame conveys configuration parameters that affect how
    endpoints communicate. The parameters are either constraints on peer
    behavior or preferences.

    Settings are not negotiated. Settings describe characteristics of the
    sending peer, which are used by the receiving peer. Different values for
    the same setting can be advertised by each peer. For example, a client
    might set a high initial flow control window, whereas a server might set a
    lower value to conserve resources.
    """

    #: The flags defined for SETTINGS frames.
    defined_flags = [Flag("ACK", 0x01)]

    #: The type byte defined for SETTINGS frames.
    type = 0x04

    stream_association = _STREAM_ASSOC_NO_STREAM

    # We need to define the known settings, they may as well be class
    # attributes.
    #: The byte that signals the SETTINGS_HEADER_TABLE_SIZE setting.
    HEADER_TABLE_SIZE = 0x01
    #: The byte that signals the SETTINGS_ENABLE_PUSH setting.
    ENABLE_PUSH = 0x02
    #: The byte that signals the SETTINGS_MAX_CONCURRENT_STREAMS setting.
    MAX_CONCURRENT_STREAMS = 0x03
    #: The byte that signals the SETTINGS_INITIAL_WINDOW_SIZE setting.
    INITIAL_WINDOW_SIZE = 0x04
    #: The byte that signals the SETTINGS_MAX_FRAME_SIZE setting.
    MAX_FRAME_SIZE = 0x05
    #: The byte that signals the SETTINGS_MAX_HEADER_LIST_SIZE setting.
    MAX_HEADER_LIST_SIZE = 0x06
    #: The byte that signals SETTINGS_ENABLE_CONNECT_PROTOCOL setting.
    ENABLE_CONNECT_PROTOCOL = 0x08

    def __init__(self, stream_id: int = 0, settings: dict[int, int] | None = None, **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        if settings and "ACK" in kwargs.get("flags", ()):
            msg = "Settings must be empty if ACK flag is set."
            raise InvalidDataError(msg)

        #: A dictionary of the setting type byte to the value of the setting.
        self.settings: dict[int, int] = settings or {}

    def _body_repr(self) -> str:
        return f"settings={self.settings}"

    def serialize_body(self) -> bytes:
        return b"".join([_STRUCT_HL.pack(setting & 0xFF, value)
                         for setting, value in self.settings.items()])

    def parse_body(self, data: memoryview) -> None:
        if "ACK" in self.flags and len(data) > 0:
            msg = f"SETTINGS ack frame must not have payload: got {len(data)} bytes"
            raise InvalidDataError(msg)

        body_len = 0
        for i in range(0, len(data), 6):
            try:
                name, value = _STRUCT_HL.unpack(data[i:i+6])
            except struct.error as err:
                msg = "Invalid SETTINGS body"
                raise InvalidFrameError(msg) from err

            self.settings[name] = value
            body_len += 6

        self.body_len = body_len


class PushPromiseFrame(Padding, Frame):
    """
    The PUSH_PROMISE frame is used to notify the peer endpoint in advance of
    streams the sender intends to initiate.
    """

    #: The flags defined for PUSH_PROMISE frames.
    defined_flags = [
        Flag("END_HEADERS", 0x04),
        Flag("PADDED", 0x08),
    ]

    #: The type byte defined for PUSH_PROMISE frames.
    type = 0x05

    stream_association = _STREAM_ASSOC_HAS_STREAM

    def __init__(self, stream_id: int, promised_stream_id: int = 0, data: bytes = b"", **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The stream ID that is promised by this frame.
        self.promised_stream_id = promised_stream_id

        #: The HPACK-encoded header block for the simulated request on the new
        #: stream.
        self.data = data

    def _body_repr(self) -> str:
        return f"promised_stream_id={self.promised_stream_id}, data={_raw_data_repr(self.data)}"

    def serialize_body(self) -> bytes:
        padding_data = self.serialize_padding_data()
        padding = b"\0" * self.pad_length
        data = _STRUCT_L.pack(self.promised_stream_id)
        return b"".join([padding_data, data, self.data, padding])

    def parse_body(self, data: memoryview) -> None:
        padding_data_length = self.parse_padding_data(data)

        try:
            self.promised_stream_id = _STRUCT_L.unpack(
                data[padding_data_length:padding_data_length + 4],
            )[0]
        except struct.error as err:
            msg = "Invalid PUSH_PROMISE body"
            raise InvalidFrameError(msg) from err

        self.data = (
            data[padding_data_length + 4:len(data)-self.pad_length].tobytes()
        )
        self.body_len = len(data)

        if self.promised_stream_id == 0 or self.promised_stream_id % 2 != 0:
            msg = f"Invalid PUSH_PROMISE promised stream id: {self.promised_stream_id}"
            raise InvalidDataError(msg)

        if self.pad_length and self.pad_length >= self.body_len:
            msg = "Padding is too long."
            raise InvalidPaddingError(msg)


class PingFrame(Frame):
    """
    The PING frame is a mechanism for measuring a minimal round-trip time from
    the sender, as well as determining whether an idle connection is still
    functional. PING frames can be sent from any endpoint.
    """

    #: The flags defined for PING frames.
    defined_flags = [Flag("ACK", 0x01)]

    #: The type byte defined for PING frames.
    type = 0x06

    stream_association = _STREAM_ASSOC_NO_STREAM

    def __init__(self, stream_id: int = 0, opaque_data: bytes = b"", **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The opaque data sent in this PING frame, as a bytestring.
        self.opaque_data = opaque_data

    def _body_repr(self) -> str:
        return f"opaque_data={self.opaque_data!r}"

    def serialize_body(self) -> bytes:
        if len(self.opaque_data) > 8:
            msg = f"PING frame may not have more than 8 bytes of data, got {len(self.opaque_data)}"
            raise InvalidFrameError(msg)

        data = self.opaque_data
        data += b"\x00" * (8 - len(self.opaque_data))
        return data

    def parse_body(self, data: memoryview) -> None:
        if len(data) != 8:
            msg = f"PING frame must have 8 byte length: got {len(data)}"
            raise InvalidFrameError(msg)

        self.opaque_data = data.tobytes()
        self.body_len = 8


class GoAwayFrame(Frame):
    """
    The GOAWAY frame informs the remote peer to stop creating streams on this
    connection. It can be sent from the client or the server. Once sent, the
    sender will ignore frames sent on new streams for the remainder of the
    connection.
    """

    #: The flags defined for GOAWAY frames.
    defined_flags: list[Flag] = []

    #: The type byte defined for GOAWAY frames.
    type = 0x07

    stream_association = _STREAM_ASSOC_NO_STREAM

    def __init__(self,
                 stream_id: int = 0,
                 last_stream_id: int = 0,
                 error_code: int = 0,
                 additional_data: bytes = b"",
                 **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The last stream ID definitely seen by the remote peer.
        self.last_stream_id = last_stream_id

        #: The error code for connection teardown.
        self.error_code = error_code

        #: Any additional data sent in the GOAWAY.
        self.additional_data = additional_data

    def _body_repr(self) -> str:
        return f"last_stream_id={self.last_stream_id}, error_code={self.error_code}, additional_data={self.additional_data!r}"

    def serialize_body(self) -> bytes:
        data = _STRUCT_LL.pack(
            self.last_stream_id & 0x7FFFFFFF,
            self.error_code,
        )
        data += self.additional_data

        return data

    def parse_body(self, data: memoryview) -> None:
        try:
            self.last_stream_id, self.error_code = _STRUCT_LL.unpack(
                data[:8],
            )
        except struct.error as err:
            msg = "Invalid GOAWAY body."
            raise InvalidFrameError(msg) from err

        self.body_len = len(data)

        if len(data) > 8:
            self.additional_data = data[8:].tobytes()


class WindowUpdateFrame(Frame):
    """
    The WINDOW_UPDATE frame is used to implement flow control.

    Flow control operates at two levels: on each individual stream and on the
    entire connection.

    Both types of flow control are hop by hop; that is, only between the two
    endpoints. Intermediaries do not forward WINDOW_UPDATE frames between
    dependent connections. However, throttling of data transfer by any receiver
    can indirectly cause the propagation of flow control information toward the
    original sender.
    """

    #: The flags defined for WINDOW_UPDATE frames.
    defined_flags: list[Flag] = []

    #: The type byte defined for WINDOW_UPDATE frames.
    type = 0x08

    stream_association = _STREAM_ASSOC_EITHER

    def __init__(self, stream_id: int, window_increment: int = 0, **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The amount the flow control window is to be incremented.
        self.window_increment = window_increment

    def _body_repr(self) -> str:
        return f"window_increment={self.window_increment}"

    def serialize_body(self) -> bytes:
        return _STRUCT_L.pack(self.window_increment & 0x7FFFFFFF)

    def parse_body(self, data: memoryview) -> None:
        if len(data) > 4:
            msg = f"WINDOW_UPDATE frame must have 4 byte length: got {len(data)}"
            raise InvalidFrameError(msg)

        try:
            self.window_increment = _STRUCT_L.unpack(data)[0]
        except struct.error as err:
            msg = "Invalid WINDOW_UPDATE body"
            raise InvalidFrameError(msg) from err

        if not 1 <= self.window_increment <= 2**31-1:
            msg = "WINDOW_UPDATE increment must be between 1 to 2^31-1"
            raise InvalidDataError(msg)

        self.body_len = 4


class HeadersFrame(Padding, Priority, Frame):
    """
    The HEADERS frame carries name-value pairs. It is used to open a stream.
    HEADERS frames can be sent on a stream in the "open" or "half closed
    (remote)" states.

    The HeadersFrame class is actually basically a data frame in this
    implementation, because of the requirement to control the sizes of frames.
    A header block fragment that doesn't fit in an entire HEADERS frame needs
    to be followed with CONTINUATION frames. From the perspective of the frame
    building code the header block is an opaque data segment.
    """

    #: The flags defined for HEADERS frames.
    defined_flags = [
        Flag("END_STREAM", 0x01),
        Flag("END_HEADERS", 0x04),
        Flag("PADDED", 0x08),
        Flag("PRIORITY", 0x20),
    ]

    #: The type byte defined for HEADERS frames.
    type = 0x01

    stream_association = _STREAM_ASSOC_HAS_STREAM

    def __init__(self, stream_id: int, data: bytes = b"", **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The HPACK-encoded header block.
        self.data = data

    def _body_repr(self) -> str:
        return f"exclusive={self.exclusive}, depends_on={self.depends_on}, stream_weight={self.stream_weight}, data={_raw_data_repr(self.data)}"

    def serialize_body(self) -> bytes:
        padding_data = self.serialize_padding_data()
        padding = b"\0" * self.pad_length

        if "PRIORITY" in self.flags:
            priority_data = self.serialize_priority_data()
        else:
            priority_data = b""

        return b"".join([padding_data, priority_data, self.data, padding])

    def parse_body(self, data: memoryview) -> None:
        padding_data_length = self.parse_padding_data(data)
        data = data[padding_data_length:]

        if "PRIORITY" in self.flags:
            priority_data_length = self.parse_priority_data(data)
        else:
            priority_data_length = 0

        self.body_len = len(data)
        self.data = (
            data[priority_data_length:len(data)-self.pad_length].tobytes()
        )

        if self.pad_length and self.pad_length >= self.body_len:
            msg = "Padding is too long."
            raise InvalidPaddingError(msg)


class ContinuationFrame(Frame):
    """
    The CONTINUATION frame is used to continue a sequence of header block
    fragments. Any number of CONTINUATION frames can be sent on an existing
    stream, as long as the preceding frame on the same stream is one of
    HEADERS, PUSH_PROMISE or CONTINUATION without the END_HEADERS flag set.

    Much like the HEADERS frame, hyper treats this as an opaque data frame with
    different flags and a different type.
    """

    #: The flags defined for CONTINUATION frames.
    defined_flags = [Flag("END_HEADERS", 0x04)]

    #: The type byte defined for CONTINUATION frames.
    type = 0x09

    stream_association = _STREAM_ASSOC_HAS_STREAM

    def __init__(self, stream_id: int, data: bytes = b"", **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        #: The HPACK-encoded header block.
        self.data = data

    def _body_repr(self) -> str:
        return f"data={_raw_data_repr(self.data)}"

    def serialize_body(self) -> bytes:
        return self.data

    def parse_body(self, data: memoryview) -> None:
        self.data = data.tobytes()
        self.body_len = len(data)


class AltSvcFrame(Frame):
    """
    The ALTSVC frame is used to advertise alternate services that the current
    host, or a different one, can understand. This frame is standardised as
    part of RFC 7838.

    This frame does no work to validate that the ALTSVC field parameter is
    acceptable per the rules of RFC 7838.

    .. note:: If the ``stream_id`` of this frame is nonzero, the origin field
              must have zero length. Conversely, if the ``stream_id`` of this
              frame is zero, the origin field must have nonzero length. Put
              another way, a valid ALTSVC frame has ``stream_id != 0`` XOR
              ``len(origin) != 0``.
    """

    type = 0x0A

    stream_association = _STREAM_ASSOC_EITHER

    def __init__(self, stream_id: int, origin: bytes = b"", field: bytes = b"", **kwargs: Any) -> None:
        super().__init__(stream_id, **kwargs)

        if not isinstance(origin, bytes):
            msg = "AltSvc origin must be a bytestring."
            raise InvalidDataError(msg)
        if not isinstance(field, bytes):
            msg = "AltSvc field must be a bytestring."
            raise InvalidDataError(msg)
        self.origin = origin
        self.field = field

    def _body_repr(self) -> str:
        return f"origin={self.origin!r}, field={self.field!r}"

    def serialize_body(self) -> bytes:
        origin_len = _STRUCT_H.pack(len(self.origin))
        return b"".join([origin_len, self.origin, self.field])

    def parse_body(self, data: memoryview) -> None:
        try:
            origin_len = _STRUCT_H.unpack(data[0:2])[0]
            self.origin = data[2:2+origin_len].tobytes()

            if len(self.origin) != origin_len:
                msg = "Invalid ALTSVC frame body."
                raise InvalidFrameError(msg)

            self.field = data[2+origin_len:].tobytes()
        except (struct.error, ValueError) as err:
            msg = "Invalid ALTSVC frame body."
            raise InvalidFrameError(msg) from err

        self.body_len = len(data)


class ExtensionFrame(Frame):
    """
    ExtensionFrame is used to wrap frames which are not natively interpretable
    by hyperframe.

    Although certain byte prefixes are ordained by specification to have
    certain contextual meanings, frames with other prefixes are not prohibited,
    and may be used to communicate arbitrary meaning between HTTP/2 peers.

    Thus, hyperframe, rather than raising an exception when such a frame is
    encountered, wraps it in a generic frame to be properly acted upon by
    upstream consumers which might have additional context on how to use it.

    .. versionadded:: 5.0.0
    """

    stream_association = _STREAM_ASSOC_EITHER

    def __init__(self, type: int, stream_id: int, flag_byte: int = 0x0, body: bytes = b"", **kwargs: Any) -> None:  # noqa: A002
        super().__init__(stream_id, **kwargs)
        self.type = type
        self.flag_byte = flag_byte
        self.body = body

    def _body_repr(self) -> str:
        return f"type={self.type}, flag_byte={self.flag_byte}, body={_raw_data_repr(self.body)}"

    def parse_flags(self, flag_byte: int) -> None:  # type: ignore
        """
        For extension frames, we parse the flags by just storing a flag byte.
        """
        self.flag_byte = flag_byte

    def parse_body(self, data: memoryview) -> None:
        self.body = data.tobytes()
        self.body_len = len(data)

    def serialize(self) -> bytes:
        """
        A broad override of the serialize method that ensures that the data
        comes back out exactly as it came in. This should not be used in most
        user code: it exists only as a helper method if frames need to be
        reconstituted.
        """
        # Build the frame header.
        # First, get the flags.
        flags = self.flag_byte

        header = _STRUCT_HBBBL.pack(
            (self.body_len >> 8) & 0xFFFF,  # Length spread over top 24 bits
            self.body_len & 0xFF,
            self.type,
            flags,
            self.stream_id & 0x7FFFFFFF,  # Stream ID is 32 bits.
        )

        return header + self.body


def _raw_data_repr(data: bytes | None) -> str:
    if not data:
        return "None"
    r = binascii.hexlify(data).decode("ascii")
    if len(r) > 20:
        r = r[:20] + "..."
    return "<hex:" + r + ">"


_FRAME_CLASSES: list[type[Frame]] = [
    DataFrame,
    HeadersFrame,
    PriorityFrame,
    RstStreamFrame,
    SettingsFrame,
    PushPromiseFrame,
    PingFrame,
    GoAwayFrame,
    WindowUpdateFrame,
    ContinuationFrame,
    AltSvcFrame,
]
#: FRAMES maps the type byte for each frame to the class used to represent that
#: frame.
FRAMES = {cls.type: cls for cls in _FRAME_CLASSES}


# ---------------------------------------------------------------------------
# hpack/exceptions.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
Exceptions used in hpack.
"""


class HPACKError(Exception):
    """
    The base class for all ``hpack`` exceptions.
    """


class HPACKDecodingError(HPACKError):
    """
    An error has been encountered while performing HPACK decoding.
    """


class InvalidTableIndexError(HPACKDecodingError):
    """
    An invalid table index was received.

    .. versionadded:: 4.1.0
    """

class InvalidTableIndex(InvalidTableIndexError):  # noqa: N818
    """
    An invalid table index was received.

    .. deprecated:: 4.1.0
       Renamed to :class:`InvalidTableIndexError`, use it instead.
    """


class OversizedHeaderListError(HPACKDecodingError):
    """
    A header list that was larger than we allow has been received. This may be
    a DoS attack.

    .. versionadded:: 2.3.0
    """


class InvalidTableSizeError(HPACKDecodingError):
    """
    An attempt was made to change the decoder table size to a value larger than
    allowed, or the list was shrunk and the remote peer didn't shrink their
    table size.

    .. versionadded:: 3.0.0
    """


# ---------------------------------------------------------------------------
# hpack/huffman.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
An implementation of a bitwise prefix tree specially built for decoding
Huffman-coded content where we already know the Huffman table.
"""


class HuffmanEncoder:
    """
    Encodes a string according to the Huffman encoding table defined in the
    HPACK specification.
    """

    def __init__(self, huffman_code_list: list[int], huffman_code_list_lengths: list[int]) -> None:
        self.huffman_code_list = huffman_code_list
        self.huffman_code_list_lengths = huffman_code_list_lengths

    def encode(self, bytes_to_encode: bytes | None) -> bytes:
        """
        Given a string of bytes, encodes them according to the HPACK Huffman
        specification.
        """
        # If handed the empty string, just immediately return.
        if not bytes_to_encode:
            return b""

        final_num = 0
        final_int_len = 0

        # Turn each byte into its huffman code. These codes aren't necessarily
        # octet aligned, so keep track of how far through an octet we are. To
        # handle this cleanly, just use a single giant integer.
        for byte in bytes_to_encode:
            bin_int_len = self.huffman_code_list_lengths[byte]
            bin_int = self.huffman_code_list[byte] & (
                2 ** (bin_int_len + 1) - 1
            )
            final_num <<= bin_int_len
            final_num |= bin_int
            final_int_len += bin_int_len

        # Pad out to an octet with ones.
        bits_to_be_padded = (8 - (final_int_len % 8)) % 8
        final_num <<= bits_to_be_padded
        final_num |= (1 << bits_to_be_padded) - 1

        # Convert the number to hex without leading '0x' or trailing 'L'.
        s = f"{final_num:x}"

        # If this is odd, prepend a zero.
        s = "0" + s if len(s) % 2 != 0 else s

        # This number should have twice as many digits as bytes. If not, we're
        # missing some leading zeroes. Work out how many bytes we want and how
        # many digits we have, then add the missing zero digits to the front.
        total_bytes = (final_int_len + bits_to_be_padded) // 8
        expected_digits = total_bytes * 2

        if len(s) != expected_digits:
            missing_digits = expected_digits - len(s)
            s = ("0" * missing_digits) + s

        return bytes.fromhex(s)


# ---------------------------------------------------------------------------
# hpack/huffman_constants.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
Defines the constant Huffman table. This takes up an upsetting amount of space,
but c'est la vie.
"""
# flake8: noqa

REQUEST_CODES = [
    0x1ff8,
    0x7fffd8,
    0xfffffe2,
    0xfffffe3,
    0xfffffe4,
    0xfffffe5,
    0xfffffe6,
    0xfffffe7,
    0xfffffe8,
    0xffffea,
    0x3ffffffc,
    0xfffffe9,
    0xfffffea,
    0x3ffffffd,
    0xfffffeb,
    0xfffffec,
    0xfffffed,
    0xfffffee,
    0xfffffef,
    0xffffff0,
    0xffffff1,
    0xffffff2,
    0x3ffffffe,
    0xffffff3,
    0xffffff4,
    0xffffff5,
    0xffffff6,
    0xffffff7,
    0xffffff8,
    0xffffff9,
    0xffffffa,
    0xffffffb,
    0x14,
    0x3f8,
    0x3f9,
    0xffa,
    0x1ff9,
    0x15,
    0xf8,
    0x7fa,
    0x3fa,
    0x3fb,
    0xf9,
    0x7fb,
    0xfa,
    0x16,
    0x17,
    0x18,
    0x0,
    0x1,
    0x2,
    0x19,
    0x1a,
    0x1b,
    0x1c,
    0x1d,
    0x1e,
    0x1f,
    0x5c,
    0xfb,
    0x7ffc,
    0x20,
    0xffb,
    0x3fc,
    0x1ffa,
    0x21,
    0x5d,
    0x5e,
    0x5f,
    0x60,
    0x61,
    0x62,
    0x63,
    0x64,
    0x65,
    0x66,
    0x67,
    0x68,
    0x69,
    0x6a,
    0x6b,
    0x6c,
    0x6d,
    0x6e,
    0x6f,
    0x70,
    0x71,
    0x72,
    0xfc,
    0x73,
    0xfd,
    0x1ffb,
    0x7fff0,
    0x1ffc,
    0x3ffc,
    0x22,
    0x7ffd,
    0x3,
    0x23,
    0x4,
    0x24,
    0x5,
    0x25,
    0x26,
    0x27,
    0x6,
    0x74,
    0x75,
    0x28,
    0x29,
    0x2a,
    0x7,
    0x2b,
    0x76,
    0x2c,
    0x8,
    0x9,
    0x2d,
    0x77,
    0x78,
    0x79,
    0x7a,
    0x7b,
    0x7ffe,
    0x7fc,
    0x3ffd,
    0x1ffd,
    0xffffffc,
    0xfffe6,
    0x3fffd2,
    0xfffe7,
    0xfffe8,
    0x3fffd3,
    0x3fffd4,
    0x3fffd5,
    0x7fffd9,
    0x3fffd6,
    0x7fffda,
    0x7fffdb,
    0x7fffdc,
    0x7fffdd,
    0x7fffde,
    0xffffeb,
    0x7fffdf,
    0xffffec,
    0xffffed,
    0x3fffd7,
    0x7fffe0,
    0xffffee,
    0x7fffe1,
    0x7fffe2,
    0x7fffe3,
    0x7fffe4,
    0x1fffdc,
    0x3fffd8,
    0x7fffe5,
    0x3fffd9,
    0x7fffe6,
    0x7fffe7,
    0xffffef,
    0x3fffda,
    0x1fffdd,
    0xfffe9,
    0x3fffdb,
    0x3fffdc,
    0x7fffe8,
    0x7fffe9,
    0x1fffde,
    0x7fffea,
    0x3fffdd,
    0x3fffde,
    0xfffff0,
    0x1fffdf,
    0x3fffdf,
    0x7fffeb,
    0x7fffec,
    0x1fffe0,
    0x1fffe1,
    0x3fffe0,
    0x1fffe2,
    0x7fffed,
    0x3fffe1,
    0x7fffee,
    0x7fffef,
    0xfffea,
    0x3fffe2,
    0x3fffe3,
    0x3fffe4,
    0x7ffff0,
    0x3fffe5,
    0x3fffe6,
    0x7ffff1,
    0x3ffffe0,
    0x3ffffe1,
    0xfffeb,
    0x7fff1,
    0x3fffe7,
    0x7ffff2,
    0x3fffe8,
    0x1ffffec,
    0x3ffffe2,
    0x3ffffe3,
    0x3ffffe4,
    0x7ffffde,
    0x7ffffdf,
    0x3ffffe5,
    0xfffff1,
    0x1ffffed,
    0x7fff2,
    0x1fffe3,
    0x3ffffe6,
    0x7ffffe0,
    0x7ffffe1,
    0x3ffffe7,
    0x7ffffe2,
    0xfffff2,
    0x1fffe4,
    0x1fffe5,
    0x3ffffe8,
    0x3ffffe9,
    0xffffffd,
    0x7ffffe3,
    0x7ffffe4,
    0x7ffffe5,
    0xfffec,
    0xfffff3,
    0xfffed,
    0x1fffe6,
    0x3fffe9,
    0x1fffe7,
    0x1fffe8,
    0x7ffff3,
    0x3fffea,
    0x3fffeb,
    0x1ffffee,
    0x1ffffef,
    0xfffff4,
    0xfffff5,
    0x3ffffea,
    0x7ffff4,
    0x3ffffeb,
    0x7ffffe6,
    0x3ffffec,
    0x3ffffed,
    0x7ffffe7,
    0x7ffffe8,
    0x7ffffe9,
    0x7ffffea,
    0x7ffffeb,
    0xffffffe,
    0x7ffffec,
    0x7ffffed,
    0x7ffffee,
    0x7ffffef,
    0x7fffff0,
    0x3ffffee,
    0x3fffffff,
]

REQUEST_CODES_LENGTH = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
     6, 10, 10, 12, 13,  6,  8, 11, 10, 10,  8, 11,  8,  6,  6,  6,
     5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8, 15,  6, 12, 10,
    13,  6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
     7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8, 13, 19, 13, 14,  6,
    15,  5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
     6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
]


# ---------------------------------------------------------------------------
# hpack/huffman_table.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
Implementation of a Huffman decoding table for HTTP/2.

This is essentially a Python port of the work originally done for nghttp2's
Huffman decoding. For this reason, while this file is made available under the
MIT license as is the rest of this module, this file is undoubtedly a
derivative work of the nghttp2 file ``nghttp2_hd_huffman_data.c``, obtained
from https://github.com/tatsuhiro-t/nghttp2/ at commit
d2b55ad1a245e1d1964579fa3fac36ebf3939e72. That work is made available under
the Apache 2.0 license under the following terms:

    Copyright (c) 2013 Tatsuhiro Tsujikawa

    Permission is hereby granted, free of charge, to any person obtaining
    a copy of this software and associated documentation files (the
    "Software"), to deal in the Software without restriction, including
    without limitation the rights to use, copy, modify, merge, publish,
    distribute, sublicense, and/or sell copies of the Software, and to
    permit persons to whom the Software is furnished to do so, subject to
    the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

The essence of this approach is that it builds a finite state machine out of
4-bit nibbles of Huffman coded data. The input function passes 4 bits worth of
data to the state machine each time, which uses those 4 bits of data along with
the current accumulated state data to process the data given.

For the sake of efficiency, the in-memory representation of the states,
transitions, and result values of the state machine are represented as a long
list containing three-tuples. This list is enormously long, and viewing it as
an in-memory representation is not very clear, but it is laid out here in a way
that is intended to be *somewhat* more clear.

Essentially, the list is structured as 256 collections of 16 entries (one for
each nibble) of three-tuples. Each collection is called a "node", and the
zeroth collection is called the "root node". The state machine tracks one
value: the "state" byte.

For each nibble passed to the state machine, it first multiplies the "state"
byte by 16 and adds the numerical value of the nibble. This number is the index
into the large flat list.

The three-tuple that is found by looking up that index consists of three
values:

- a new state value, used for subsequent decoding
- a collection of flags, used to determine whether data is emitted or whether
  the state machine is complete.
- the byte value to emit, assuming that emitting a byte is required.

The flags are consulted, if necessary a byte is emitted, and then the next
nibble is used. This continues until the state machine believes it has
completely Huffman-decoded the data.

This approach has relatively little indirection, and therefore performs
relatively well, particularly on implementations like PyPy where the cost of
loops at the Python-level is not too expensive. The total number of loop
iterations is 4x the number of bytes passed to the decoder.
"""


# This defines the state machine "class" at the top of the file. The reason we
# do this is to keep the terrifing monster state table at the *bottom* of the
# file so you don't have to actually *look* at the damn thing.
def decode_huffman(huffman_string: bytes | bytearray | memoryview | None) -> bytes:
    """
    Given a bytestring of Huffman-encoded data for HPACK, returns a bytestring
    of the decompressed data.
    """
    if not huffman_string:
        return b""

    state = 0
    flags = 0
    decoded_bytes = bytearray()

    # Perversely, bytearrays are a lot more convenient across Python 2 and
    # Python 3 because they behave *the same way* on both platforms. Given that
    # we really do want numerical bytes when we iterate here, let's use a
    # bytearray.
    huffman_string = bytearray(huffman_string)

    # This loop is unrolled somewhat. Because we use a nibble, not a byte, we
    # need to handle each nibble twice. We unroll that: it makes the loop body
    # a bit longer, but that's ok.
    for input_byte in huffman_string:
        index = (state * 16) + (input_byte >> 4)
        state, flags, output_byte = HUFFMAN_TABLE[index]

        if flags & HUFFMAN_FAIL:
            msg = "Invalid Huffman string"
            raise HPACKDecodingError(msg)

        if flags & HUFFMAN_EMIT_SYMBOL:
            decoded_bytes.append(output_byte)

        index = (state * 16) + (input_byte & 0x0F)
        state, flags, output_byte = HUFFMAN_TABLE[index]

        if flags & HUFFMAN_FAIL:
            msg = "Invalid Huffman string"
            raise HPACKDecodingError(msg)

        if flags & HUFFMAN_EMIT_SYMBOL:
            decoded_bytes.append(output_byte)

    if not (flags & HUFFMAN_COMPLETE):
        msg = "Incomplete Huffman string"
        raise HPACKDecodingError(msg)

    return bytes(decoded_bytes)


# Some decoder flags to control state transitions.
HUFFMAN_COMPLETE = 1
HUFFMAN_EMIT_SYMBOL = (1 << 1)
HUFFMAN_FAIL = (1 << 2)

# This is the monster table. Avert your eyes, children.
HUFFMAN_TABLE = [
    # Node 0 (Root Node, never emits symbols.)
    (4, 0, 0),
    (5, 0, 0),
    (7, 0, 0),
    (8, 0, 0),
    (11, 0, 0),
    (12, 0, 0),
    (16, 0, 0),
    (19, 0, 0),
    (25, 0, 0),
    (28, 0, 0),
    (32, 0, 0),
    (35, 0, 0),
    (42, 0, 0),
    (49, 0, 0),
    (57, 0, 0),
    (64, HUFFMAN_COMPLETE, 0),

    # Node 1
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 48),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 49),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 50),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 97),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 99),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 101),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 105),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 111),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 115),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 116),
    (13, 0, 0),
    (14, 0, 0),
    (17, 0, 0),
    (18, 0, 0),
    (20, 0, 0),
    (21, 0, 0),

    # Node 2
    (1, HUFFMAN_EMIT_SYMBOL, 48),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 48),
    (1, HUFFMAN_EMIT_SYMBOL, 49),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 49),
    (1, HUFFMAN_EMIT_SYMBOL, 50),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 50),
    (1, HUFFMAN_EMIT_SYMBOL, 97),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 97),
    (1, HUFFMAN_EMIT_SYMBOL, 99),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 99),
    (1, HUFFMAN_EMIT_SYMBOL, 101),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 101),
    (1, HUFFMAN_EMIT_SYMBOL, 105),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 105),
    (1, HUFFMAN_EMIT_SYMBOL, 111),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 111),

    # Node 3
    (2, HUFFMAN_EMIT_SYMBOL, 48),
    (9, HUFFMAN_EMIT_SYMBOL, 48),
    (23, HUFFMAN_EMIT_SYMBOL, 48),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 48),
    (2, HUFFMAN_EMIT_SYMBOL, 49),
    (9, HUFFMAN_EMIT_SYMBOL, 49),
    (23, HUFFMAN_EMIT_SYMBOL, 49),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 49),
    (2, HUFFMAN_EMIT_SYMBOL, 50),
    (9, HUFFMAN_EMIT_SYMBOL, 50),
    (23, HUFFMAN_EMIT_SYMBOL, 50),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 50),
    (2, HUFFMAN_EMIT_SYMBOL, 97),
    (9, HUFFMAN_EMIT_SYMBOL, 97),
    (23, HUFFMAN_EMIT_SYMBOL, 97),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 97),

    # Node 4
    (3, HUFFMAN_EMIT_SYMBOL, 48),
    (6, HUFFMAN_EMIT_SYMBOL, 48),
    (10, HUFFMAN_EMIT_SYMBOL, 48),
    (15, HUFFMAN_EMIT_SYMBOL, 48),
    (24, HUFFMAN_EMIT_SYMBOL, 48),
    (31, HUFFMAN_EMIT_SYMBOL, 48),
    (41, HUFFMAN_EMIT_SYMBOL, 48),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 48),
    (3, HUFFMAN_EMIT_SYMBOL, 49),
    (6, HUFFMAN_EMIT_SYMBOL, 49),
    (10, HUFFMAN_EMIT_SYMBOL, 49),
    (15, HUFFMAN_EMIT_SYMBOL, 49),
    (24, HUFFMAN_EMIT_SYMBOL, 49),
    (31, HUFFMAN_EMIT_SYMBOL, 49),
    (41, HUFFMAN_EMIT_SYMBOL, 49),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 49),

    # Node 5
    (3, HUFFMAN_EMIT_SYMBOL, 50),
    (6, HUFFMAN_EMIT_SYMBOL, 50),
    (10, HUFFMAN_EMIT_SYMBOL, 50),
    (15, HUFFMAN_EMIT_SYMBOL, 50),
    (24, HUFFMAN_EMIT_SYMBOL, 50),
    (31, HUFFMAN_EMIT_SYMBOL, 50),
    (41, HUFFMAN_EMIT_SYMBOL, 50),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 50),
    (3, HUFFMAN_EMIT_SYMBOL, 97),
    (6, HUFFMAN_EMIT_SYMBOL, 97),
    (10, HUFFMAN_EMIT_SYMBOL, 97),
    (15, HUFFMAN_EMIT_SYMBOL, 97),
    (24, HUFFMAN_EMIT_SYMBOL, 97),
    (31, HUFFMAN_EMIT_SYMBOL, 97),
    (41, HUFFMAN_EMIT_SYMBOL, 97),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 97),

    # Node 6
    (2, HUFFMAN_EMIT_SYMBOL, 99),
    (9, HUFFMAN_EMIT_SYMBOL, 99),
    (23, HUFFMAN_EMIT_SYMBOL, 99),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 99),
    (2, HUFFMAN_EMIT_SYMBOL, 101),
    (9, HUFFMAN_EMIT_SYMBOL, 101),
    (23, HUFFMAN_EMIT_SYMBOL, 101),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 101),
    (2, HUFFMAN_EMIT_SYMBOL, 105),
    (9, HUFFMAN_EMIT_SYMBOL, 105),
    (23, HUFFMAN_EMIT_SYMBOL, 105),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 105),
    (2, HUFFMAN_EMIT_SYMBOL, 111),
    (9, HUFFMAN_EMIT_SYMBOL, 111),
    (23, HUFFMAN_EMIT_SYMBOL, 111),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 111),

    # Node 7
    (3, HUFFMAN_EMIT_SYMBOL, 99),
    (6, HUFFMAN_EMIT_SYMBOL, 99),
    (10, HUFFMAN_EMIT_SYMBOL, 99),
    (15, HUFFMAN_EMIT_SYMBOL, 99),
    (24, HUFFMAN_EMIT_SYMBOL, 99),
    (31, HUFFMAN_EMIT_SYMBOL, 99),
    (41, HUFFMAN_EMIT_SYMBOL, 99),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 99),
    (3, HUFFMAN_EMIT_SYMBOL, 101),
    (6, HUFFMAN_EMIT_SYMBOL, 101),
    (10, HUFFMAN_EMIT_SYMBOL, 101),
    (15, HUFFMAN_EMIT_SYMBOL, 101),
    (24, HUFFMAN_EMIT_SYMBOL, 101),
    (31, HUFFMAN_EMIT_SYMBOL, 101),
    (41, HUFFMAN_EMIT_SYMBOL, 101),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 101),

    # Node 8
    (3, HUFFMAN_EMIT_SYMBOL, 105),
    (6, HUFFMAN_EMIT_SYMBOL, 105),
    (10, HUFFMAN_EMIT_SYMBOL, 105),
    (15, HUFFMAN_EMIT_SYMBOL, 105),
    (24, HUFFMAN_EMIT_SYMBOL, 105),
    (31, HUFFMAN_EMIT_SYMBOL, 105),
    (41, HUFFMAN_EMIT_SYMBOL, 105),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 105),
    (3, HUFFMAN_EMIT_SYMBOL, 111),
    (6, HUFFMAN_EMIT_SYMBOL, 111),
    (10, HUFFMAN_EMIT_SYMBOL, 111),
    (15, HUFFMAN_EMIT_SYMBOL, 111),
    (24, HUFFMAN_EMIT_SYMBOL, 111),
    (31, HUFFMAN_EMIT_SYMBOL, 111),
    (41, HUFFMAN_EMIT_SYMBOL, 111),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 111),

    # Node 9
    (1, HUFFMAN_EMIT_SYMBOL, 115),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 115),
    (1, HUFFMAN_EMIT_SYMBOL, 116),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 116),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 32),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 37),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 45),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 46),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 47),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 51),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 52),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 53),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 54),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 55),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 56),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 57),

    # Node 10
    (2, HUFFMAN_EMIT_SYMBOL, 115),
    (9, HUFFMAN_EMIT_SYMBOL, 115),
    (23, HUFFMAN_EMIT_SYMBOL, 115),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 115),
    (2, HUFFMAN_EMIT_SYMBOL, 116),
    (9, HUFFMAN_EMIT_SYMBOL, 116),
    (23, HUFFMAN_EMIT_SYMBOL, 116),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 116),
    (1, HUFFMAN_EMIT_SYMBOL, 32),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 32),
    (1, HUFFMAN_EMIT_SYMBOL, 37),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 37),
    (1, HUFFMAN_EMIT_SYMBOL, 45),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 45),
    (1, HUFFMAN_EMIT_SYMBOL, 46),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 46),

    # Node 11
    (3, HUFFMAN_EMIT_SYMBOL, 115),
    (6, HUFFMAN_EMIT_SYMBOL, 115),
    (10, HUFFMAN_EMIT_SYMBOL, 115),
    (15, HUFFMAN_EMIT_SYMBOL, 115),
    (24, HUFFMAN_EMIT_SYMBOL, 115),
    (31, HUFFMAN_EMIT_SYMBOL, 115),
    (41, HUFFMAN_EMIT_SYMBOL, 115),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 115),
    (3, HUFFMAN_EMIT_SYMBOL, 116),
    (6, HUFFMAN_EMIT_SYMBOL, 116),
    (10, HUFFMAN_EMIT_SYMBOL, 116),
    (15, HUFFMAN_EMIT_SYMBOL, 116),
    (24, HUFFMAN_EMIT_SYMBOL, 116),
    (31, HUFFMAN_EMIT_SYMBOL, 116),
    (41, HUFFMAN_EMIT_SYMBOL, 116),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 116),

    # Node 12
    (2, HUFFMAN_EMIT_SYMBOL, 32),
    (9, HUFFMAN_EMIT_SYMBOL, 32),
    (23, HUFFMAN_EMIT_SYMBOL, 32),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 32),
    (2, HUFFMAN_EMIT_SYMBOL, 37),
    (9, HUFFMAN_EMIT_SYMBOL, 37),
    (23, HUFFMAN_EMIT_SYMBOL, 37),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 37),
    (2, HUFFMAN_EMIT_SYMBOL, 45),
    (9, HUFFMAN_EMIT_SYMBOL, 45),
    (23, HUFFMAN_EMIT_SYMBOL, 45),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 45),
    (2, HUFFMAN_EMIT_SYMBOL, 46),
    (9, HUFFMAN_EMIT_SYMBOL, 46),
    (23, HUFFMAN_EMIT_SYMBOL, 46),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 46),

    # Node 13
    (3, HUFFMAN_EMIT_SYMBOL, 32),
    (6, HUFFMAN_EMIT_SYMBOL, 32),
    (10, HUFFMAN_EMIT_SYMBOL, 32),
    (15, HUFFMAN_EMIT_SYMBOL, 32),
    (24, HUFFMAN_EMIT_SYMBOL, 32),
    (31, HUFFMAN_EMIT_SYMBOL, 32),
    (41, HUFFMAN_EMIT_SYMBOL, 32),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 32),
    (3, HUFFMAN_EMIT_SYMBOL, 37),
    (6, HUFFMAN_EMIT_SYMBOL, 37),
    (10, HUFFMAN_EMIT_SYMBOL, 37),
    (15, HUFFMAN_EMIT_SYMBOL, 37),
    (24, HUFFMAN_EMIT_SYMBOL, 37),
    (31, HUFFMAN_EMIT_SYMBOL, 37),
    (41, HUFFMAN_EMIT_SYMBOL, 37),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 37),

    # Node 14
    (3, HUFFMAN_EMIT_SYMBOL, 45),
    (6, HUFFMAN_EMIT_SYMBOL, 45),
    (10, HUFFMAN_EMIT_SYMBOL, 45),
    (15, HUFFMAN_EMIT_SYMBOL, 45),
    (24, HUFFMAN_EMIT_SYMBOL, 45),
    (31, HUFFMAN_EMIT_SYMBOL, 45),
    (41, HUFFMAN_EMIT_SYMBOL, 45),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 45),
    (3, HUFFMAN_EMIT_SYMBOL, 46),
    (6, HUFFMAN_EMIT_SYMBOL, 46),
    (10, HUFFMAN_EMIT_SYMBOL, 46),
    (15, HUFFMAN_EMIT_SYMBOL, 46),
    (24, HUFFMAN_EMIT_SYMBOL, 46),
    (31, HUFFMAN_EMIT_SYMBOL, 46),
    (41, HUFFMAN_EMIT_SYMBOL, 46),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 46),

    # Node 15
    (1, HUFFMAN_EMIT_SYMBOL, 47),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 47),
    (1, HUFFMAN_EMIT_SYMBOL, 51),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 51),
    (1, HUFFMAN_EMIT_SYMBOL, 52),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 52),
    (1, HUFFMAN_EMIT_SYMBOL, 53),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 53),
    (1, HUFFMAN_EMIT_SYMBOL, 54),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 54),
    (1, HUFFMAN_EMIT_SYMBOL, 55),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 55),
    (1, HUFFMAN_EMIT_SYMBOL, 56),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 56),
    (1, HUFFMAN_EMIT_SYMBOL, 57),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 57),

    # Node 16
    (2, HUFFMAN_EMIT_SYMBOL, 47),
    (9, HUFFMAN_EMIT_SYMBOL, 47),
    (23, HUFFMAN_EMIT_SYMBOL, 47),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 47),
    (2, HUFFMAN_EMIT_SYMBOL, 51),
    (9, HUFFMAN_EMIT_SYMBOL, 51),
    (23, HUFFMAN_EMIT_SYMBOL, 51),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 51),
    (2, HUFFMAN_EMIT_SYMBOL, 52),
    (9, HUFFMAN_EMIT_SYMBOL, 52),
    (23, HUFFMAN_EMIT_SYMBOL, 52),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 52),
    (2, HUFFMAN_EMIT_SYMBOL, 53),
    (9, HUFFMAN_EMIT_SYMBOL, 53),
    (23, HUFFMAN_EMIT_SYMBOL, 53),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 53),

    # Node 17
    (3, HUFFMAN_EMIT_SYMBOL, 47),
    (6, HUFFMAN_EMIT_SYMBOL, 47),
    (10, HUFFMAN_EMIT_SYMBOL, 47),
    (15, HUFFMAN_EMIT_SYMBOL, 47),
    (24, HUFFMAN_EMIT_SYMBOL, 47),
    (31, HUFFMAN_EMIT_SYMBOL, 47),
    (41, HUFFMAN_EMIT_SYMBOL, 47),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 47),
    (3, HUFFMAN_EMIT_SYMBOL, 51),
    (6, HUFFMAN_EMIT_SYMBOL, 51),
    (10, HUFFMAN_EMIT_SYMBOL, 51),
    (15, HUFFMAN_EMIT_SYMBOL, 51),
    (24, HUFFMAN_EMIT_SYMBOL, 51),
    (31, HUFFMAN_EMIT_SYMBOL, 51),
    (41, HUFFMAN_EMIT_SYMBOL, 51),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 51),

    # Node 18
    (3, HUFFMAN_EMIT_SYMBOL, 52),
    (6, HUFFMAN_EMIT_SYMBOL, 52),
    (10, HUFFMAN_EMIT_SYMBOL, 52),
    (15, HUFFMAN_EMIT_SYMBOL, 52),
    (24, HUFFMAN_EMIT_SYMBOL, 52),
    (31, HUFFMAN_EMIT_SYMBOL, 52),
    (41, HUFFMAN_EMIT_SYMBOL, 52),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 52),
    (3, HUFFMAN_EMIT_SYMBOL, 53),
    (6, HUFFMAN_EMIT_SYMBOL, 53),
    (10, HUFFMAN_EMIT_SYMBOL, 53),
    (15, HUFFMAN_EMIT_SYMBOL, 53),
    (24, HUFFMAN_EMIT_SYMBOL, 53),
    (31, HUFFMAN_EMIT_SYMBOL, 53),
    (41, HUFFMAN_EMIT_SYMBOL, 53),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 53),

    # Node 19
    (2, HUFFMAN_EMIT_SYMBOL, 54),
    (9, HUFFMAN_EMIT_SYMBOL, 54),
    (23, HUFFMAN_EMIT_SYMBOL, 54),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 54),
    (2, HUFFMAN_EMIT_SYMBOL, 55),
    (9, HUFFMAN_EMIT_SYMBOL, 55),
    (23, HUFFMAN_EMIT_SYMBOL, 55),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 55),
    (2, HUFFMAN_EMIT_SYMBOL, 56),
    (9, HUFFMAN_EMIT_SYMBOL, 56),
    (23, HUFFMAN_EMIT_SYMBOL, 56),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 56),
    (2, HUFFMAN_EMIT_SYMBOL, 57),
    (9, HUFFMAN_EMIT_SYMBOL, 57),
    (23, HUFFMAN_EMIT_SYMBOL, 57),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 57),

    # Node 20
    (3, HUFFMAN_EMIT_SYMBOL, 54),
    (6, HUFFMAN_EMIT_SYMBOL, 54),
    (10, HUFFMAN_EMIT_SYMBOL, 54),
    (15, HUFFMAN_EMIT_SYMBOL, 54),
    (24, HUFFMAN_EMIT_SYMBOL, 54),
    (31, HUFFMAN_EMIT_SYMBOL, 54),
    (41, HUFFMAN_EMIT_SYMBOL, 54),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 54),
    (3, HUFFMAN_EMIT_SYMBOL, 55),
    (6, HUFFMAN_EMIT_SYMBOL, 55),
    (10, HUFFMAN_EMIT_SYMBOL, 55),
    (15, HUFFMAN_EMIT_SYMBOL, 55),
    (24, HUFFMAN_EMIT_SYMBOL, 55),
    (31, HUFFMAN_EMIT_SYMBOL, 55),
    (41, HUFFMAN_EMIT_SYMBOL, 55),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 55),

    # Node 21
    (3, HUFFMAN_EMIT_SYMBOL, 56),
    (6, HUFFMAN_EMIT_SYMBOL, 56),
    (10, HUFFMAN_EMIT_SYMBOL, 56),
    (15, HUFFMAN_EMIT_SYMBOL, 56),
    (24, HUFFMAN_EMIT_SYMBOL, 56),
    (31, HUFFMAN_EMIT_SYMBOL, 56),
    (41, HUFFMAN_EMIT_SYMBOL, 56),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 56),
    (3, HUFFMAN_EMIT_SYMBOL, 57),
    (6, HUFFMAN_EMIT_SYMBOL, 57),
    (10, HUFFMAN_EMIT_SYMBOL, 57),
    (15, HUFFMAN_EMIT_SYMBOL, 57),
    (24, HUFFMAN_EMIT_SYMBOL, 57),
    (31, HUFFMAN_EMIT_SYMBOL, 57),
    (41, HUFFMAN_EMIT_SYMBOL, 57),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 57),

    # Node 22
    (26, 0, 0),
    (27, 0, 0),
    (29, 0, 0),
    (30, 0, 0),
    (33, 0, 0),
    (34, 0, 0),
    (36, 0, 0),
    (37, 0, 0),
    (43, 0, 0),
    (46, 0, 0),
    (50, 0, 0),
    (53, 0, 0),
    (58, 0, 0),
    (61, 0, 0),
    (65, 0, 0),
    (68, HUFFMAN_COMPLETE, 0),

    # Node 23
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 61),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 65),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 95),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 98),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 100),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 102),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 103),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 104),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 108),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 109),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 110),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 112),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 114),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 117),
    (38, 0, 0),
    (39, 0, 0),

    # Node 24
    (1, HUFFMAN_EMIT_SYMBOL, 61),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 61),
    (1, HUFFMAN_EMIT_SYMBOL, 65),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 65),
    (1, HUFFMAN_EMIT_SYMBOL, 95),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 95),
    (1, HUFFMAN_EMIT_SYMBOL, 98),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 98),
    (1, HUFFMAN_EMIT_SYMBOL, 100),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 100),
    (1, HUFFMAN_EMIT_SYMBOL, 102),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 102),
    (1, HUFFMAN_EMIT_SYMBOL, 103),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 103),
    (1, HUFFMAN_EMIT_SYMBOL, 104),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 104),

    # Node 25
    (2, HUFFMAN_EMIT_SYMBOL, 61),
    (9, HUFFMAN_EMIT_SYMBOL, 61),
    (23, HUFFMAN_EMIT_SYMBOL, 61),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 61),
    (2, HUFFMAN_EMIT_SYMBOL, 65),
    (9, HUFFMAN_EMIT_SYMBOL, 65),
    (23, HUFFMAN_EMIT_SYMBOL, 65),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 65),
    (2, HUFFMAN_EMIT_SYMBOL, 95),
    (9, HUFFMAN_EMIT_SYMBOL, 95),
    (23, HUFFMAN_EMIT_SYMBOL, 95),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 95),
    (2, HUFFMAN_EMIT_SYMBOL, 98),
    (9, HUFFMAN_EMIT_SYMBOL, 98),
    (23, HUFFMAN_EMIT_SYMBOL, 98),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 98),

    # Node 26
    (3, HUFFMAN_EMIT_SYMBOL, 61),
    (6, HUFFMAN_EMIT_SYMBOL, 61),
    (10, HUFFMAN_EMIT_SYMBOL, 61),
    (15, HUFFMAN_EMIT_SYMBOL, 61),
    (24, HUFFMAN_EMIT_SYMBOL, 61),
    (31, HUFFMAN_EMIT_SYMBOL, 61),
    (41, HUFFMAN_EMIT_SYMBOL, 61),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 61),
    (3, HUFFMAN_EMIT_SYMBOL, 65),
    (6, HUFFMAN_EMIT_SYMBOL, 65),
    (10, HUFFMAN_EMIT_SYMBOL, 65),
    (15, HUFFMAN_EMIT_SYMBOL, 65),
    (24, HUFFMAN_EMIT_SYMBOL, 65),
    (31, HUFFMAN_EMIT_SYMBOL, 65),
    (41, HUFFMAN_EMIT_SYMBOL, 65),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 65),

    # Node 27
    (3, HUFFMAN_EMIT_SYMBOL, 95),
    (6, HUFFMAN_EMIT_SYMBOL, 95),
    (10, HUFFMAN_EMIT_SYMBOL, 95),
    (15, HUFFMAN_EMIT_SYMBOL, 95),
    (24, HUFFMAN_EMIT_SYMBOL, 95),
    (31, HUFFMAN_EMIT_SYMBOL, 95),
    (41, HUFFMAN_EMIT_SYMBOL, 95),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 95),
    (3, HUFFMAN_EMIT_SYMBOL, 98),
    (6, HUFFMAN_EMIT_SYMBOL, 98),
    (10, HUFFMAN_EMIT_SYMBOL, 98),
    (15, HUFFMAN_EMIT_SYMBOL, 98),
    (24, HUFFMAN_EMIT_SYMBOL, 98),
    (31, HUFFMAN_EMIT_SYMBOL, 98),
    (41, HUFFMAN_EMIT_SYMBOL, 98),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 98),

    # Node 28
    (2, HUFFMAN_EMIT_SYMBOL, 100),
    (9, HUFFMAN_EMIT_SYMBOL, 100),
    (23, HUFFMAN_EMIT_SYMBOL, 100),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 100),
    (2, HUFFMAN_EMIT_SYMBOL, 102),
    (9, HUFFMAN_EMIT_SYMBOL, 102),
    (23, HUFFMAN_EMIT_SYMBOL, 102),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 102),
    (2, HUFFMAN_EMIT_SYMBOL, 103),
    (9, HUFFMAN_EMIT_SYMBOL, 103),
    (23, HUFFMAN_EMIT_SYMBOL, 103),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 103),
    (2, HUFFMAN_EMIT_SYMBOL, 104),
    (9, HUFFMAN_EMIT_SYMBOL, 104),
    (23, HUFFMAN_EMIT_SYMBOL, 104),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 104),

    # Node 29
    (3, HUFFMAN_EMIT_SYMBOL, 100),
    (6, HUFFMAN_EMIT_SYMBOL, 100),
    (10, HUFFMAN_EMIT_SYMBOL, 100),
    (15, HUFFMAN_EMIT_SYMBOL, 100),
    (24, HUFFMAN_EMIT_SYMBOL, 100),
    (31, HUFFMAN_EMIT_SYMBOL, 100),
    (41, HUFFMAN_EMIT_SYMBOL, 100),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 100),
    (3, HUFFMAN_EMIT_SYMBOL, 102),
    (6, HUFFMAN_EMIT_SYMBOL, 102),
    (10, HUFFMAN_EMIT_SYMBOL, 102),
    (15, HUFFMAN_EMIT_SYMBOL, 102),
    (24, HUFFMAN_EMIT_SYMBOL, 102),
    (31, HUFFMAN_EMIT_SYMBOL, 102),
    (41, HUFFMAN_EMIT_SYMBOL, 102),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 102),

    # Node 30
    (3, HUFFMAN_EMIT_SYMBOL, 103),
    (6, HUFFMAN_EMIT_SYMBOL, 103),
    (10, HUFFMAN_EMIT_SYMBOL, 103),
    (15, HUFFMAN_EMIT_SYMBOL, 103),
    (24, HUFFMAN_EMIT_SYMBOL, 103),
    (31, HUFFMAN_EMIT_SYMBOL, 103),
    (41, HUFFMAN_EMIT_SYMBOL, 103),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 103),
    (3, HUFFMAN_EMIT_SYMBOL, 104),
    (6, HUFFMAN_EMIT_SYMBOL, 104),
    (10, HUFFMAN_EMIT_SYMBOL, 104),
    (15, HUFFMAN_EMIT_SYMBOL, 104),
    (24, HUFFMAN_EMIT_SYMBOL, 104),
    (31, HUFFMAN_EMIT_SYMBOL, 104),
    (41, HUFFMAN_EMIT_SYMBOL, 104),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 104),

    # Node 31
    (1, HUFFMAN_EMIT_SYMBOL, 108),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 108),
    (1, HUFFMAN_EMIT_SYMBOL, 109),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 109),
    (1, HUFFMAN_EMIT_SYMBOL, 110),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 110),
    (1, HUFFMAN_EMIT_SYMBOL, 112),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 112),
    (1, HUFFMAN_EMIT_SYMBOL, 114),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 114),
    (1, HUFFMAN_EMIT_SYMBOL, 117),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 117),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 58),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 66),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 67),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 68),

    # Node 32
    (2, HUFFMAN_EMIT_SYMBOL, 108),
    (9, HUFFMAN_EMIT_SYMBOL, 108),
    (23, HUFFMAN_EMIT_SYMBOL, 108),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 108),
    (2, HUFFMAN_EMIT_SYMBOL, 109),
    (9, HUFFMAN_EMIT_SYMBOL, 109),
    (23, HUFFMAN_EMIT_SYMBOL, 109),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 109),
    (2, HUFFMAN_EMIT_SYMBOL, 110),
    (9, HUFFMAN_EMIT_SYMBOL, 110),
    (23, HUFFMAN_EMIT_SYMBOL, 110),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 110),
    (2, HUFFMAN_EMIT_SYMBOL, 112),
    (9, HUFFMAN_EMIT_SYMBOL, 112),
    (23, HUFFMAN_EMIT_SYMBOL, 112),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 112),

    # Node 33
    (3, HUFFMAN_EMIT_SYMBOL, 108),
    (6, HUFFMAN_EMIT_SYMBOL, 108),
    (10, HUFFMAN_EMIT_SYMBOL, 108),
    (15, HUFFMAN_EMIT_SYMBOL, 108),
    (24, HUFFMAN_EMIT_SYMBOL, 108),
    (31, HUFFMAN_EMIT_SYMBOL, 108),
    (41, HUFFMAN_EMIT_SYMBOL, 108),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 108),
    (3, HUFFMAN_EMIT_SYMBOL, 109),
    (6, HUFFMAN_EMIT_SYMBOL, 109),
    (10, HUFFMAN_EMIT_SYMBOL, 109),
    (15, HUFFMAN_EMIT_SYMBOL, 109),
    (24, HUFFMAN_EMIT_SYMBOL, 109),
    (31, HUFFMAN_EMIT_SYMBOL, 109),
    (41, HUFFMAN_EMIT_SYMBOL, 109),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 109),

    # Node 34
    (3, HUFFMAN_EMIT_SYMBOL, 110),
    (6, HUFFMAN_EMIT_SYMBOL, 110),
    (10, HUFFMAN_EMIT_SYMBOL, 110),
    (15, HUFFMAN_EMIT_SYMBOL, 110),
    (24, HUFFMAN_EMIT_SYMBOL, 110),
    (31, HUFFMAN_EMIT_SYMBOL, 110),
    (41, HUFFMAN_EMIT_SYMBOL, 110),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 110),
    (3, HUFFMAN_EMIT_SYMBOL, 112),
    (6, HUFFMAN_EMIT_SYMBOL, 112),
    (10, HUFFMAN_EMIT_SYMBOL, 112),
    (15, HUFFMAN_EMIT_SYMBOL, 112),
    (24, HUFFMAN_EMIT_SYMBOL, 112),
    (31, HUFFMAN_EMIT_SYMBOL, 112),
    (41, HUFFMAN_EMIT_SYMBOL, 112),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 112),

    # Node 35
    (2, HUFFMAN_EMIT_SYMBOL, 114),
    (9, HUFFMAN_EMIT_SYMBOL, 114),
    (23, HUFFMAN_EMIT_SYMBOL, 114),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 114),
    (2, HUFFMAN_EMIT_SYMBOL, 117),
    (9, HUFFMAN_EMIT_SYMBOL, 117),
    (23, HUFFMAN_EMIT_SYMBOL, 117),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 117),
    (1, HUFFMAN_EMIT_SYMBOL, 58),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 58),
    (1, HUFFMAN_EMIT_SYMBOL, 66),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 66),
    (1, HUFFMAN_EMIT_SYMBOL, 67),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 67),
    (1, HUFFMAN_EMIT_SYMBOL, 68),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 68),

    # Node 36
    (3, HUFFMAN_EMIT_SYMBOL, 114),
    (6, HUFFMAN_EMIT_SYMBOL, 114),
    (10, HUFFMAN_EMIT_SYMBOL, 114),
    (15, HUFFMAN_EMIT_SYMBOL, 114),
    (24, HUFFMAN_EMIT_SYMBOL, 114),
    (31, HUFFMAN_EMIT_SYMBOL, 114),
    (41, HUFFMAN_EMIT_SYMBOL, 114),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 114),
    (3, HUFFMAN_EMIT_SYMBOL, 117),
    (6, HUFFMAN_EMIT_SYMBOL, 117),
    (10, HUFFMAN_EMIT_SYMBOL, 117),
    (15, HUFFMAN_EMIT_SYMBOL, 117),
    (24, HUFFMAN_EMIT_SYMBOL, 117),
    (31, HUFFMAN_EMIT_SYMBOL, 117),
    (41, HUFFMAN_EMIT_SYMBOL, 117),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 117),

    # Node 37
    (2, HUFFMAN_EMIT_SYMBOL, 58),
    (9, HUFFMAN_EMIT_SYMBOL, 58),
    (23, HUFFMAN_EMIT_SYMBOL, 58),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 58),
    (2, HUFFMAN_EMIT_SYMBOL, 66),
    (9, HUFFMAN_EMIT_SYMBOL, 66),
    (23, HUFFMAN_EMIT_SYMBOL, 66),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 66),
    (2, HUFFMAN_EMIT_SYMBOL, 67),
    (9, HUFFMAN_EMIT_SYMBOL, 67),
    (23, HUFFMAN_EMIT_SYMBOL, 67),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 67),
    (2, HUFFMAN_EMIT_SYMBOL, 68),
    (9, HUFFMAN_EMIT_SYMBOL, 68),
    (23, HUFFMAN_EMIT_SYMBOL, 68),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 68),

    # Node 38
    (3, HUFFMAN_EMIT_SYMBOL, 58),
    (6, HUFFMAN_EMIT_SYMBOL, 58),
    (10, HUFFMAN_EMIT_SYMBOL, 58),
    (15, HUFFMAN_EMIT_SYMBOL, 58),
    (24, HUFFMAN_EMIT_SYMBOL, 58),
    (31, HUFFMAN_EMIT_SYMBOL, 58),
    (41, HUFFMAN_EMIT_SYMBOL, 58),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 58),
    (3, HUFFMAN_EMIT_SYMBOL, 66),
    (6, HUFFMAN_EMIT_SYMBOL, 66),
    (10, HUFFMAN_EMIT_SYMBOL, 66),
    (15, HUFFMAN_EMIT_SYMBOL, 66),
    (24, HUFFMAN_EMIT_SYMBOL, 66),
    (31, HUFFMAN_EMIT_SYMBOL, 66),
    (41, HUFFMAN_EMIT_SYMBOL, 66),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 66),

    # Node 39
    (3, HUFFMAN_EMIT_SYMBOL, 67),
    (6, HUFFMAN_EMIT_SYMBOL, 67),
    (10, HUFFMAN_EMIT_SYMBOL, 67),
    (15, HUFFMAN_EMIT_SYMBOL, 67),
    (24, HUFFMAN_EMIT_SYMBOL, 67),
    (31, HUFFMAN_EMIT_SYMBOL, 67),
    (41, HUFFMAN_EMIT_SYMBOL, 67),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 67),
    (3, HUFFMAN_EMIT_SYMBOL, 68),
    (6, HUFFMAN_EMIT_SYMBOL, 68),
    (10, HUFFMAN_EMIT_SYMBOL, 68),
    (15, HUFFMAN_EMIT_SYMBOL, 68),
    (24, HUFFMAN_EMIT_SYMBOL, 68),
    (31, HUFFMAN_EMIT_SYMBOL, 68),
    (41, HUFFMAN_EMIT_SYMBOL, 68),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 68),

    # Node 40
    (44, 0, 0),
    (45, 0, 0),
    (47, 0, 0),
    (48, 0, 0),
    (51, 0, 0),
    (52, 0, 0),
    (54, 0, 0),
    (55, 0, 0),
    (59, 0, 0),
    (60, 0, 0),
    (62, 0, 0),
    (63, 0, 0),
    (66, 0, 0),
    (67, 0, 0),
    (69, 0, 0),
    (72, HUFFMAN_COMPLETE, 0),

    # Node 41
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 69),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 70),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 71),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 72),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 73),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 74),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 75),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 76),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 77),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 78),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 79),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 80),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 81),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 82),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 83),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 84),

    # Node 42
    (1, HUFFMAN_EMIT_SYMBOL, 69),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 69),
    (1, HUFFMAN_EMIT_SYMBOL, 70),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 70),
    (1, HUFFMAN_EMIT_SYMBOL, 71),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 71),
    (1, HUFFMAN_EMIT_SYMBOL, 72),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 72),
    (1, HUFFMAN_EMIT_SYMBOL, 73),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 73),
    (1, HUFFMAN_EMIT_SYMBOL, 74),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 74),
    (1, HUFFMAN_EMIT_SYMBOL, 75),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 75),
    (1, HUFFMAN_EMIT_SYMBOL, 76),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 76),

    # Node 43
    (2, HUFFMAN_EMIT_SYMBOL, 69),
    (9, HUFFMAN_EMIT_SYMBOL, 69),
    (23, HUFFMAN_EMIT_SYMBOL, 69),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 69),
    (2, HUFFMAN_EMIT_SYMBOL, 70),
    (9, HUFFMAN_EMIT_SYMBOL, 70),
    (23, HUFFMAN_EMIT_SYMBOL, 70),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 70),
    (2, HUFFMAN_EMIT_SYMBOL, 71),
    (9, HUFFMAN_EMIT_SYMBOL, 71),
    (23, HUFFMAN_EMIT_SYMBOL, 71),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 71),
    (2, HUFFMAN_EMIT_SYMBOL, 72),
    (9, HUFFMAN_EMIT_SYMBOL, 72),
    (23, HUFFMAN_EMIT_SYMBOL, 72),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 72),

    # Node 44
    (3, HUFFMAN_EMIT_SYMBOL, 69),
    (6, HUFFMAN_EMIT_SYMBOL, 69),
    (10, HUFFMAN_EMIT_SYMBOL, 69),
    (15, HUFFMAN_EMIT_SYMBOL, 69),
    (24, HUFFMAN_EMIT_SYMBOL, 69),
    (31, HUFFMAN_EMIT_SYMBOL, 69),
    (41, HUFFMAN_EMIT_SYMBOL, 69),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 69),
    (3, HUFFMAN_EMIT_SYMBOL, 70),
    (6, HUFFMAN_EMIT_SYMBOL, 70),
    (10, HUFFMAN_EMIT_SYMBOL, 70),
    (15, HUFFMAN_EMIT_SYMBOL, 70),
    (24, HUFFMAN_EMIT_SYMBOL, 70),
    (31, HUFFMAN_EMIT_SYMBOL, 70),
    (41, HUFFMAN_EMIT_SYMBOL, 70),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 70),

    # Node 45
    (3, HUFFMAN_EMIT_SYMBOL, 71),
    (6, HUFFMAN_EMIT_SYMBOL, 71),
    (10, HUFFMAN_EMIT_SYMBOL, 71),
    (15, HUFFMAN_EMIT_SYMBOL, 71),
    (24, HUFFMAN_EMIT_SYMBOL, 71),
    (31, HUFFMAN_EMIT_SYMBOL, 71),
    (41, HUFFMAN_EMIT_SYMBOL, 71),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 71),
    (3, HUFFMAN_EMIT_SYMBOL, 72),
    (6, HUFFMAN_EMIT_SYMBOL, 72),
    (10, HUFFMAN_EMIT_SYMBOL, 72),
    (15, HUFFMAN_EMIT_SYMBOL, 72),
    (24, HUFFMAN_EMIT_SYMBOL, 72),
    (31, HUFFMAN_EMIT_SYMBOL, 72),
    (41, HUFFMAN_EMIT_SYMBOL, 72),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 72),

    # Node 46
    (2, HUFFMAN_EMIT_SYMBOL, 73),
    (9, HUFFMAN_EMIT_SYMBOL, 73),
    (23, HUFFMAN_EMIT_SYMBOL, 73),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 73),
    (2, HUFFMAN_EMIT_SYMBOL, 74),
    (9, HUFFMAN_EMIT_SYMBOL, 74),
    (23, HUFFMAN_EMIT_SYMBOL, 74),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 74),
    (2, HUFFMAN_EMIT_SYMBOL, 75),
    (9, HUFFMAN_EMIT_SYMBOL, 75),
    (23, HUFFMAN_EMIT_SYMBOL, 75),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 75),
    (2, HUFFMAN_EMIT_SYMBOL, 76),
    (9, HUFFMAN_EMIT_SYMBOL, 76),
    (23, HUFFMAN_EMIT_SYMBOL, 76),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 76),

    # Node 47
    (3, HUFFMAN_EMIT_SYMBOL, 73),
    (6, HUFFMAN_EMIT_SYMBOL, 73),
    (10, HUFFMAN_EMIT_SYMBOL, 73),
    (15, HUFFMAN_EMIT_SYMBOL, 73),
    (24, HUFFMAN_EMIT_SYMBOL, 73),
    (31, HUFFMAN_EMIT_SYMBOL, 73),
    (41, HUFFMAN_EMIT_SYMBOL, 73),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 73),
    (3, HUFFMAN_EMIT_SYMBOL, 74),
    (6, HUFFMAN_EMIT_SYMBOL, 74),
    (10, HUFFMAN_EMIT_SYMBOL, 74),
    (15, HUFFMAN_EMIT_SYMBOL, 74),
    (24, HUFFMAN_EMIT_SYMBOL, 74),
    (31, HUFFMAN_EMIT_SYMBOL, 74),
    (41, HUFFMAN_EMIT_SYMBOL, 74),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 74),

    # Node 48
    (3, HUFFMAN_EMIT_SYMBOL, 75),
    (6, HUFFMAN_EMIT_SYMBOL, 75),
    (10, HUFFMAN_EMIT_SYMBOL, 75),
    (15, HUFFMAN_EMIT_SYMBOL, 75),
    (24, HUFFMAN_EMIT_SYMBOL, 75),
    (31, HUFFMAN_EMIT_SYMBOL, 75),
    (41, HUFFMAN_EMIT_SYMBOL, 75),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 75),
    (3, HUFFMAN_EMIT_SYMBOL, 76),
    (6, HUFFMAN_EMIT_SYMBOL, 76),
    (10, HUFFMAN_EMIT_SYMBOL, 76),
    (15, HUFFMAN_EMIT_SYMBOL, 76),
    (24, HUFFMAN_EMIT_SYMBOL, 76),
    (31, HUFFMAN_EMIT_SYMBOL, 76),
    (41, HUFFMAN_EMIT_SYMBOL, 76),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 76),

    # Node 49
    (1, HUFFMAN_EMIT_SYMBOL, 77),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 77),
    (1, HUFFMAN_EMIT_SYMBOL, 78),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 78),
    (1, HUFFMAN_EMIT_SYMBOL, 79),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 79),
    (1, HUFFMAN_EMIT_SYMBOL, 80),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 80),
    (1, HUFFMAN_EMIT_SYMBOL, 81),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 81),
    (1, HUFFMAN_EMIT_SYMBOL, 82),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 82),
    (1, HUFFMAN_EMIT_SYMBOL, 83),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 83),
    (1, HUFFMAN_EMIT_SYMBOL, 84),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 84),

    # Node 50
    (2, HUFFMAN_EMIT_SYMBOL, 77),
    (9, HUFFMAN_EMIT_SYMBOL, 77),
    (23, HUFFMAN_EMIT_SYMBOL, 77),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 77),
    (2, HUFFMAN_EMIT_SYMBOL, 78),
    (9, HUFFMAN_EMIT_SYMBOL, 78),
    (23, HUFFMAN_EMIT_SYMBOL, 78),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 78),
    (2, HUFFMAN_EMIT_SYMBOL, 79),
    (9, HUFFMAN_EMIT_SYMBOL, 79),
    (23, HUFFMAN_EMIT_SYMBOL, 79),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 79),
    (2, HUFFMAN_EMIT_SYMBOL, 80),
    (9, HUFFMAN_EMIT_SYMBOL, 80),
    (23, HUFFMAN_EMIT_SYMBOL, 80),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 80),

    # Node 51
    (3, HUFFMAN_EMIT_SYMBOL, 77),
    (6, HUFFMAN_EMIT_SYMBOL, 77),
    (10, HUFFMAN_EMIT_SYMBOL, 77),
    (15, HUFFMAN_EMIT_SYMBOL, 77),
    (24, HUFFMAN_EMIT_SYMBOL, 77),
    (31, HUFFMAN_EMIT_SYMBOL, 77),
    (41, HUFFMAN_EMIT_SYMBOL, 77),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 77),
    (3, HUFFMAN_EMIT_SYMBOL, 78),
    (6, HUFFMAN_EMIT_SYMBOL, 78),
    (10, HUFFMAN_EMIT_SYMBOL, 78),
    (15, HUFFMAN_EMIT_SYMBOL, 78),
    (24, HUFFMAN_EMIT_SYMBOL, 78),
    (31, HUFFMAN_EMIT_SYMBOL, 78),
    (41, HUFFMAN_EMIT_SYMBOL, 78),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 78),

    # Node 52
    (3, HUFFMAN_EMIT_SYMBOL, 79),
    (6, HUFFMAN_EMIT_SYMBOL, 79),
    (10, HUFFMAN_EMIT_SYMBOL, 79),
    (15, HUFFMAN_EMIT_SYMBOL, 79),
    (24, HUFFMAN_EMIT_SYMBOL, 79),
    (31, HUFFMAN_EMIT_SYMBOL, 79),
    (41, HUFFMAN_EMIT_SYMBOL, 79),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 79),
    (3, HUFFMAN_EMIT_SYMBOL, 80),
    (6, HUFFMAN_EMIT_SYMBOL, 80),
    (10, HUFFMAN_EMIT_SYMBOL, 80),
    (15, HUFFMAN_EMIT_SYMBOL, 80),
    (24, HUFFMAN_EMIT_SYMBOL, 80),
    (31, HUFFMAN_EMIT_SYMBOL, 80),
    (41, HUFFMAN_EMIT_SYMBOL, 80),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 80),

    # Node 53
    (2, HUFFMAN_EMIT_SYMBOL, 81),
    (9, HUFFMAN_EMIT_SYMBOL, 81),
    (23, HUFFMAN_EMIT_SYMBOL, 81),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 81),
    (2, HUFFMAN_EMIT_SYMBOL, 82),
    (9, HUFFMAN_EMIT_SYMBOL, 82),
    (23, HUFFMAN_EMIT_SYMBOL, 82),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 82),
    (2, HUFFMAN_EMIT_SYMBOL, 83),
    (9, HUFFMAN_EMIT_SYMBOL, 83),
    (23, HUFFMAN_EMIT_SYMBOL, 83),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 83),
    (2, HUFFMAN_EMIT_SYMBOL, 84),
    (9, HUFFMAN_EMIT_SYMBOL, 84),
    (23, HUFFMAN_EMIT_SYMBOL, 84),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 84),

    # Node 54
    (3, HUFFMAN_EMIT_SYMBOL, 81),
    (6, HUFFMAN_EMIT_SYMBOL, 81),
    (10, HUFFMAN_EMIT_SYMBOL, 81),
    (15, HUFFMAN_EMIT_SYMBOL, 81),
    (24, HUFFMAN_EMIT_SYMBOL, 81),
    (31, HUFFMAN_EMIT_SYMBOL, 81),
    (41, HUFFMAN_EMIT_SYMBOL, 81),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 81),
    (3, HUFFMAN_EMIT_SYMBOL, 82),
    (6, HUFFMAN_EMIT_SYMBOL, 82),
    (10, HUFFMAN_EMIT_SYMBOL, 82),
    (15, HUFFMAN_EMIT_SYMBOL, 82),
    (24, HUFFMAN_EMIT_SYMBOL, 82),
    (31, HUFFMAN_EMIT_SYMBOL, 82),
    (41, HUFFMAN_EMIT_SYMBOL, 82),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 82),

    # Node 55
    (3, HUFFMAN_EMIT_SYMBOL, 83),
    (6, HUFFMAN_EMIT_SYMBOL, 83),
    (10, HUFFMAN_EMIT_SYMBOL, 83),
    (15, HUFFMAN_EMIT_SYMBOL, 83),
    (24, HUFFMAN_EMIT_SYMBOL, 83),
    (31, HUFFMAN_EMIT_SYMBOL, 83),
    (41, HUFFMAN_EMIT_SYMBOL, 83),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 83),
    (3, HUFFMAN_EMIT_SYMBOL, 84),
    (6, HUFFMAN_EMIT_SYMBOL, 84),
    (10, HUFFMAN_EMIT_SYMBOL, 84),
    (15, HUFFMAN_EMIT_SYMBOL, 84),
    (24, HUFFMAN_EMIT_SYMBOL, 84),
    (31, HUFFMAN_EMIT_SYMBOL, 84),
    (41, HUFFMAN_EMIT_SYMBOL, 84),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 84),

    # Node 56
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 85),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 86),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 87),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 89),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 106),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 107),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 113),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 118),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 119),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 120),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 121),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 122),
    (70, 0, 0),
    (71, 0, 0),
    (73, 0, 0),
    (74, HUFFMAN_COMPLETE, 0),

    # Node 57
    (1, HUFFMAN_EMIT_SYMBOL, 85),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 85),
    (1, HUFFMAN_EMIT_SYMBOL, 86),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 86),
    (1, HUFFMAN_EMIT_SYMBOL, 87),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 87),
    (1, HUFFMAN_EMIT_SYMBOL, 89),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 89),
    (1, HUFFMAN_EMIT_SYMBOL, 106),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 106),
    (1, HUFFMAN_EMIT_SYMBOL, 107),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 107),
    (1, HUFFMAN_EMIT_SYMBOL, 113),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 113),
    (1, HUFFMAN_EMIT_SYMBOL, 118),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 118),

    # Node 58
    (2, HUFFMAN_EMIT_SYMBOL, 85),
    (9, HUFFMAN_EMIT_SYMBOL, 85),
    (23, HUFFMAN_EMIT_SYMBOL, 85),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 85),
    (2, HUFFMAN_EMIT_SYMBOL, 86),
    (9, HUFFMAN_EMIT_SYMBOL, 86),
    (23, HUFFMAN_EMIT_SYMBOL, 86),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 86),
    (2, HUFFMAN_EMIT_SYMBOL, 87),
    (9, HUFFMAN_EMIT_SYMBOL, 87),
    (23, HUFFMAN_EMIT_SYMBOL, 87),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 87),
    (2, HUFFMAN_EMIT_SYMBOL, 89),
    (9, HUFFMAN_EMIT_SYMBOL, 89),
    (23, HUFFMAN_EMIT_SYMBOL, 89),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 89),

    # Node 59
    (3, HUFFMAN_EMIT_SYMBOL, 85),
    (6, HUFFMAN_EMIT_SYMBOL, 85),
    (10, HUFFMAN_EMIT_SYMBOL, 85),
    (15, HUFFMAN_EMIT_SYMBOL, 85),
    (24, HUFFMAN_EMIT_SYMBOL, 85),
    (31, HUFFMAN_EMIT_SYMBOL, 85),
    (41, HUFFMAN_EMIT_SYMBOL, 85),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 85),
    (3, HUFFMAN_EMIT_SYMBOL, 86),
    (6, HUFFMAN_EMIT_SYMBOL, 86),
    (10, HUFFMAN_EMIT_SYMBOL, 86),
    (15, HUFFMAN_EMIT_SYMBOL, 86),
    (24, HUFFMAN_EMIT_SYMBOL, 86),
    (31, HUFFMAN_EMIT_SYMBOL, 86),
    (41, HUFFMAN_EMIT_SYMBOL, 86),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 86),

    # Node 60
    (3, HUFFMAN_EMIT_SYMBOL, 87),
    (6, HUFFMAN_EMIT_SYMBOL, 87),
    (10, HUFFMAN_EMIT_SYMBOL, 87),
    (15, HUFFMAN_EMIT_SYMBOL, 87),
    (24, HUFFMAN_EMIT_SYMBOL, 87),
    (31, HUFFMAN_EMIT_SYMBOL, 87),
    (41, HUFFMAN_EMIT_SYMBOL, 87),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 87),
    (3, HUFFMAN_EMIT_SYMBOL, 89),
    (6, HUFFMAN_EMIT_SYMBOL, 89),
    (10, HUFFMAN_EMIT_SYMBOL, 89),
    (15, HUFFMAN_EMIT_SYMBOL, 89),
    (24, HUFFMAN_EMIT_SYMBOL, 89),
    (31, HUFFMAN_EMIT_SYMBOL, 89),
    (41, HUFFMAN_EMIT_SYMBOL, 89),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 89),

    # Node 61
    (2, HUFFMAN_EMIT_SYMBOL, 106),
    (9, HUFFMAN_EMIT_SYMBOL, 106),
    (23, HUFFMAN_EMIT_SYMBOL, 106),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 106),
    (2, HUFFMAN_EMIT_SYMBOL, 107),
    (9, HUFFMAN_EMIT_SYMBOL, 107),
    (23, HUFFMAN_EMIT_SYMBOL, 107),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 107),
    (2, HUFFMAN_EMIT_SYMBOL, 113),
    (9, HUFFMAN_EMIT_SYMBOL, 113),
    (23, HUFFMAN_EMIT_SYMBOL, 113),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 113),
    (2, HUFFMAN_EMIT_SYMBOL, 118),
    (9, HUFFMAN_EMIT_SYMBOL, 118),
    (23, HUFFMAN_EMIT_SYMBOL, 118),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 118),

    # Node 62
    (3, HUFFMAN_EMIT_SYMBOL, 106),
    (6, HUFFMAN_EMIT_SYMBOL, 106),
    (10, HUFFMAN_EMIT_SYMBOL, 106),
    (15, HUFFMAN_EMIT_SYMBOL, 106),
    (24, HUFFMAN_EMIT_SYMBOL, 106),
    (31, HUFFMAN_EMIT_SYMBOL, 106),
    (41, HUFFMAN_EMIT_SYMBOL, 106),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 106),
    (3, HUFFMAN_EMIT_SYMBOL, 107),
    (6, HUFFMAN_EMIT_SYMBOL, 107),
    (10, HUFFMAN_EMIT_SYMBOL, 107),
    (15, HUFFMAN_EMIT_SYMBOL, 107),
    (24, HUFFMAN_EMIT_SYMBOL, 107),
    (31, HUFFMAN_EMIT_SYMBOL, 107),
    (41, HUFFMAN_EMIT_SYMBOL, 107),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 107),

    # Node 63
    (3, HUFFMAN_EMIT_SYMBOL, 113),
    (6, HUFFMAN_EMIT_SYMBOL, 113),
    (10, HUFFMAN_EMIT_SYMBOL, 113),
    (15, HUFFMAN_EMIT_SYMBOL, 113),
    (24, HUFFMAN_EMIT_SYMBOL, 113),
    (31, HUFFMAN_EMIT_SYMBOL, 113),
    (41, HUFFMAN_EMIT_SYMBOL, 113),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 113),
    (3, HUFFMAN_EMIT_SYMBOL, 118),
    (6, HUFFMAN_EMIT_SYMBOL, 118),
    (10, HUFFMAN_EMIT_SYMBOL, 118),
    (15, HUFFMAN_EMIT_SYMBOL, 118),
    (24, HUFFMAN_EMIT_SYMBOL, 118),
    (31, HUFFMAN_EMIT_SYMBOL, 118),
    (41, HUFFMAN_EMIT_SYMBOL, 118),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 118),

    # Node 64
    (1, HUFFMAN_EMIT_SYMBOL, 119),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 119),
    (1, HUFFMAN_EMIT_SYMBOL, 120),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 120),
    (1, HUFFMAN_EMIT_SYMBOL, 121),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 121),
    (1, HUFFMAN_EMIT_SYMBOL, 122),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 122),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 38),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 42),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 44),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 59),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 88),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 90),
    (75, 0, 0),
    (78, 0, 0),

    # Node 65
    (2, HUFFMAN_EMIT_SYMBOL, 119),
    (9, HUFFMAN_EMIT_SYMBOL, 119),
    (23, HUFFMAN_EMIT_SYMBOL, 119),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 119),
    (2, HUFFMAN_EMIT_SYMBOL, 120),
    (9, HUFFMAN_EMIT_SYMBOL, 120),
    (23, HUFFMAN_EMIT_SYMBOL, 120),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 120),
    (2, HUFFMAN_EMIT_SYMBOL, 121),
    (9, HUFFMAN_EMIT_SYMBOL, 121),
    (23, HUFFMAN_EMIT_SYMBOL, 121),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 121),
    (2, HUFFMAN_EMIT_SYMBOL, 122),
    (9, HUFFMAN_EMIT_SYMBOL, 122),
    (23, HUFFMAN_EMIT_SYMBOL, 122),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 122),

    # Node 66
    (3, HUFFMAN_EMIT_SYMBOL, 119),
    (6, HUFFMAN_EMIT_SYMBOL, 119),
    (10, HUFFMAN_EMIT_SYMBOL, 119),
    (15, HUFFMAN_EMIT_SYMBOL, 119),
    (24, HUFFMAN_EMIT_SYMBOL, 119),
    (31, HUFFMAN_EMIT_SYMBOL, 119),
    (41, HUFFMAN_EMIT_SYMBOL, 119),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 119),
    (3, HUFFMAN_EMIT_SYMBOL, 120),
    (6, HUFFMAN_EMIT_SYMBOL, 120),
    (10, HUFFMAN_EMIT_SYMBOL, 120),
    (15, HUFFMAN_EMIT_SYMBOL, 120),
    (24, HUFFMAN_EMIT_SYMBOL, 120),
    (31, HUFFMAN_EMIT_SYMBOL, 120),
    (41, HUFFMAN_EMIT_SYMBOL, 120),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 120),

    # Node 67
    (3, HUFFMAN_EMIT_SYMBOL, 121),
    (6, HUFFMAN_EMIT_SYMBOL, 121),
    (10, HUFFMAN_EMIT_SYMBOL, 121),
    (15, HUFFMAN_EMIT_SYMBOL, 121),
    (24, HUFFMAN_EMIT_SYMBOL, 121),
    (31, HUFFMAN_EMIT_SYMBOL, 121),
    (41, HUFFMAN_EMIT_SYMBOL, 121),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 121),
    (3, HUFFMAN_EMIT_SYMBOL, 122),
    (6, HUFFMAN_EMIT_SYMBOL, 122),
    (10, HUFFMAN_EMIT_SYMBOL, 122),
    (15, HUFFMAN_EMIT_SYMBOL, 122),
    (24, HUFFMAN_EMIT_SYMBOL, 122),
    (31, HUFFMAN_EMIT_SYMBOL, 122),
    (41, HUFFMAN_EMIT_SYMBOL, 122),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 122),

    # Node 68
    (1, HUFFMAN_EMIT_SYMBOL, 38),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 38),
    (1, HUFFMAN_EMIT_SYMBOL, 42),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 42),
    (1, HUFFMAN_EMIT_SYMBOL, 44),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 44),
    (1, HUFFMAN_EMIT_SYMBOL, 59),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 59),
    (1, HUFFMAN_EMIT_SYMBOL, 88),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 88),
    (1, HUFFMAN_EMIT_SYMBOL, 90),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 90),
    (76, 0, 0),
    (77, 0, 0),
    (79, 0, 0),
    (81, 0, 0),

    # Node 69
    (2, HUFFMAN_EMIT_SYMBOL, 38),
    (9, HUFFMAN_EMIT_SYMBOL, 38),
    (23, HUFFMAN_EMIT_SYMBOL, 38),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 38),
    (2, HUFFMAN_EMIT_SYMBOL, 42),
    (9, HUFFMAN_EMIT_SYMBOL, 42),
    (23, HUFFMAN_EMIT_SYMBOL, 42),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 42),
    (2, HUFFMAN_EMIT_SYMBOL, 44),
    (9, HUFFMAN_EMIT_SYMBOL, 44),
    (23, HUFFMAN_EMIT_SYMBOL, 44),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 44),
    (2, HUFFMAN_EMIT_SYMBOL, 59),
    (9, HUFFMAN_EMIT_SYMBOL, 59),
    (23, HUFFMAN_EMIT_SYMBOL, 59),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 59),

    # Node 70
    (3, HUFFMAN_EMIT_SYMBOL, 38),
    (6, HUFFMAN_EMIT_SYMBOL, 38),
    (10, HUFFMAN_EMIT_SYMBOL, 38),
    (15, HUFFMAN_EMIT_SYMBOL, 38),
    (24, HUFFMAN_EMIT_SYMBOL, 38),
    (31, HUFFMAN_EMIT_SYMBOL, 38),
    (41, HUFFMAN_EMIT_SYMBOL, 38),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 38),
    (3, HUFFMAN_EMIT_SYMBOL, 42),
    (6, HUFFMAN_EMIT_SYMBOL, 42),
    (10, HUFFMAN_EMIT_SYMBOL, 42),
    (15, HUFFMAN_EMIT_SYMBOL, 42),
    (24, HUFFMAN_EMIT_SYMBOL, 42),
    (31, HUFFMAN_EMIT_SYMBOL, 42),
    (41, HUFFMAN_EMIT_SYMBOL, 42),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 42),

    # Node 71
    (3, HUFFMAN_EMIT_SYMBOL, 44),
    (6, HUFFMAN_EMIT_SYMBOL, 44),
    (10, HUFFMAN_EMIT_SYMBOL, 44),
    (15, HUFFMAN_EMIT_SYMBOL, 44),
    (24, HUFFMAN_EMIT_SYMBOL, 44),
    (31, HUFFMAN_EMIT_SYMBOL, 44),
    (41, HUFFMAN_EMIT_SYMBOL, 44),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 44),
    (3, HUFFMAN_EMIT_SYMBOL, 59),
    (6, HUFFMAN_EMIT_SYMBOL, 59),
    (10, HUFFMAN_EMIT_SYMBOL, 59),
    (15, HUFFMAN_EMIT_SYMBOL, 59),
    (24, HUFFMAN_EMIT_SYMBOL, 59),
    (31, HUFFMAN_EMIT_SYMBOL, 59),
    (41, HUFFMAN_EMIT_SYMBOL, 59),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 59),

    # Node 72
    (2, HUFFMAN_EMIT_SYMBOL, 88),
    (9, HUFFMAN_EMIT_SYMBOL, 88),
    (23, HUFFMAN_EMIT_SYMBOL, 88),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 88),
    (2, HUFFMAN_EMIT_SYMBOL, 90),
    (9, HUFFMAN_EMIT_SYMBOL, 90),
    (23, HUFFMAN_EMIT_SYMBOL, 90),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 90),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 33),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 34),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 40),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 41),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 63),
    (80, 0, 0),
    (82, 0, 0),
    (84, 0, 0),

    # Node 73
    (3, HUFFMAN_EMIT_SYMBOL, 88),
    (6, HUFFMAN_EMIT_SYMBOL, 88),
    (10, HUFFMAN_EMIT_SYMBOL, 88),
    (15, HUFFMAN_EMIT_SYMBOL, 88),
    (24, HUFFMAN_EMIT_SYMBOL, 88),
    (31, HUFFMAN_EMIT_SYMBOL, 88),
    (41, HUFFMAN_EMIT_SYMBOL, 88),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 88),
    (3, HUFFMAN_EMIT_SYMBOL, 90),
    (6, HUFFMAN_EMIT_SYMBOL, 90),
    (10, HUFFMAN_EMIT_SYMBOL, 90),
    (15, HUFFMAN_EMIT_SYMBOL, 90),
    (24, HUFFMAN_EMIT_SYMBOL, 90),
    (31, HUFFMAN_EMIT_SYMBOL, 90),
    (41, HUFFMAN_EMIT_SYMBOL, 90),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 90),

    # Node 74
    (1, HUFFMAN_EMIT_SYMBOL, 33),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 33),
    (1, HUFFMAN_EMIT_SYMBOL, 34),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 34),
    (1, HUFFMAN_EMIT_SYMBOL, 40),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 40),
    (1, HUFFMAN_EMIT_SYMBOL, 41),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 41),
    (1, HUFFMAN_EMIT_SYMBOL, 63),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 63),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 39),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 43),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 124),
    (83, 0, 0),
    (85, 0, 0),
    (88, 0, 0),

    # Node 75
    (2, HUFFMAN_EMIT_SYMBOL, 33),
    (9, HUFFMAN_EMIT_SYMBOL, 33),
    (23, HUFFMAN_EMIT_SYMBOL, 33),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 33),
    (2, HUFFMAN_EMIT_SYMBOL, 34),
    (9, HUFFMAN_EMIT_SYMBOL, 34),
    (23, HUFFMAN_EMIT_SYMBOL, 34),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 34),
    (2, HUFFMAN_EMIT_SYMBOL, 40),
    (9, HUFFMAN_EMIT_SYMBOL, 40),
    (23, HUFFMAN_EMIT_SYMBOL, 40),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 40),
    (2, HUFFMAN_EMIT_SYMBOL, 41),
    (9, HUFFMAN_EMIT_SYMBOL, 41),
    (23, HUFFMAN_EMIT_SYMBOL, 41),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 41),

    # Node 76
    (3, HUFFMAN_EMIT_SYMBOL, 33),
    (6, HUFFMAN_EMIT_SYMBOL, 33),
    (10, HUFFMAN_EMIT_SYMBOL, 33),
    (15, HUFFMAN_EMIT_SYMBOL, 33),
    (24, HUFFMAN_EMIT_SYMBOL, 33),
    (31, HUFFMAN_EMIT_SYMBOL, 33),
    (41, HUFFMAN_EMIT_SYMBOL, 33),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 33),
    (3, HUFFMAN_EMIT_SYMBOL, 34),
    (6, HUFFMAN_EMIT_SYMBOL, 34),
    (10, HUFFMAN_EMIT_SYMBOL, 34),
    (15, HUFFMAN_EMIT_SYMBOL, 34),
    (24, HUFFMAN_EMIT_SYMBOL, 34),
    (31, HUFFMAN_EMIT_SYMBOL, 34),
    (41, HUFFMAN_EMIT_SYMBOL, 34),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 34),

    # Node 77
    (3, HUFFMAN_EMIT_SYMBOL, 40),
    (6, HUFFMAN_EMIT_SYMBOL, 40),
    (10, HUFFMAN_EMIT_SYMBOL, 40),
    (15, HUFFMAN_EMIT_SYMBOL, 40),
    (24, HUFFMAN_EMIT_SYMBOL, 40),
    (31, HUFFMAN_EMIT_SYMBOL, 40),
    (41, HUFFMAN_EMIT_SYMBOL, 40),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 40),
    (3, HUFFMAN_EMIT_SYMBOL, 41),
    (6, HUFFMAN_EMIT_SYMBOL, 41),
    (10, HUFFMAN_EMIT_SYMBOL, 41),
    (15, HUFFMAN_EMIT_SYMBOL, 41),
    (24, HUFFMAN_EMIT_SYMBOL, 41),
    (31, HUFFMAN_EMIT_SYMBOL, 41),
    (41, HUFFMAN_EMIT_SYMBOL, 41),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 41),

    # Node 78
    (2, HUFFMAN_EMIT_SYMBOL, 63),
    (9, HUFFMAN_EMIT_SYMBOL, 63),
    (23, HUFFMAN_EMIT_SYMBOL, 63),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 63),
    (1, HUFFMAN_EMIT_SYMBOL, 39),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 39),
    (1, HUFFMAN_EMIT_SYMBOL, 43),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 43),
    (1, HUFFMAN_EMIT_SYMBOL, 124),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 124),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 35),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 62),
    (86, 0, 0),
    (87, 0, 0),
    (89, 0, 0),
    (90, 0, 0),

    # Node 79
    (3, HUFFMAN_EMIT_SYMBOL, 63),
    (6, HUFFMAN_EMIT_SYMBOL, 63),
    (10, HUFFMAN_EMIT_SYMBOL, 63),
    (15, HUFFMAN_EMIT_SYMBOL, 63),
    (24, HUFFMAN_EMIT_SYMBOL, 63),
    (31, HUFFMAN_EMIT_SYMBOL, 63),
    (41, HUFFMAN_EMIT_SYMBOL, 63),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 63),
    (2, HUFFMAN_EMIT_SYMBOL, 39),
    (9, HUFFMAN_EMIT_SYMBOL, 39),
    (23, HUFFMAN_EMIT_SYMBOL, 39),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 39),
    (2, HUFFMAN_EMIT_SYMBOL, 43),
    (9, HUFFMAN_EMIT_SYMBOL, 43),
    (23, HUFFMAN_EMIT_SYMBOL, 43),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 43),

    # Node 80
    (3, HUFFMAN_EMIT_SYMBOL, 39),
    (6, HUFFMAN_EMIT_SYMBOL, 39),
    (10, HUFFMAN_EMIT_SYMBOL, 39),
    (15, HUFFMAN_EMIT_SYMBOL, 39),
    (24, HUFFMAN_EMIT_SYMBOL, 39),
    (31, HUFFMAN_EMIT_SYMBOL, 39),
    (41, HUFFMAN_EMIT_SYMBOL, 39),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 39),
    (3, HUFFMAN_EMIT_SYMBOL, 43),
    (6, HUFFMAN_EMIT_SYMBOL, 43),
    (10, HUFFMAN_EMIT_SYMBOL, 43),
    (15, HUFFMAN_EMIT_SYMBOL, 43),
    (24, HUFFMAN_EMIT_SYMBOL, 43),
    (31, HUFFMAN_EMIT_SYMBOL, 43),
    (41, HUFFMAN_EMIT_SYMBOL, 43),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 43),

    # Node 81
    (2, HUFFMAN_EMIT_SYMBOL, 124),
    (9, HUFFMAN_EMIT_SYMBOL, 124),
    (23, HUFFMAN_EMIT_SYMBOL, 124),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 124),
    (1, HUFFMAN_EMIT_SYMBOL, 35),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 35),
    (1, HUFFMAN_EMIT_SYMBOL, 62),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 62),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 0),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 36),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 64),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 91),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 93),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 126),
    (91, 0, 0),
    (92, 0, 0),

    # Node 82
    (3, HUFFMAN_EMIT_SYMBOL, 124),
    (6, HUFFMAN_EMIT_SYMBOL, 124),
    (10, HUFFMAN_EMIT_SYMBOL, 124),
    (15, HUFFMAN_EMIT_SYMBOL, 124),
    (24, HUFFMAN_EMIT_SYMBOL, 124),
    (31, HUFFMAN_EMIT_SYMBOL, 124),
    (41, HUFFMAN_EMIT_SYMBOL, 124),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 124),
    (2, HUFFMAN_EMIT_SYMBOL, 35),
    (9, HUFFMAN_EMIT_SYMBOL, 35),
    (23, HUFFMAN_EMIT_SYMBOL, 35),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 35),
    (2, HUFFMAN_EMIT_SYMBOL, 62),
    (9, HUFFMAN_EMIT_SYMBOL, 62),
    (23, HUFFMAN_EMIT_SYMBOL, 62),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 62),

    # Node 83
    (3, HUFFMAN_EMIT_SYMBOL, 35),
    (6, HUFFMAN_EMIT_SYMBOL, 35),
    (10, HUFFMAN_EMIT_SYMBOL, 35),
    (15, HUFFMAN_EMIT_SYMBOL, 35),
    (24, HUFFMAN_EMIT_SYMBOL, 35),
    (31, HUFFMAN_EMIT_SYMBOL, 35),
    (41, HUFFMAN_EMIT_SYMBOL, 35),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 35),
    (3, HUFFMAN_EMIT_SYMBOL, 62),
    (6, HUFFMAN_EMIT_SYMBOL, 62),
    (10, HUFFMAN_EMIT_SYMBOL, 62),
    (15, HUFFMAN_EMIT_SYMBOL, 62),
    (24, HUFFMAN_EMIT_SYMBOL, 62),
    (31, HUFFMAN_EMIT_SYMBOL, 62),
    (41, HUFFMAN_EMIT_SYMBOL, 62),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 62),

    # Node 84
    (1, HUFFMAN_EMIT_SYMBOL, 0),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 0),
    (1, HUFFMAN_EMIT_SYMBOL, 36),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 36),
    (1, HUFFMAN_EMIT_SYMBOL, 64),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 64),
    (1, HUFFMAN_EMIT_SYMBOL, 91),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 91),
    (1, HUFFMAN_EMIT_SYMBOL, 93),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 93),
    (1, HUFFMAN_EMIT_SYMBOL, 126),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 126),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 94),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 125),
    (93, 0, 0),
    (94, 0, 0),

    # Node 85
    (2, HUFFMAN_EMIT_SYMBOL, 0),
    (9, HUFFMAN_EMIT_SYMBOL, 0),
    (23, HUFFMAN_EMIT_SYMBOL, 0),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 0),
    (2, HUFFMAN_EMIT_SYMBOL, 36),
    (9, HUFFMAN_EMIT_SYMBOL, 36),
    (23, HUFFMAN_EMIT_SYMBOL, 36),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 36),
    (2, HUFFMAN_EMIT_SYMBOL, 64),
    (9, HUFFMAN_EMIT_SYMBOL, 64),
    (23, HUFFMAN_EMIT_SYMBOL, 64),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 64),
    (2, HUFFMAN_EMIT_SYMBOL, 91),
    (9, HUFFMAN_EMIT_SYMBOL, 91),
    (23, HUFFMAN_EMIT_SYMBOL, 91),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 91),

    # Node 86
    (3, HUFFMAN_EMIT_SYMBOL, 0),
    (6, HUFFMAN_EMIT_SYMBOL, 0),
    (10, HUFFMAN_EMIT_SYMBOL, 0),
    (15, HUFFMAN_EMIT_SYMBOL, 0),
    (24, HUFFMAN_EMIT_SYMBOL, 0),
    (31, HUFFMAN_EMIT_SYMBOL, 0),
    (41, HUFFMAN_EMIT_SYMBOL, 0),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 0),
    (3, HUFFMAN_EMIT_SYMBOL, 36),
    (6, HUFFMAN_EMIT_SYMBOL, 36),
    (10, HUFFMAN_EMIT_SYMBOL, 36),
    (15, HUFFMAN_EMIT_SYMBOL, 36),
    (24, HUFFMAN_EMIT_SYMBOL, 36),
    (31, HUFFMAN_EMIT_SYMBOL, 36),
    (41, HUFFMAN_EMIT_SYMBOL, 36),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 36),

    # Node 87
    (3, HUFFMAN_EMIT_SYMBOL, 64),
    (6, HUFFMAN_EMIT_SYMBOL, 64),
    (10, HUFFMAN_EMIT_SYMBOL, 64),
    (15, HUFFMAN_EMIT_SYMBOL, 64),
    (24, HUFFMAN_EMIT_SYMBOL, 64),
    (31, HUFFMAN_EMIT_SYMBOL, 64),
    (41, HUFFMAN_EMIT_SYMBOL, 64),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 64),
    (3, HUFFMAN_EMIT_SYMBOL, 91),
    (6, HUFFMAN_EMIT_SYMBOL, 91),
    (10, HUFFMAN_EMIT_SYMBOL, 91),
    (15, HUFFMAN_EMIT_SYMBOL, 91),
    (24, HUFFMAN_EMIT_SYMBOL, 91),
    (31, HUFFMAN_EMIT_SYMBOL, 91),
    (41, HUFFMAN_EMIT_SYMBOL, 91),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 91),

    # Node 88
    (2, HUFFMAN_EMIT_SYMBOL, 93),
    (9, HUFFMAN_EMIT_SYMBOL, 93),
    (23, HUFFMAN_EMIT_SYMBOL, 93),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 93),
    (2, HUFFMAN_EMIT_SYMBOL, 126),
    (9, HUFFMAN_EMIT_SYMBOL, 126),
    (23, HUFFMAN_EMIT_SYMBOL, 126),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 126),
    (1, HUFFMAN_EMIT_SYMBOL, 94),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 94),
    (1, HUFFMAN_EMIT_SYMBOL, 125),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 125),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 60),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 96),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 123),
    (95, 0, 0),

    # Node 89
    (3, HUFFMAN_EMIT_SYMBOL, 93),
    (6, HUFFMAN_EMIT_SYMBOL, 93),
    (10, HUFFMAN_EMIT_SYMBOL, 93),
    (15, HUFFMAN_EMIT_SYMBOL, 93),
    (24, HUFFMAN_EMIT_SYMBOL, 93),
    (31, HUFFMAN_EMIT_SYMBOL, 93),
    (41, HUFFMAN_EMIT_SYMBOL, 93),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 93),
    (3, HUFFMAN_EMIT_SYMBOL, 126),
    (6, HUFFMAN_EMIT_SYMBOL, 126),
    (10, HUFFMAN_EMIT_SYMBOL, 126),
    (15, HUFFMAN_EMIT_SYMBOL, 126),
    (24, HUFFMAN_EMIT_SYMBOL, 126),
    (31, HUFFMAN_EMIT_SYMBOL, 126),
    (41, HUFFMAN_EMIT_SYMBOL, 126),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 126),

    # Node 90
    (2, HUFFMAN_EMIT_SYMBOL, 94),
    (9, HUFFMAN_EMIT_SYMBOL, 94),
    (23, HUFFMAN_EMIT_SYMBOL, 94),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 94),
    (2, HUFFMAN_EMIT_SYMBOL, 125),
    (9, HUFFMAN_EMIT_SYMBOL, 125),
    (23, HUFFMAN_EMIT_SYMBOL, 125),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 125),
    (1, HUFFMAN_EMIT_SYMBOL, 60),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 60),
    (1, HUFFMAN_EMIT_SYMBOL, 96),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 96),
    (1, HUFFMAN_EMIT_SYMBOL, 123),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 123),
    (96, 0, 0),
    (110, 0, 0),

    # Node 91
    (3, HUFFMAN_EMIT_SYMBOL, 94),
    (6, HUFFMAN_EMIT_SYMBOL, 94),
    (10, HUFFMAN_EMIT_SYMBOL, 94),
    (15, HUFFMAN_EMIT_SYMBOL, 94),
    (24, HUFFMAN_EMIT_SYMBOL, 94),
    (31, HUFFMAN_EMIT_SYMBOL, 94),
    (41, HUFFMAN_EMIT_SYMBOL, 94),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 94),
    (3, HUFFMAN_EMIT_SYMBOL, 125),
    (6, HUFFMAN_EMIT_SYMBOL, 125),
    (10, HUFFMAN_EMIT_SYMBOL, 125),
    (15, HUFFMAN_EMIT_SYMBOL, 125),
    (24, HUFFMAN_EMIT_SYMBOL, 125),
    (31, HUFFMAN_EMIT_SYMBOL, 125),
    (41, HUFFMAN_EMIT_SYMBOL, 125),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 125),

    # Node 92
    (2, HUFFMAN_EMIT_SYMBOL, 60),
    (9, HUFFMAN_EMIT_SYMBOL, 60),
    (23, HUFFMAN_EMIT_SYMBOL, 60),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 60),
    (2, HUFFMAN_EMIT_SYMBOL, 96),
    (9, HUFFMAN_EMIT_SYMBOL, 96),
    (23, HUFFMAN_EMIT_SYMBOL, 96),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 96),
    (2, HUFFMAN_EMIT_SYMBOL, 123),
    (9, HUFFMAN_EMIT_SYMBOL, 123),
    (23, HUFFMAN_EMIT_SYMBOL, 123),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 123),
    (97, 0, 0),
    (101, 0, 0),
    (111, 0, 0),
    (133, 0, 0),

    # Node 93
    (3, HUFFMAN_EMIT_SYMBOL, 60),
    (6, HUFFMAN_EMIT_SYMBOL, 60),
    (10, HUFFMAN_EMIT_SYMBOL, 60),
    (15, HUFFMAN_EMIT_SYMBOL, 60),
    (24, HUFFMAN_EMIT_SYMBOL, 60),
    (31, HUFFMAN_EMIT_SYMBOL, 60),
    (41, HUFFMAN_EMIT_SYMBOL, 60),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 60),
    (3, HUFFMAN_EMIT_SYMBOL, 96),
    (6, HUFFMAN_EMIT_SYMBOL, 96),
    (10, HUFFMAN_EMIT_SYMBOL, 96),
    (15, HUFFMAN_EMIT_SYMBOL, 96),
    (24, HUFFMAN_EMIT_SYMBOL, 96),
    (31, HUFFMAN_EMIT_SYMBOL, 96),
    (41, HUFFMAN_EMIT_SYMBOL, 96),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 96),

    # Node 94
    (3, HUFFMAN_EMIT_SYMBOL, 123),
    (6, HUFFMAN_EMIT_SYMBOL, 123),
    (10, HUFFMAN_EMIT_SYMBOL, 123),
    (15, HUFFMAN_EMIT_SYMBOL, 123),
    (24, HUFFMAN_EMIT_SYMBOL, 123),
    (31, HUFFMAN_EMIT_SYMBOL, 123),
    (41, HUFFMAN_EMIT_SYMBOL, 123),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 123),
    (98, 0, 0),
    (99, 0, 0),
    (102, 0, 0),
    (105, 0, 0),
    (112, 0, 0),
    (119, 0, 0),
    (134, 0, 0),
    (153, 0, 0),

    # Node 95
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 92),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 195),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 208),
    (100, 0, 0),
    (103, 0, 0),
    (104, 0, 0),
    (106, 0, 0),
    (107, 0, 0),
    (113, 0, 0),
    (116, 0, 0),
    (120, 0, 0),
    (126, 0, 0),
    (135, 0, 0),
    (142, 0, 0),
    (154, 0, 0),
    (169, 0, 0),

    # Node 96
    (1, HUFFMAN_EMIT_SYMBOL, 92),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 92),
    (1, HUFFMAN_EMIT_SYMBOL, 195),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 195),
    (1, HUFFMAN_EMIT_SYMBOL, 208),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 208),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 128),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 130),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 131),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 162),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 184),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 194),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 224),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 226),
    (108, 0, 0),
    (109, 0, 0),

    # Node 97
    (2, HUFFMAN_EMIT_SYMBOL, 92),
    (9, HUFFMAN_EMIT_SYMBOL, 92),
    (23, HUFFMAN_EMIT_SYMBOL, 92),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 92),
    (2, HUFFMAN_EMIT_SYMBOL, 195),
    (9, HUFFMAN_EMIT_SYMBOL, 195),
    (23, HUFFMAN_EMIT_SYMBOL, 195),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 195),
    (2, HUFFMAN_EMIT_SYMBOL, 208),
    (9, HUFFMAN_EMIT_SYMBOL, 208),
    (23, HUFFMAN_EMIT_SYMBOL, 208),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 208),
    (1, HUFFMAN_EMIT_SYMBOL, 128),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 128),
    (1, HUFFMAN_EMIT_SYMBOL, 130),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 130),

    # Node 98
    (3, HUFFMAN_EMIT_SYMBOL, 92),
    (6, HUFFMAN_EMIT_SYMBOL, 92),
    (10, HUFFMAN_EMIT_SYMBOL, 92),
    (15, HUFFMAN_EMIT_SYMBOL, 92),
    (24, HUFFMAN_EMIT_SYMBOL, 92),
    (31, HUFFMAN_EMIT_SYMBOL, 92),
    (41, HUFFMAN_EMIT_SYMBOL, 92),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 92),
    (3, HUFFMAN_EMIT_SYMBOL, 195),
    (6, HUFFMAN_EMIT_SYMBOL, 195),
    (10, HUFFMAN_EMIT_SYMBOL, 195),
    (15, HUFFMAN_EMIT_SYMBOL, 195),
    (24, HUFFMAN_EMIT_SYMBOL, 195),
    (31, HUFFMAN_EMIT_SYMBOL, 195),
    (41, HUFFMAN_EMIT_SYMBOL, 195),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 195),

    # Node 99
    (3, HUFFMAN_EMIT_SYMBOL, 208),
    (6, HUFFMAN_EMIT_SYMBOL, 208),
    (10, HUFFMAN_EMIT_SYMBOL, 208),
    (15, HUFFMAN_EMIT_SYMBOL, 208),
    (24, HUFFMAN_EMIT_SYMBOL, 208),
    (31, HUFFMAN_EMIT_SYMBOL, 208),
    (41, HUFFMAN_EMIT_SYMBOL, 208),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 208),
    (2, HUFFMAN_EMIT_SYMBOL, 128),
    (9, HUFFMAN_EMIT_SYMBOL, 128),
    (23, HUFFMAN_EMIT_SYMBOL, 128),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 128),
    (2, HUFFMAN_EMIT_SYMBOL, 130),
    (9, HUFFMAN_EMIT_SYMBOL, 130),
    (23, HUFFMAN_EMIT_SYMBOL, 130),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 130),

    # Node 100
    (3, HUFFMAN_EMIT_SYMBOL, 128),
    (6, HUFFMAN_EMIT_SYMBOL, 128),
    (10, HUFFMAN_EMIT_SYMBOL, 128),
    (15, HUFFMAN_EMIT_SYMBOL, 128),
    (24, HUFFMAN_EMIT_SYMBOL, 128),
    (31, HUFFMAN_EMIT_SYMBOL, 128),
    (41, HUFFMAN_EMIT_SYMBOL, 128),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 128),
    (3, HUFFMAN_EMIT_SYMBOL, 130),
    (6, HUFFMAN_EMIT_SYMBOL, 130),
    (10, HUFFMAN_EMIT_SYMBOL, 130),
    (15, HUFFMAN_EMIT_SYMBOL, 130),
    (24, HUFFMAN_EMIT_SYMBOL, 130),
    (31, HUFFMAN_EMIT_SYMBOL, 130),
    (41, HUFFMAN_EMIT_SYMBOL, 130),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 130),

    # Node 101
    (1, HUFFMAN_EMIT_SYMBOL, 131),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 131),
    (1, HUFFMAN_EMIT_SYMBOL, 162),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 162),
    (1, HUFFMAN_EMIT_SYMBOL, 184),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 184),
    (1, HUFFMAN_EMIT_SYMBOL, 194),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 194),
    (1, HUFFMAN_EMIT_SYMBOL, 224),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 224),
    (1, HUFFMAN_EMIT_SYMBOL, 226),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 226),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 153),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 161),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 167),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 172),

    # Node 102
    (2, HUFFMAN_EMIT_SYMBOL, 131),
    (9, HUFFMAN_EMIT_SYMBOL, 131),
    (23, HUFFMAN_EMIT_SYMBOL, 131),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 131),
    (2, HUFFMAN_EMIT_SYMBOL, 162),
    (9, HUFFMAN_EMIT_SYMBOL, 162),
    (23, HUFFMAN_EMIT_SYMBOL, 162),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 162),
    (2, HUFFMAN_EMIT_SYMBOL, 184),
    (9, HUFFMAN_EMIT_SYMBOL, 184),
    (23, HUFFMAN_EMIT_SYMBOL, 184),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 184),
    (2, HUFFMAN_EMIT_SYMBOL, 194),
    (9, HUFFMAN_EMIT_SYMBOL, 194),
    (23, HUFFMAN_EMIT_SYMBOL, 194),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 194),

    # Node 103
    (3, HUFFMAN_EMIT_SYMBOL, 131),
    (6, HUFFMAN_EMIT_SYMBOL, 131),
    (10, HUFFMAN_EMIT_SYMBOL, 131),
    (15, HUFFMAN_EMIT_SYMBOL, 131),
    (24, HUFFMAN_EMIT_SYMBOL, 131),
    (31, HUFFMAN_EMIT_SYMBOL, 131),
    (41, HUFFMAN_EMIT_SYMBOL, 131),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 131),
    (3, HUFFMAN_EMIT_SYMBOL, 162),
    (6, HUFFMAN_EMIT_SYMBOL, 162),
    (10, HUFFMAN_EMIT_SYMBOL, 162),
    (15, HUFFMAN_EMIT_SYMBOL, 162),
    (24, HUFFMAN_EMIT_SYMBOL, 162),
    (31, HUFFMAN_EMIT_SYMBOL, 162),
    (41, HUFFMAN_EMIT_SYMBOL, 162),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 162),

    # Node 104
    (3, HUFFMAN_EMIT_SYMBOL, 184),
    (6, HUFFMAN_EMIT_SYMBOL, 184),
    (10, HUFFMAN_EMIT_SYMBOL, 184),
    (15, HUFFMAN_EMIT_SYMBOL, 184),
    (24, HUFFMAN_EMIT_SYMBOL, 184),
    (31, HUFFMAN_EMIT_SYMBOL, 184),
    (41, HUFFMAN_EMIT_SYMBOL, 184),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 184),
    (3, HUFFMAN_EMIT_SYMBOL, 194),
    (6, HUFFMAN_EMIT_SYMBOL, 194),
    (10, HUFFMAN_EMIT_SYMBOL, 194),
    (15, HUFFMAN_EMIT_SYMBOL, 194),
    (24, HUFFMAN_EMIT_SYMBOL, 194),
    (31, HUFFMAN_EMIT_SYMBOL, 194),
    (41, HUFFMAN_EMIT_SYMBOL, 194),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 194),

    # Node 105
    (2, HUFFMAN_EMIT_SYMBOL, 224),
    (9, HUFFMAN_EMIT_SYMBOL, 224),
    (23, HUFFMAN_EMIT_SYMBOL, 224),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 224),
    (2, HUFFMAN_EMIT_SYMBOL, 226),
    (9, HUFFMAN_EMIT_SYMBOL, 226),
    (23, HUFFMAN_EMIT_SYMBOL, 226),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 226),
    (1, HUFFMAN_EMIT_SYMBOL, 153),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 153),
    (1, HUFFMAN_EMIT_SYMBOL, 161),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 161),
    (1, HUFFMAN_EMIT_SYMBOL, 167),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 167),
    (1, HUFFMAN_EMIT_SYMBOL, 172),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 172),

    # Node 106
    (3, HUFFMAN_EMIT_SYMBOL, 224),
    (6, HUFFMAN_EMIT_SYMBOL, 224),
    (10, HUFFMAN_EMIT_SYMBOL, 224),
    (15, HUFFMAN_EMIT_SYMBOL, 224),
    (24, HUFFMAN_EMIT_SYMBOL, 224),
    (31, HUFFMAN_EMIT_SYMBOL, 224),
    (41, HUFFMAN_EMIT_SYMBOL, 224),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 224),
    (3, HUFFMAN_EMIT_SYMBOL, 226),
    (6, HUFFMAN_EMIT_SYMBOL, 226),
    (10, HUFFMAN_EMIT_SYMBOL, 226),
    (15, HUFFMAN_EMIT_SYMBOL, 226),
    (24, HUFFMAN_EMIT_SYMBOL, 226),
    (31, HUFFMAN_EMIT_SYMBOL, 226),
    (41, HUFFMAN_EMIT_SYMBOL, 226),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 226),

    # Node 107
    (2, HUFFMAN_EMIT_SYMBOL, 153),
    (9, HUFFMAN_EMIT_SYMBOL, 153),
    (23, HUFFMAN_EMIT_SYMBOL, 153),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 153),
    (2, HUFFMAN_EMIT_SYMBOL, 161),
    (9, HUFFMAN_EMIT_SYMBOL, 161),
    (23, HUFFMAN_EMIT_SYMBOL, 161),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 161),
    (2, HUFFMAN_EMIT_SYMBOL, 167),
    (9, HUFFMAN_EMIT_SYMBOL, 167),
    (23, HUFFMAN_EMIT_SYMBOL, 167),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 167),
    (2, HUFFMAN_EMIT_SYMBOL, 172),
    (9, HUFFMAN_EMIT_SYMBOL, 172),
    (23, HUFFMAN_EMIT_SYMBOL, 172),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 172),

    # Node 108
    (3, HUFFMAN_EMIT_SYMBOL, 153),
    (6, HUFFMAN_EMIT_SYMBOL, 153),
    (10, HUFFMAN_EMIT_SYMBOL, 153),
    (15, HUFFMAN_EMIT_SYMBOL, 153),
    (24, HUFFMAN_EMIT_SYMBOL, 153),
    (31, HUFFMAN_EMIT_SYMBOL, 153),
    (41, HUFFMAN_EMIT_SYMBOL, 153),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 153),
    (3, HUFFMAN_EMIT_SYMBOL, 161),
    (6, HUFFMAN_EMIT_SYMBOL, 161),
    (10, HUFFMAN_EMIT_SYMBOL, 161),
    (15, HUFFMAN_EMIT_SYMBOL, 161),
    (24, HUFFMAN_EMIT_SYMBOL, 161),
    (31, HUFFMAN_EMIT_SYMBOL, 161),
    (41, HUFFMAN_EMIT_SYMBOL, 161),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 161),

    # Node 109
    (3, HUFFMAN_EMIT_SYMBOL, 167),
    (6, HUFFMAN_EMIT_SYMBOL, 167),
    (10, HUFFMAN_EMIT_SYMBOL, 167),
    (15, HUFFMAN_EMIT_SYMBOL, 167),
    (24, HUFFMAN_EMIT_SYMBOL, 167),
    (31, HUFFMAN_EMIT_SYMBOL, 167),
    (41, HUFFMAN_EMIT_SYMBOL, 167),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 167),
    (3, HUFFMAN_EMIT_SYMBOL, 172),
    (6, HUFFMAN_EMIT_SYMBOL, 172),
    (10, HUFFMAN_EMIT_SYMBOL, 172),
    (15, HUFFMAN_EMIT_SYMBOL, 172),
    (24, HUFFMAN_EMIT_SYMBOL, 172),
    (31, HUFFMAN_EMIT_SYMBOL, 172),
    (41, HUFFMAN_EMIT_SYMBOL, 172),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 172),

    # Node 110
    (114, 0, 0),
    (115, 0, 0),
    (117, 0, 0),
    (118, 0, 0),
    (121, 0, 0),
    (123, 0, 0),
    (127, 0, 0),
    (130, 0, 0),
    (136, 0, 0),
    (139, 0, 0),
    (143, 0, 0),
    (146, 0, 0),
    (155, 0, 0),
    (162, 0, 0),
    (170, 0, 0),
    (180, 0, 0),

    # Node 111
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 176),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 177),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 179),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 209),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 216),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 217),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 227),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 229),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 230),
    (122, 0, 0),
    (124, 0, 0),
    (125, 0, 0),
    (128, 0, 0),
    (129, 0, 0),
    (131, 0, 0),
    (132, 0, 0),

    # Node 112
    (1, HUFFMAN_EMIT_SYMBOL, 176),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 176),
    (1, HUFFMAN_EMIT_SYMBOL, 177),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 177),
    (1, HUFFMAN_EMIT_SYMBOL, 179),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 179),
    (1, HUFFMAN_EMIT_SYMBOL, 209),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 209),
    (1, HUFFMAN_EMIT_SYMBOL, 216),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 216),
    (1, HUFFMAN_EMIT_SYMBOL, 217),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 217),
    (1, HUFFMAN_EMIT_SYMBOL, 227),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 227),
    (1, HUFFMAN_EMIT_SYMBOL, 229),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 229),

    # Node 113
    (2, HUFFMAN_EMIT_SYMBOL, 176),
    (9, HUFFMAN_EMIT_SYMBOL, 176),
    (23, HUFFMAN_EMIT_SYMBOL, 176),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 176),
    (2, HUFFMAN_EMIT_SYMBOL, 177),
    (9, HUFFMAN_EMIT_SYMBOL, 177),
    (23, HUFFMAN_EMIT_SYMBOL, 177),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 177),
    (2, HUFFMAN_EMIT_SYMBOL, 179),
    (9, HUFFMAN_EMIT_SYMBOL, 179),
    (23, HUFFMAN_EMIT_SYMBOL, 179),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 179),
    (2, HUFFMAN_EMIT_SYMBOL, 209),
    (9, HUFFMAN_EMIT_SYMBOL, 209),
    (23, HUFFMAN_EMIT_SYMBOL, 209),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 209),

    # Node 114
    (3, HUFFMAN_EMIT_SYMBOL, 176),
    (6, HUFFMAN_EMIT_SYMBOL, 176),
    (10, HUFFMAN_EMIT_SYMBOL, 176),
    (15, HUFFMAN_EMIT_SYMBOL, 176),
    (24, HUFFMAN_EMIT_SYMBOL, 176),
    (31, HUFFMAN_EMIT_SYMBOL, 176),
    (41, HUFFMAN_EMIT_SYMBOL, 176),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 176),
    (3, HUFFMAN_EMIT_SYMBOL, 177),
    (6, HUFFMAN_EMIT_SYMBOL, 177),
    (10, HUFFMAN_EMIT_SYMBOL, 177),
    (15, HUFFMAN_EMIT_SYMBOL, 177),
    (24, HUFFMAN_EMIT_SYMBOL, 177),
    (31, HUFFMAN_EMIT_SYMBOL, 177),
    (41, HUFFMAN_EMIT_SYMBOL, 177),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 177),

    # Node 115
    (3, HUFFMAN_EMIT_SYMBOL, 179),
    (6, HUFFMAN_EMIT_SYMBOL, 179),
    (10, HUFFMAN_EMIT_SYMBOL, 179),
    (15, HUFFMAN_EMIT_SYMBOL, 179),
    (24, HUFFMAN_EMIT_SYMBOL, 179),
    (31, HUFFMAN_EMIT_SYMBOL, 179),
    (41, HUFFMAN_EMIT_SYMBOL, 179),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 179),
    (3, HUFFMAN_EMIT_SYMBOL, 209),
    (6, HUFFMAN_EMIT_SYMBOL, 209),
    (10, HUFFMAN_EMIT_SYMBOL, 209),
    (15, HUFFMAN_EMIT_SYMBOL, 209),
    (24, HUFFMAN_EMIT_SYMBOL, 209),
    (31, HUFFMAN_EMIT_SYMBOL, 209),
    (41, HUFFMAN_EMIT_SYMBOL, 209),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 209),

    # Node 116
    (2, HUFFMAN_EMIT_SYMBOL, 216),
    (9, HUFFMAN_EMIT_SYMBOL, 216),
    (23, HUFFMAN_EMIT_SYMBOL, 216),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 216),
    (2, HUFFMAN_EMIT_SYMBOL, 217),
    (9, HUFFMAN_EMIT_SYMBOL, 217),
    (23, HUFFMAN_EMIT_SYMBOL, 217),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 217),
    (2, HUFFMAN_EMIT_SYMBOL, 227),
    (9, HUFFMAN_EMIT_SYMBOL, 227),
    (23, HUFFMAN_EMIT_SYMBOL, 227),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 227),
    (2, HUFFMAN_EMIT_SYMBOL, 229),
    (9, HUFFMAN_EMIT_SYMBOL, 229),
    (23, HUFFMAN_EMIT_SYMBOL, 229),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 229),

    # Node 117
    (3, HUFFMAN_EMIT_SYMBOL, 216),
    (6, HUFFMAN_EMIT_SYMBOL, 216),
    (10, HUFFMAN_EMIT_SYMBOL, 216),
    (15, HUFFMAN_EMIT_SYMBOL, 216),
    (24, HUFFMAN_EMIT_SYMBOL, 216),
    (31, HUFFMAN_EMIT_SYMBOL, 216),
    (41, HUFFMAN_EMIT_SYMBOL, 216),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 216),
    (3, HUFFMAN_EMIT_SYMBOL, 217),
    (6, HUFFMAN_EMIT_SYMBOL, 217),
    (10, HUFFMAN_EMIT_SYMBOL, 217),
    (15, HUFFMAN_EMIT_SYMBOL, 217),
    (24, HUFFMAN_EMIT_SYMBOL, 217),
    (31, HUFFMAN_EMIT_SYMBOL, 217),
    (41, HUFFMAN_EMIT_SYMBOL, 217),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 217),

    # Node 118
    (3, HUFFMAN_EMIT_SYMBOL, 227),
    (6, HUFFMAN_EMIT_SYMBOL, 227),
    (10, HUFFMAN_EMIT_SYMBOL, 227),
    (15, HUFFMAN_EMIT_SYMBOL, 227),
    (24, HUFFMAN_EMIT_SYMBOL, 227),
    (31, HUFFMAN_EMIT_SYMBOL, 227),
    (41, HUFFMAN_EMIT_SYMBOL, 227),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 227),
    (3, HUFFMAN_EMIT_SYMBOL, 229),
    (6, HUFFMAN_EMIT_SYMBOL, 229),
    (10, HUFFMAN_EMIT_SYMBOL, 229),
    (15, HUFFMAN_EMIT_SYMBOL, 229),
    (24, HUFFMAN_EMIT_SYMBOL, 229),
    (31, HUFFMAN_EMIT_SYMBOL, 229),
    (41, HUFFMAN_EMIT_SYMBOL, 229),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 229),

    # Node 119
    (1, HUFFMAN_EMIT_SYMBOL, 230),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 230),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 129),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 132),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 133),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 134),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 136),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 146),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 154),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 156),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 160),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 163),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 164),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 169),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 170),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 173),

    # Node 120
    (2, HUFFMAN_EMIT_SYMBOL, 230),
    (9, HUFFMAN_EMIT_SYMBOL, 230),
    (23, HUFFMAN_EMIT_SYMBOL, 230),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 230),
    (1, HUFFMAN_EMIT_SYMBOL, 129),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 129),
    (1, HUFFMAN_EMIT_SYMBOL, 132),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 132),
    (1, HUFFMAN_EMIT_SYMBOL, 133),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 133),
    (1, HUFFMAN_EMIT_SYMBOL, 134),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 134),
    (1, HUFFMAN_EMIT_SYMBOL, 136),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 136),
    (1, HUFFMAN_EMIT_SYMBOL, 146),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 146),

    # Node 121
    (3, HUFFMAN_EMIT_SYMBOL, 230),
    (6, HUFFMAN_EMIT_SYMBOL, 230),
    (10, HUFFMAN_EMIT_SYMBOL, 230),
    (15, HUFFMAN_EMIT_SYMBOL, 230),
    (24, HUFFMAN_EMIT_SYMBOL, 230),
    (31, HUFFMAN_EMIT_SYMBOL, 230),
    (41, HUFFMAN_EMIT_SYMBOL, 230),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 230),
    (2, HUFFMAN_EMIT_SYMBOL, 129),
    (9, HUFFMAN_EMIT_SYMBOL, 129),
    (23, HUFFMAN_EMIT_SYMBOL, 129),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 129),
    (2, HUFFMAN_EMIT_SYMBOL, 132),
    (9, HUFFMAN_EMIT_SYMBOL, 132),
    (23, HUFFMAN_EMIT_SYMBOL, 132),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 132),

    # Node 122
    (3, HUFFMAN_EMIT_SYMBOL, 129),
    (6, HUFFMAN_EMIT_SYMBOL, 129),
    (10, HUFFMAN_EMIT_SYMBOL, 129),
    (15, HUFFMAN_EMIT_SYMBOL, 129),
    (24, HUFFMAN_EMIT_SYMBOL, 129),
    (31, HUFFMAN_EMIT_SYMBOL, 129),
    (41, HUFFMAN_EMIT_SYMBOL, 129),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 129),
    (3, HUFFMAN_EMIT_SYMBOL, 132),
    (6, HUFFMAN_EMIT_SYMBOL, 132),
    (10, HUFFMAN_EMIT_SYMBOL, 132),
    (15, HUFFMAN_EMIT_SYMBOL, 132),
    (24, HUFFMAN_EMIT_SYMBOL, 132),
    (31, HUFFMAN_EMIT_SYMBOL, 132),
    (41, HUFFMAN_EMIT_SYMBOL, 132),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 132),

    # Node 123
    (2, HUFFMAN_EMIT_SYMBOL, 133),
    (9, HUFFMAN_EMIT_SYMBOL, 133),
    (23, HUFFMAN_EMIT_SYMBOL, 133),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 133),
    (2, HUFFMAN_EMIT_SYMBOL, 134),
    (9, HUFFMAN_EMIT_SYMBOL, 134),
    (23, HUFFMAN_EMIT_SYMBOL, 134),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 134),
    (2, HUFFMAN_EMIT_SYMBOL, 136),
    (9, HUFFMAN_EMIT_SYMBOL, 136),
    (23, HUFFMAN_EMIT_SYMBOL, 136),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 136),
    (2, HUFFMAN_EMIT_SYMBOL, 146),
    (9, HUFFMAN_EMIT_SYMBOL, 146),
    (23, HUFFMAN_EMIT_SYMBOL, 146),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 146),

    # Node 124
    (3, HUFFMAN_EMIT_SYMBOL, 133),
    (6, HUFFMAN_EMIT_SYMBOL, 133),
    (10, HUFFMAN_EMIT_SYMBOL, 133),
    (15, HUFFMAN_EMIT_SYMBOL, 133),
    (24, HUFFMAN_EMIT_SYMBOL, 133),
    (31, HUFFMAN_EMIT_SYMBOL, 133),
    (41, HUFFMAN_EMIT_SYMBOL, 133),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 133),
    (3, HUFFMAN_EMIT_SYMBOL, 134),
    (6, HUFFMAN_EMIT_SYMBOL, 134),
    (10, HUFFMAN_EMIT_SYMBOL, 134),
    (15, HUFFMAN_EMIT_SYMBOL, 134),
    (24, HUFFMAN_EMIT_SYMBOL, 134),
    (31, HUFFMAN_EMIT_SYMBOL, 134),
    (41, HUFFMAN_EMIT_SYMBOL, 134),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 134),

    # Node 125
    (3, HUFFMAN_EMIT_SYMBOL, 136),
    (6, HUFFMAN_EMIT_SYMBOL, 136),
    (10, HUFFMAN_EMIT_SYMBOL, 136),
    (15, HUFFMAN_EMIT_SYMBOL, 136),
    (24, HUFFMAN_EMIT_SYMBOL, 136),
    (31, HUFFMAN_EMIT_SYMBOL, 136),
    (41, HUFFMAN_EMIT_SYMBOL, 136),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 136),
    (3, HUFFMAN_EMIT_SYMBOL, 146),
    (6, HUFFMAN_EMIT_SYMBOL, 146),
    (10, HUFFMAN_EMIT_SYMBOL, 146),
    (15, HUFFMAN_EMIT_SYMBOL, 146),
    (24, HUFFMAN_EMIT_SYMBOL, 146),
    (31, HUFFMAN_EMIT_SYMBOL, 146),
    (41, HUFFMAN_EMIT_SYMBOL, 146),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 146),

    # Node 126
    (1, HUFFMAN_EMIT_SYMBOL, 154),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 154),
    (1, HUFFMAN_EMIT_SYMBOL, 156),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 156),
    (1, HUFFMAN_EMIT_SYMBOL, 160),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 160),
    (1, HUFFMAN_EMIT_SYMBOL, 163),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 163),
    (1, HUFFMAN_EMIT_SYMBOL, 164),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 164),
    (1, HUFFMAN_EMIT_SYMBOL, 169),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 169),
    (1, HUFFMAN_EMIT_SYMBOL, 170),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 170),
    (1, HUFFMAN_EMIT_SYMBOL, 173),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 173),

    # Node 127
    (2, HUFFMAN_EMIT_SYMBOL, 154),
    (9, HUFFMAN_EMIT_SYMBOL, 154),
    (23, HUFFMAN_EMIT_SYMBOL, 154),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 154),
    (2, HUFFMAN_EMIT_SYMBOL, 156),
    (9, HUFFMAN_EMIT_SYMBOL, 156),
    (23, HUFFMAN_EMIT_SYMBOL, 156),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 156),
    (2, HUFFMAN_EMIT_SYMBOL, 160),
    (9, HUFFMAN_EMIT_SYMBOL, 160),
    (23, HUFFMAN_EMIT_SYMBOL, 160),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 160),
    (2, HUFFMAN_EMIT_SYMBOL, 163),
    (9, HUFFMAN_EMIT_SYMBOL, 163),
    (23, HUFFMAN_EMIT_SYMBOL, 163),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 163),

    # Node 128
    (3, HUFFMAN_EMIT_SYMBOL, 154),
    (6, HUFFMAN_EMIT_SYMBOL, 154),
    (10, HUFFMAN_EMIT_SYMBOL, 154),
    (15, HUFFMAN_EMIT_SYMBOL, 154),
    (24, HUFFMAN_EMIT_SYMBOL, 154),
    (31, HUFFMAN_EMIT_SYMBOL, 154),
    (41, HUFFMAN_EMIT_SYMBOL, 154),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 154),
    (3, HUFFMAN_EMIT_SYMBOL, 156),
    (6, HUFFMAN_EMIT_SYMBOL, 156),
    (10, HUFFMAN_EMIT_SYMBOL, 156),
    (15, HUFFMAN_EMIT_SYMBOL, 156),
    (24, HUFFMAN_EMIT_SYMBOL, 156),
    (31, HUFFMAN_EMIT_SYMBOL, 156),
    (41, HUFFMAN_EMIT_SYMBOL, 156),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 156),

    # Node 129
    (3, HUFFMAN_EMIT_SYMBOL, 160),
    (6, HUFFMAN_EMIT_SYMBOL, 160),
    (10, HUFFMAN_EMIT_SYMBOL, 160),
    (15, HUFFMAN_EMIT_SYMBOL, 160),
    (24, HUFFMAN_EMIT_SYMBOL, 160),
    (31, HUFFMAN_EMIT_SYMBOL, 160),
    (41, HUFFMAN_EMIT_SYMBOL, 160),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 160),
    (3, HUFFMAN_EMIT_SYMBOL, 163),
    (6, HUFFMAN_EMIT_SYMBOL, 163),
    (10, HUFFMAN_EMIT_SYMBOL, 163),
    (15, HUFFMAN_EMIT_SYMBOL, 163),
    (24, HUFFMAN_EMIT_SYMBOL, 163),
    (31, HUFFMAN_EMIT_SYMBOL, 163),
    (41, HUFFMAN_EMIT_SYMBOL, 163),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 163),

    # Node 130
    (2, HUFFMAN_EMIT_SYMBOL, 164),
    (9, HUFFMAN_EMIT_SYMBOL, 164),
    (23, HUFFMAN_EMIT_SYMBOL, 164),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 164),
    (2, HUFFMAN_EMIT_SYMBOL, 169),
    (9, HUFFMAN_EMIT_SYMBOL, 169),
    (23, HUFFMAN_EMIT_SYMBOL, 169),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 169),
    (2, HUFFMAN_EMIT_SYMBOL, 170),
    (9, HUFFMAN_EMIT_SYMBOL, 170),
    (23, HUFFMAN_EMIT_SYMBOL, 170),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 170),
    (2, HUFFMAN_EMIT_SYMBOL, 173),
    (9, HUFFMAN_EMIT_SYMBOL, 173),
    (23, HUFFMAN_EMIT_SYMBOL, 173),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 173),

    # Node 131
    (3, HUFFMAN_EMIT_SYMBOL, 164),
    (6, HUFFMAN_EMIT_SYMBOL, 164),
    (10, HUFFMAN_EMIT_SYMBOL, 164),
    (15, HUFFMAN_EMIT_SYMBOL, 164),
    (24, HUFFMAN_EMIT_SYMBOL, 164),
    (31, HUFFMAN_EMIT_SYMBOL, 164),
    (41, HUFFMAN_EMIT_SYMBOL, 164),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 164),
    (3, HUFFMAN_EMIT_SYMBOL, 169),
    (6, HUFFMAN_EMIT_SYMBOL, 169),
    (10, HUFFMAN_EMIT_SYMBOL, 169),
    (15, HUFFMAN_EMIT_SYMBOL, 169),
    (24, HUFFMAN_EMIT_SYMBOL, 169),
    (31, HUFFMAN_EMIT_SYMBOL, 169),
    (41, HUFFMAN_EMIT_SYMBOL, 169),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 169),

    # Node 132
    (3, HUFFMAN_EMIT_SYMBOL, 170),
    (6, HUFFMAN_EMIT_SYMBOL, 170),
    (10, HUFFMAN_EMIT_SYMBOL, 170),
    (15, HUFFMAN_EMIT_SYMBOL, 170),
    (24, HUFFMAN_EMIT_SYMBOL, 170),
    (31, HUFFMAN_EMIT_SYMBOL, 170),
    (41, HUFFMAN_EMIT_SYMBOL, 170),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 170),
    (3, HUFFMAN_EMIT_SYMBOL, 173),
    (6, HUFFMAN_EMIT_SYMBOL, 173),
    (10, HUFFMAN_EMIT_SYMBOL, 173),
    (15, HUFFMAN_EMIT_SYMBOL, 173),
    (24, HUFFMAN_EMIT_SYMBOL, 173),
    (31, HUFFMAN_EMIT_SYMBOL, 173),
    (41, HUFFMAN_EMIT_SYMBOL, 173),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 173),

    # Node 133
    (137, 0, 0),
    (138, 0, 0),
    (140, 0, 0),
    (141, 0, 0),
    (144, 0, 0),
    (145, 0, 0),
    (147, 0, 0),
    (150, 0, 0),
    (156, 0, 0),
    (159, 0, 0),
    (163, 0, 0),
    (166, 0, 0),
    (171, 0, 0),
    (174, 0, 0),
    (181, 0, 0),
    (190, 0, 0),

    # Node 134
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 178),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 181),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 185),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 186),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 187),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 189),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 190),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 196),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 198),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 228),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 232),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 233),
    (148, 0, 0),
    (149, 0, 0),
    (151, 0, 0),
    (152, 0, 0),

    # Node 135
    (1, HUFFMAN_EMIT_SYMBOL, 178),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 178),
    (1, HUFFMAN_EMIT_SYMBOL, 181),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 181),
    (1, HUFFMAN_EMIT_SYMBOL, 185),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 185),
    (1, HUFFMAN_EMIT_SYMBOL, 186),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 186),
    (1, HUFFMAN_EMIT_SYMBOL, 187),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 187),
    (1, HUFFMAN_EMIT_SYMBOL, 189),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 189),
    (1, HUFFMAN_EMIT_SYMBOL, 190),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 190),
    (1, HUFFMAN_EMIT_SYMBOL, 196),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 196),

    # Node 136
    (2, HUFFMAN_EMIT_SYMBOL, 178),
    (9, HUFFMAN_EMIT_SYMBOL, 178),
    (23, HUFFMAN_EMIT_SYMBOL, 178),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 178),
    (2, HUFFMAN_EMIT_SYMBOL, 181),
    (9, HUFFMAN_EMIT_SYMBOL, 181),
    (23, HUFFMAN_EMIT_SYMBOL, 181),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 181),
    (2, HUFFMAN_EMIT_SYMBOL, 185),
    (9, HUFFMAN_EMIT_SYMBOL, 185),
    (23, HUFFMAN_EMIT_SYMBOL, 185),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 185),
    (2, HUFFMAN_EMIT_SYMBOL, 186),
    (9, HUFFMAN_EMIT_SYMBOL, 186),
    (23, HUFFMAN_EMIT_SYMBOL, 186),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 186),

    # Node 137
    (3, HUFFMAN_EMIT_SYMBOL, 178),
    (6, HUFFMAN_EMIT_SYMBOL, 178),
    (10, HUFFMAN_EMIT_SYMBOL, 178),
    (15, HUFFMAN_EMIT_SYMBOL, 178),
    (24, HUFFMAN_EMIT_SYMBOL, 178),
    (31, HUFFMAN_EMIT_SYMBOL, 178),
    (41, HUFFMAN_EMIT_SYMBOL, 178),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 178),
    (3, HUFFMAN_EMIT_SYMBOL, 181),
    (6, HUFFMAN_EMIT_SYMBOL, 181),
    (10, HUFFMAN_EMIT_SYMBOL, 181),
    (15, HUFFMAN_EMIT_SYMBOL, 181),
    (24, HUFFMAN_EMIT_SYMBOL, 181),
    (31, HUFFMAN_EMIT_SYMBOL, 181),
    (41, HUFFMAN_EMIT_SYMBOL, 181),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 181),

    # Node 138
    (3, HUFFMAN_EMIT_SYMBOL, 185),
    (6, HUFFMAN_EMIT_SYMBOL, 185),
    (10, HUFFMAN_EMIT_SYMBOL, 185),
    (15, HUFFMAN_EMIT_SYMBOL, 185),
    (24, HUFFMAN_EMIT_SYMBOL, 185),
    (31, HUFFMAN_EMIT_SYMBOL, 185),
    (41, HUFFMAN_EMIT_SYMBOL, 185),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 185),
    (3, HUFFMAN_EMIT_SYMBOL, 186),
    (6, HUFFMAN_EMIT_SYMBOL, 186),
    (10, HUFFMAN_EMIT_SYMBOL, 186),
    (15, HUFFMAN_EMIT_SYMBOL, 186),
    (24, HUFFMAN_EMIT_SYMBOL, 186),
    (31, HUFFMAN_EMIT_SYMBOL, 186),
    (41, HUFFMAN_EMIT_SYMBOL, 186),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 186),

    # Node 139
    (2, HUFFMAN_EMIT_SYMBOL, 187),
    (9, HUFFMAN_EMIT_SYMBOL, 187),
    (23, HUFFMAN_EMIT_SYMBOL, 187),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 187),
    (2, HUFFMAN_EMIT_SYMBOL, 189),
    (9, HUFFMAN_EMIT_SYMBOL, 189),
    (23, HUFFMAN_EMIT_SYMBOL, 189),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 189),
    (2, HUFFMAN_EMIT_SYMBOL, 190),
    (9, HUFFMAN_EMIT_SYMBOL, 190),
    (23, HUFFMAN_EMIT_SYMBOL, 190),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 190),
    (2, HUFFMAN_EMIT_SYMBOL, 196),
    (9, HUFFMAN_EMIT_SYMBOL, 196),
    (23, HUFFMAN_EMIT_SYMBOL, 196),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 196),

    # Node 140
    (3, HUFFMAN_EMIT_SYMBOL, 187),
    (6, HUFFMAN_EMIT_SYMBOL, 187),
    (10, HUFFMAN_EMIT_SYMBOL, 187),
    (15, HUFFMAN_EMIT_SYMBOL, 187),
    (24, HUFFMAN_EMIT_SYMBOL, 187),
    (31, HUFFMAN_EMIT_SYMBOL, 187),
    (41, HUFFMAN_EMIT_SYMBOL, 187),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 187),
    (3, HUFFMAN_EMIT_SYMBOL, 189),
    (6, HUFFMAN_EMIT_SYMBOL, 189),
    (10, HUFFMAN_EMIT_SYMBOL, 189),
    (15, HUFFMAN_EMIT_SYMBOL, 189),
    (24, HUFFMAN_EMIT_SYMBOL, 189),
    (31, HUFFMAN_EMIT_SYMBOL, 189),
    (41, HUFFMAN_EMIT_SYMBOL, 189),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 189),

    # Node 141
    (3, HUFFMAN_EMIT_SYMBOL, 190),
    (6, HUFFMAN_EMIT_SYMBOL, 190),
    (10, HUFFMAN_EMIT_SYMBOL, 190),
    (15, HUFFMAN_EMIT_SYMBOL, 190),
    (24, HUFFMAN_EMIT_SYMBOL, 190),
    (31, HUFFMAN_EMIT_SYMBOL, 190),
    (41, HUFFMAN_EMIT_SYMBOL, 190),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 190),
    (3, HUFFMAN_EMIT_SYMBOL, 196),
    (6, HUFFMAN_EMIT_SYMBOL, 196),
    (10, HUFFMAN_EMIT_SYMBOL, 196),
    (15, HUFFMAN_EMIT_SYMBOL, 196),
    (24, HUFFMAN_EMIT_SYMBOL, 196),
    (31, HUFFMAN_EMIT_SYMBOL, 196),
    (41, HUFFMAN_EMIT_SYMBOL, 196),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 196),

    # Node 142
    (1, HUFFMAN_EMIT_SYMBOL, 198),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 198),
    (1, HUFFMAN_EMIT_SYMBOL, 228),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 228),
    (1, HUFFMAN_EMIT_SYMBOL, 232),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 232),
    (1, HUFFMAN_EMIT_SYMBOL, 233),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 233),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 1),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 135),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 137),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 138),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 139),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 140),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 141),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 143),

    # Node 143
    (2, HUFFMAN_EMIT_SYMBOL, 198),
    (9, HUFFMAN_EMIT_SYMBOL, 198),
    (23, HUFFMAN_EMIT_SYMBOL, 198),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 198),
    (2, HUFFMAN_EMIT_SYMBOL, 228),
    (9, HUFFMAN_EMIT_SYMBOL, 228),
    (23, HUFFMAN_EMIT_SYMBOL, 228),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 228),
    (2, HUFFMAN_EMIT_SYMBOL, 232),
    (9, HUFFMAN_EMIT_SYMBOL, 232),
    (23, HUFFMAN_EMIT_SYMBOL, 232),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 232),
    (2, HUFFMAN_EMIT_SYMBOL, 233),
    (9, HUFFMAN_EMIT_SYMBOL, 233),
    (23, HUFFMAN_EMIT_SYMBOL, 233),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 233),

    # Node 144
    (3, HUFFMAN_EMIT_SYMBOL, 198),
    (6, HUFFMAN_EMIT_SYMBOL, 198),
    (10, HUFFMAN_EMIT_SYMBOL, 198),
    (15, HUFFMAN_EMIT_SYMBOL, 198),
    (24, HUFFMAN_EMIT_SYMBOL, 198),
    (31, HUFFMAN_EMIT_SYMBOL, 198),
    (41, HUFFMAN_EMIT_SYMBOL, 198),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 198),
    (3, HUFFMAN_EMIT_SYMBOL, 228),
    (6, HUFFMAN_EMIT_SYMBOL, 228),
    (10, HUFFMAN_EMIT_SYMBOL, 228),
    (15, HUFFMAN_EMIT_SYMBOL, 228),
    (24, HUFFMAN_EMIT_SYMBOL, 228),
    (31, HUFFMAN_EMIT_SYMBOL, 228),
    (41, HUFFMAN_EMIT_SYMBOL, 228),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 228),

    # Node 145
    (3, HUFFMAN_EMIT_SYMBOL, 232),
    (6, HUFFMAN_EMIT_SYMBOL, 232),
    (10, HUFFMAN_EMIT_SYMBOL, 232),
    (15, HUFFMAN_EMIT_SYMBOL, 232),
    (24, HUFFMAN_EMIT_SYMBOL, 232),
    (31, HUFFMAN_EMIT_SYMBOL, 232),
    (41, HUFFMAN_EMIT_SYMBOL, 232),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 232),
    (3, HUFFMAN_EMIT_SYMBOL, 233),
    (6, HUFFMAN_EMIT_SYMBOL, 233),
    (10, HUFFMAN_EMIT_SYMBOL, 233),
    (15, HUFFMAN_EMIT_SYMBOL, 233),
    (24, HUFFMAN_EMIT_SYMBOL, 233),
    (31, HUFFMAN_EMIT_SYMBOL, 233),
    (41, HUFFMAN_EMIT_SYMBOL, 233),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 233),

    # Node 146
    (1, HUFFMAN_EMIT_SYMBOL, 1),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 1),
    (1, HUFFMAN_EMIT_SYMBOL, 135),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 135),
    (1, HUFFMAN_EMIT_SYMBOL, 137),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 137),
    (1, HUFFMAN_EMIT_SYMBOL, 138),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 138),
    (1, HUFFMAN_EMIT_SYMBOL, 139),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 139),
    (1, HUFFMAN_EMIT_SYMBOL, 140),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 140),
    (1, HUFFMAN_EMIT_SYMBOL, 141),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 141),
    (1, HUFFMAN_EMIT_SYMBOL, 143),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 143),

    # Node 147
    (2, HUFFMAN_EMIT_SYMBOL, 1),
    (9, HUFFMAN_EMIT_SYMBOL, 1),
    (23, HUFFMAN_EMIT_SYMBOL, 1),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 1),
    (2, HUFFMAN_EMIT_SYMBOL, 135),
    (9, HUFFMAN_EMIT_SYMBOL, 135),
    (23, HUFFMAN_EMIT_SYMBOL, 135),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 135),
    (2, HUFFMAN_EMIT_SYMBOL, 137),
    (9, HUFFMAN_EMIT_SYMBOL, 137),
    (23, HUFFMAN_EMIT_SYMBOL, 137),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 137),
    (2, HUFFMAN_EMIT_SYMBOL, 138),
    (9, HUFFMAN_EMIT_SYMBOL, 138),
    (23, HUFFMAN_EMIT_SYMBOL, 138),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 138),

    # Node 148
    (3, HUFFMAN_EMIT_SYMBOL, 1),
    (6, HUFFMAN_EMIT_SYMBOL, 1),
    (10, HUFFMAN_EMIT_SYMBOL, 1),
    (15, HUFFMAN_EMIT_SYMBOL, 1),
    (24, HUFFMAN_EMIT_SYMBOL, 1),
    (31, HUFFMAN_EMIT_SYMBOL, 1),
    (41, HUFFMAN_EMIT_SYMBOL, 1),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 1),
    (3, HUFFMAN_EMIT_SYMBOL, 135),
    (6, HUFFMAN_EMIT_SYMBOL, 135),
    (10, HUFFMAN_EMIT_SYMBOL, 135),
    (15, HUFFMAN_EMIT_SYMBOL, 135),
    (24, HUFFMAN_EMIT_SYMBOL, 135),
    (31, HUFFMAN_EMIT_SYMBOL, 135),
    (41, HUFFMAN_EMIT_SYMBOL, 135),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 135),

    # Node 149
    (3, HUFFMAN_EMIT_SYMBOL, 137),
    (6, HUFFMAN_EMIT_SYMBOL, 137),
    (10, HUFFMAN_EMIT_SYMBOL, 137),
    (15, HUFFMAN_EMIT_SYMBOL, 137),
    (24, HUFFMAN_EMIT_SYMBOL, 137),
    (31, HUFFMAN_EMIT_SYMBOL, 137),
    (41, HUFFMAN_EMIT_SYMBOL, 137),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 137),
    (3, HUFFMAN_EMIT_SYMBOL, 138),
    (6, HUFFMAN_EMIT_SYMBOL, 138),
    (10, HUFFMAN_EMIT_SYMBOL, 138),
    (15, HUFFMAN_EMIT_SYMBOL, 138),
    (24, HUFFMAN_EMIT_SYMBOL, 138),
    (31, HUFFMAN_EMIT_SYMBOL, 138),
    (41, HUFFMAN_EMIT_SYMBOL, 138),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 138),

    # Node 150
    (2, HUFFMAN_EMIT_SYMBOL, 139),
    (9, HUFFMAN_EMIT_SYMBOL, 139),
    (23, HUFFMAN_EMIT_SYMBOL, 139),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 139),
    (2, HUFFMAN_EMIT_SYMBOL, 140),
    (9, HUFFMAN_EMIT_SYMBOL, 140),
    (23, HUFFMAN_EMIT_SYMBOL, 140),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 140),
    (2, HUFFMAN_EMIT_SYMBOL, 141),
    (9, HUFFMAN_EMIT_SYMBOL, 141),
    (23, HUFFMAN_EMIT_SYMBOL, 141),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 141),
    (2, HUFFMAN_EMIT_SYMBOL, 143),
    (9, HUFFMAN_EMIT_SYMBOL, 143),
    (23, HUFFMAN_EMIT_SYMBOL, 143),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 143),

    # Node 151
    (3, HUFFMAN_EMIT_SYMBOL, 139),
    (6, HUFFMAN_EMIT_SYMBOL, 139),
    (10, HUFFMAN_EMIT_SYMBOL, 139),
    (15, HUFFMAN_EMIT_SYMBOL, 139),
    (24, HUFFMAN_EMIT_SYMBOL, 139),
    (31, HUFFMAN_EMIT_SYMBOL, 139),
    (41, HUFFMAN_EMIT_SYMBOL, 139),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 139),
    (3, HUFFMAN_EMIT_SYMBOL, 140),
    (6, HUFFMAN_EMIT_SYMBOL, 140),
    (10, HUFFMAN_EMIT_SYMBOL, 140),
    (15, HUFFMAN_EMIT_SYMBOL, 140),
    (24, HUFFMAN_EMIT_SYMBOL, 140),
    (31, HUFFMAN_EMIT_SYMBOL, 140),
    (41, HUFFMAN_EMIT_SYMBOL, 140),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 140),

    # Node 152
    (3, HUFFMAN_EMIT_SYMBOL, 141),
    (6, HUFFMAN_EMIT_SYMBOL, 141),
    (10, HUFFMAN_EMIT_SYMBOL, 141),
    (15, HUFFMAN_EMIT_SYMBOL, 141),
    (24, HUFFMAN_EMIT_SYMBOL, 141),
    (31, HUFFMAN_EMIT_SYMBOL, 141),
    (41, HUFFMAN_EMIT_SYMBOL, 141),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 141),
    (3, HUFFMAN_EMIT_SYMBOL, 143),
    (6, HUFFMAN_EMIT_SYMBOL, 143),
    (10, HUFFMAN_EMIT_SYMBOL, 143),
    (15, HUFFMAN_EMIT_SYMBOL, 143),
    (24, HUFFMAN_EMIT_SYMBOL, 143),
    (31, HUFFMAN_EMIT_SYMBOL, 143),
    (41, HUFFMAN_EMIT_SYMBOL, 143),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 143),

    # Node 153
    (157, 0, 0),
    (158, 0, 0),
    (160, 0, 0),
    (161, 0, 0),
    (164, 0, 0),
    (165, 0, 0),
    (167, 0, 0),
    (168, 0, 0),
    (172, 0, 0),
    (173, 0, 0),
    (175, 0, 0),
    (177, 0, 0),
    (182, 0, 0),
    (185, 0, 0),
    (191, 0, 0),
    (207, 0, 0),

    # Node 154
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 147),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 149),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 150),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 151),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 152),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 155),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 157),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 158),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 165),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 166),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 168),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 174),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 175),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 180),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 182),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 183),

    # Node 155
    (1, HUFFMAN_EMIT_SYMBOL, 147),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 147),
    (1, HUFFMAN_EMIT_SYMBOL, 149),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 149),
    (1, HUFFMAN_EMIT_SYMBOL, 150),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 150),
    (1, HUFFMAN_EMIT_SYMBOL, 151),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 151),
    (1, HUFFMAN_EMIT_SYMBOL, 152),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 152),
    (1, HUFFMAN_EMIT_SYMBOL, 155),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 155),
    (1, HUFFMAN_EMIT_SYMBOL, 157),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 157),
    (1, HUFFMAN_EMIT_SYMBOL, 158),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 158),

    # Node 156
    (2, HUFFMAN_EMIT_SYMBOL, 147),
    (9, HUFFMAN_EMIT_SYMBOL, 147),
    (23, HUFFMAN_EMIT_SYMBOL, 147),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 147),
    (2, HUFFMAN_EMIT_SYMBOL, 149),
    (9, HUFFMAN_EMIT_SYMBOL, 149),
    (23, HUFFMAN_EMIT_SYMBOL, 149),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 149),
    (2, HUFFMAN_EMIT_SYMBOL, 150),
    (9, HUFFMAN_EMIT_SYMBOL, 150),
    (23, HUFFMAN_EMIT_SYMBOL, 150),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 150),
    (2, HUFFMAN_EMIT_SYMBOL, 151),
    (9, HUFFMAN_EMIT_SYMBOL, 151),
    (23, HUFFMAN_EMIT_SYMBOL, 151),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 151),

    # Node 157
    (3, HUFFMAN_EMIT_SYMBOL, 147),
    (6, HUFFMAN_EMIT_SYMBOL, 147),
    (10, HUFFMAN_EMIT_SYMBOL, 147),
    (15, HUFFMAN_EMIT_SYMBOL, 147),
    (24, HUFFMAN_EMIT_SYMBOL, 147),
    (31, HUFFMAN_EMIT_SYMBOL, 147),
    (41, HUFFMAN_EMIT_SYMBOL, 147),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 147),
    (3, HUFFMAN_EMIT_SYMBOL, 149),
    (6, HUFFMAN_EMIT_SYMBOL, 149),
    (10, HUFFMAN_EMIT_SYMBOL, 149),
    (15, HUFFMAN_EMIT_SYMBOL, 149),
    (24, HUFFMAN_EMIT_SYMBOL, 149),
    (31, HUFFMAN_EMIT_SYMBOL, 149),
    (41, HUFFMAN_EMIT_SYMBOL, 149),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 149),

    # Node 158
    (3, HUFFMAN_EMIT_SYMBOL, 150),
    (6, HUFFMAN_EMIT_SYMBOL, 150),
    (10, HUFFMAN_EMIT_SYMBOL, 150),
    (15, HUFFMAN_EMIT_SYMBOL, 150),
    (24, HUFFMAN_EMIT_SYMBOL, 150),
    (31, HUFFMAN_EMIT_SYMBOL, 150),
    (41, HUFFMAN_EMIT_SYMBOL, 150),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 150),
    (3, HUFFMAN_EMIT_SYMBOL, 151),
    (6, HUFFMAN_EMIT_SYMBOL, 151),
    (10, HUFFMAN_EMIT_SYMBOL, 151),
    (15, HUFFMAN_EMIT_SYMBOL, 151),
    (24, HUFFMAN_EMIT_SYMBOL, 151),
    (31, HUFFMAN_EMIT_SYMBOL, 151),
    (41, HUFFMAN_EMIT_SYMBOL, 151),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 151),

    # Node 159
    (2, HUFFMAN_EMIT_SYMBOL, 152),
    (9, HUFFMAN_EMIT_SYMBOL, 152),
    (23, HUFFMAN_EMIT_SYMBOL, 152),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 152),
    (2, HUFFMAN_EMIT_SYMBOL, 155),
    (9, HUFFMAN_EMIT_SYMBOL, 155),
    (23, HUFFMAN_EMIT_SYMBOL, 155),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 155),
    (2, HUFFMAN_EMIT_SYMBOL, 157),
    (9, HUFFMAN_EMIT_SYMBOL, 157),
    (23, HUFFMAN_EMIT_SYMBOL, 157),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 157),
    (2, HUFFMAN_EMIT_SYMBOL, 158),
    (9, HUFFMAN_EMIT_SYMBOL, 158),
    (23, HUFFMAN_EMIT_SYMBOL, 158),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 158),

    # Node 160
    (3, HUFFMAN_EMIT_SYMBOL, 152),
    (6, HUFFMAN_EMIT_SYMBOL, 152),
    (10, HUFFMAN_EMIT_SYMBOL, 152),
    (15, HUFFMAN_EMIT_SYMBOL, 152),
    (24, HUFFMAN_EMIT_SYMBOL, 152),
    (31, HUFFMAN_EMIT_SYMBOL, 152),
    (41, HUFFMAN_EMIT_SYMBOL, 152),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 152),
    (3, HUFFMAN_EMIT_SYMBOL, 155),
    (6, HUFFMAN_EMIT_SYMBOL, 155),
    (10, HUFFMAN_EMIT_SYMBOL, 155),
    (15, HUFFMAN_EMIT_SYMBOL, 155),
    (24, HUFFMAN_EMIT_SYMBOL, 155),
    (31, HUFFMAN_EMIT_SYMBOL, 155),
    (41, HUFFMAN_EMIT_SYMBOL, 155),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 155),

    # Node 161
    (3, HUFFMAN_EMIT_SYMBOL, 157),
    (6, HUFFMAN_EMIT_SYMBOL, 157),
    (10, HUFFMAN_EMIT_SYMBOL, 157),
    (15, HUFFMAN_EMIT_SYMBOL, 157),
    (24, HUFFMAN_EMIT_SYMBOL, 157),
    (31, HUFFMAN_EMIT_SYMBOL, 157),
    (41, HUFFMAN_EMIT_SYMBOL, 157),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 157),
    (3, HUFFMAN_EMIT_SYMBOL, 158),
    (6, HUFFMAN_EMIT_SYMBOL, 158),
    (10, HUFFMAN_EMIT_SYMBOL, 158),
    (15, HUFFMAN_EMIT_SYMBOL, 158),
    (24, HUFFMAN_EMIT_SYMBOL, 158),
    (31, HUFFMAN_EMIT_SYMBOL, 158),
    (41, HUFFMAN_EMIT_SYMBOL, 158),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 158),

    # Node 162
    (1, HUFFMAN_EMIT_SYMBOL, 165),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 165),
    (1, HUFFMAN_EMIT_SYMBOL, 166),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 166),
    (1, HUFFMAN_EMIT_SYMBOL, 168),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 168),
    (1, HUFFMAN_EMIT_SYMBOL, 174),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 174),
    (1, HUFFMAN_EMIT_SYMBOL, 175),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 175),
    (1, HUFFMAN_EMIT_SYMBOL, 180),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 180),
    (1, HUFFMAN_EMIT_SYMBOL, 182),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 182),
    (1, HUFFMAN_EMIT_SYMBOL, 183),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 183),

    # Node 163
    (2, HUFFMAN_EMIT_SYMBOL, 165),
    (9, HUFFMAN_EMIT_SYMBOL, 165),
    (23, HUFFMAN_EMIT_SYMBOL, 165),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 165),
    (2, HUFFMAN_EMIT_SYMBOL, 166),
    (9, HUFFMAN_EMIT_SYMBOL, 166),
    (23, HUFFMAN_EMIT_SYMBOL, 166),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 166),
    (2, HUFFMAN_EMIT_SYMBOL, 168),
    (9, HUFFMAN_EMIT_SYMBOL, 168),
    (23, HUFFMAN_EMIT_SYMBOL, 168),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 168),
    (2, HUFFMAN_EMIT_SYMBOL, 174),
    (9, HUFFMAN_EMIT_SYMBOL, 174),
    (23, HUFFMAN_EMIT_SYMBOL, 174),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 174),

    # Node 164
    (3, HUFFMAN_EMIT_SYMBOL, 165),
    (6, HUFFMAN_EMIT_SYMBOL, 165),
    (10, HUFFMAN_EMIT_SYMBOL, 165),
    (15, HUFFMAN_EMIT_SYMBOL, 165),
    (24, HUFFMAN_EMIT_SYMBOL, 165),
    (31, HUFFMAN_EMIT_SYMBOL, 165),
    (41, HUFFMAN_EMIT_SYMBOL, 165),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 165),
    (3, HUFFMAN_EMIT_SYMBOL, 166),
    (6, HUFFMAN_EMIT_SYMBOL, 166),
    (10, HUFFMAN_EMIT_SYMBOL, 166),
    (15, HUFFMAN_EMIT_SYMBOL, 166),
    (24, HUFFMAN_EMIT_SYMBOL, 166),
    (31, HUFFMAN_EMIT_SYMBOL, 166),
    (41, HUFFMAN_EMIT_SYMBOL, 166),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 166),

    # Node 165
    (3, HUFFMAN_EMIT_SYMBOL, 168),
    (6, HUFFMAN_EMIT_SYMBOL, 168),
    (10, HUFFMAN_EMIT_SYMBOL, 168),
    (15, HUFFMAN_EMIT_SYMBOL, 168),
    (24, HUFFMAN_EMIT_SYMBOL, 168),
    (31, HUFFMAN_EMIT_SYMBOL, 168),
    (41, HUFFMAN_EMIT_SYMBOL, 168),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 168),
    (3, HUFFMAN_EMIT_SYMBOL, 174),
    (6, HUFFMAN_EMIT_SYMBOL, 174),
    (10, HUFFMAN_EMIT_SYMBOL, 174),
    (15, HUFFMAN_EMIT_SYMBOL, 174),
    (24, HUFFMAN_EMIT_SYMBOL, 174),
    (31, HUFFMAN_EMIT_SYMBOL, 174),
    (41, HUFFMAN_EMIT_SYMBOL, 174),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 174),

    # Node 166
    (2, HUFFMAN_EMIT_SYMBOL, 175),
    (9, HUFFMAN_EMIT_SYMBOL, 175),
    (23, HUFFMAN_EMIT_SYMBOL, 175),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 175),
    (2, HUFFMAN_EMIT_SYMBOL, 180),
    (9, HUFFMAN_EMIT_SYMBOL, 180),
    (23, HUFFMAN_EMIT_SYMBOL, 180),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 180),
    (2, HUFFMAN_EMIT_SYMBOL, 182),
    (9, HUFFMAN_EMIT_SYMBOL, 182),
    (23, HUFFMAN_EMIT_SYMBOL, 182),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 182),
    (2, HUFFMAN_EMIT_SYMBOL, 183),
    (9, HUFFMAN_EMIT_SYMBOL, 183),
    (23, HUFFMAN_EMIT_SYMBOL, 183),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 183),

    # Node 167
    (3, HUFFMAN_EMIT_SYMBOL, 175),
    (6, HUFFMAN_EMIT_SYMBOL, 175),
    (10, HUFFMAN_EMIT_SYMBOL, 175),
    (15, HUFFMAN_EMIT_SYMBOL, 175),
    (24, HUFFMAN_EMIT_SYMBOL, 175),
    (31, HUFFMAN_EMIT_SYMBOL, 175),
    (41, HUFFMAN_EMIT_SYMBOL, 175),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 175),
    (3, HUFFMAN_EMIT_SYMBOL, 180),
    (6, HUFFMAN_EMIT_SYMBOL, 180),
    (10, HUFFMAN_EMIT_SYMBOL, 180),
    (15, HUFFMAN_EMIT_SYMBOL, 180),
    (24, HUFFMAN_EMIT_SYMBOL, 180),
    (31, HUFFMAN_EMIT_SYMBOL, 180),
    (41, HUFFMAN_EMIT_SYMBOL, 180),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 180),

    # Node 168
    (3, HUFFMAN_EMIT_SYMBOL, 182),
    (6, HUFFMAN_EMIT_SYMBOL, 182),
    (10, HUFFMAN_EMIT_SYMBOL, 182),
    (15, HUFFMAN_EMIT_SYMBOL, 182),
    (24, HUFFMAN_EMIT_SYMBOL, 182),
    (31, HUFFMAN_EMIT_SYMBOL, 182),
    (41, HUFFMAN_EMIT_SYMBOL, 182),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 182),
    (3, HUFFMAN_EMIT_SYMBOL, 183),
    (6, HUFFMAN_EMIT_SYMBOL, 183),
    (10, HUFFMAN_EMIT_SYMBOL, 183),
    (15, HUFFMAN_EMIT_SYMBOL, 183),
    (24, HUFFMAN_EMIT_SYMBOL, 183),
    (31, HUFFMAN_EMIT_SYMBOL, 183),
    (41, HUFFMAN_EMIT_SYMBOL, 183),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 183),

    # Node 169
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 188),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 191),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 197),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 231),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 239),
    (176, 0, 0),
    (178, 0, 0),
    (179, 0, 0),
    (183, 0, 0),
    (184, 0, 0),
    (186, 0, 0),
    (187, 0, 0),
    (192, 0, 0),
    (199, 0, 0),
    (208, 0, 0),
    (223, 0, 0),

    # Node 170
    (1, HUFFMAN_EMIT_SYMBOL, 188),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 188),
    (1, HUFFMAN_EMIT_SYMBOL, 191),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 191),
    (1, HUFFMAN_EMIT_SYMBOL, 197),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 197),
    (1, HUFFMAN_EMIT_SYMBOL, 231),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 231),
    (1, HUFFMAN_EMIT_SYMBOL, 239),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 239),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 9),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 142),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 144),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 145),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 148),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 159),

    # Node 171
    (2, HUFFMAN_EMIT_SYMBOL, 188),
    (9, HUFFMAN_EMIT_SYMBOL, 188),
    (23, HUFFMAN_EMIT_SYMBOL, 188),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 188),
    (2, HUFFMAN_EMIT_SYMBOL, 191),
    (9, HUFFMAN_EMIT_SYMBOL, 191),
    (23, HUFFMAN_EMIT_SYMBOL, 191),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 191),
    (2, HUFFMAN_EMIT_SYMBOL, 197),
    (9, HUFFMAN_EMIT_SYMBOL, 197),
    (23, HUFFMAN_EMIT_SYMBOL, 197),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 197),
    (2, HUFFMAN_EMIT_SYMBOL, 231),
    (9, HUFFMAN_EMIT_SYMBOL, 231),
    (23, HUFFMAN_EMIT_SYMBOL, 231),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 231),

    # Node 172
    (3, HUFFMAN_EMIT_SYMBOL, 188),
    (6, HUFFMAN_EMIT_SYMBOL, 188),
    (10, HUFFMAN_EMIT_SYMBOL, 188),
    (15, HUFFMAN_EMIT_SYMBOL, 188),
    (24, HUFFMAN_EMIT_SYMBOL, 188),
    (31, HUFFMAN_EMIT_SYMBOL, 188),
    (41, HUFFMAN_EMIT_SYMBOL, 188),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 188),
    (3, HUFFMAN_EMIT_SYMBOL, 191),
    (6, HUFFMAN_EMIT_SYMBOL, 191),
    (10, HUFFMAN_EMIT_SYMBOL, 191),
    (15, HUFFMAN_EMIT_SYMBOL, 191),
    (24, HUFFMAN_EMIT_SYMBOL, 191),
    (31, HUFFMAN_EMIT_SYMBOL, 191),
    (41, HUFFMAN_EMIT_SYMBOL, 191),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 191),

    # Node 173
    (3, HUFFMAN_EMIT_SYMBOL, 197),
    (6, HUFFMAN_EMIT_SYMBOL, 197),
    (10, HUFFMAN_EMIT_SYMBOL, 197),
    (15, HUFFMAN_EMIT_SYMBOL, 197),
    (24, HUFFMAN_EMIT_SYMBOL, 197),
    (31, HUFFMAN_EMIT_SYMBOL, 197),
    (41, HUFFMAN_EMIT_SYMBOL, 197),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 197),
    (3, HUFFMAN_EMIT_SYMBOL, 231),
    (6, HUFFMAN_EMIT_SYMBOL, 231),
    (10, HUFFMAN_EMIT_SYMBOL, 231),
    (15, HUFFMAN_EMIT_SYMBOL, 231),
    (24, HUFFMAN_EMIT_SYMBOL, 231),
    (31, HUFFMAN_EMIT_SYMBOL, 231),
    (41, HUFFMAN_EMIT_SYMBOL, 231),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 231),

    # Node 174
    (2, HUFFMAN_EMIT_SYMBOL, 239),
    (9, HUFFMAN_EMIT_SYMBOL, 239),
    (23, HUFFMAN_EMIT_SYMBOL, 239),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 239),
    (1, HUFFMAN_EMIT_SYMBOL, 9),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 9),
    (1, HUFFMAN_EMIT_SYMBOL, 142),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 142),
    (1, HUFFMAN_EMIT_SYMBOL, 144),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 144),
    (1, HUFFMAN_EMIT_SYMBOL, 145),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 145),
    (1, HUFFMAN_EMIT_SYMBOL, 148),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 148),
    (1, HUFFMAN_EMIT_SYMBOL, 159),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 159),

    # Node 175
    (3, HUFFMAN_EMIT_SYMBOL, 239),
    (6, HUFFMAN_EMIT_SYMBOL, 239),
    (10, HUFFMAN_EMIT_SYMBOL, 239),
    (15, HUFFMAN_EMIT_SYMBOL, 239),
    (24, HUFFMAN_EMIT_SYMBOL, 239),
    (31, HUFFMAN_EMIT_SYMBOL, 239),
    (41, HUFFMAN_EMIT_SYMBOL, 239),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 239),
    (2, HUFFMAN_EMIT_SYMBOL, 9),
    (9, HUFFMAN_EMIT_SYMBOL, 9),
    (23, HUFFMAN_EMIT_SYMBOL, 9),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 9),
    (2, HUFFMAN_EMIT_SYMBOL, 142),
    (9, HUFFMAN_EMIT_SYMBOL, 142),
    (23, HUFFMAN_EMIT_SYMBOL, 142),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 142),

    # Node 176
    (3, HUFFMAN_EMIT_SYMBOL, 9),
    (6, HUFFMAN_EMIT_SYMBOL, 9),
    (10, HUFFMAN_EMIT_SYMBOL, 9),
    (15, HUFFMAN_EMIT_SYMBOL, 9),
    (24, HUFFMAN_EMIT_SYMBOL, 9),
    (31, HUFFMAN_EMIT_SYMBOL, 9),
    (41, HUFFMAN_EMIT_SYMBOL, 9),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 9),
    (3, HUFFMAN_EMIT_SYMBOL, 142),
    (6, HUFFMAN_EMIT_SYMBOL, 142),
    (10, HUFFMAN_EMIT_SYMBOL, 142),
    (15, HUFFMAN_EMIT_SYMBOL, 142),
    (24, HUFFMAN_EMIT_SYMBOL, 142),
    (31, HUFFMAN_EMIT_SYMBOL, 142),
    (41, HUFFMAN_EMIT_SYMBOL, 142),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 142),

    # Node 177
    (2, HUFFMAN_EMIT_SYMBOL, 144),
    (9, HUFFMAN_EMIT_SYMBOL, 144),
    (23, HUFFMAN_EMIT_SYMBOL, 144),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 144),
    (2, HUFFMAN_EMIT_SYMBOL, 145),
    (9, HUFFMAN_EMIT_SYMBOL, 145),
    (23, HUFFMAN_EMIT_SYMBOL, 145),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 145),
    (2, HUFFMAN_EMIT_SYMBOL, 148),
    (9, HUFFMAN_EMIT_SYMBOL, 148),
    (23, HUFFMAN_EMIT_SYMBOL, 148),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 148),
    (2, HUFFMAN_EMIT_SYMBOL, 159),
    (9, HUFFMAN_EMIT_SYMBOL, 159),
    (23, HUFFMAN_EMIT_SYMBOL, 159),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 159),

    # Node 178
    (3, HUFFMAN_EMIT_SYMBOL, 144),
    (6, HUFFMAN_EMIT_SYMBOL, 144),
    (10, HUFFMAN_EMIT_SYMBOL, 144),
    (15, HUFFMAN_EMIT_SYMBOL, 144),
    (24, HUFFMAN_EMIT_SYMBOL, 144),
    (31, HUFFMAN_EMIT_SYMBOL, 144),
    (41, HUFFMAN_EMIT_SYMBOL, 144),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 144),
    (3, HUFFMAN_EMIT_SYMBOL, 145),
    (6, HUFFMAN_EMIT_SYMBOL, 145),
    (10, HUFFMAN_EMIT_SYMBOL, 145),
    (15, HUFFMAN_EMIT_SYMBOL, 145),
    (24, HUFFMAN_EMIT_SYMBOL, 145),
    (31, HUFFMAN_EMIT_SYMBOL, 145),
    (41, HUFFMAN_EMIT_SYMBOL, 145),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 145),

    # Node 179
    (3, HUFFMAN_EMIT_SYMBOL, 148),
    (6, HUFFMAN_EMIT_SYMBOL, 148),
    (10, HUFFMAN_EMIT_SYMBOL, 148),
    (15, HUFFMAN_EMIT_SYMBOL, 148),
    (24, HUFFMAN_EMIT_SYMBOL, 148),
    (31, HUFFMAN_EMIT_SYMBOL, 148),
    (41, HUFFMAN_EMIT_SYMBOL, 148),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 148),
    (3, HUFFMAN_EMIT_SYMBOL, 159),
    (6, HUFFMAN_EMIT_SYMBOL, 159),
    (10, HUFFMAN_EMIT_SYMBOL, 159),
    (15, HUFFMAN_EMIT_SYMBOL, 159),
    (24, HUFFMAN_EMIT_SYMBOL, 159),
    (31, HUFFMAN_EMIT_SYMBOL, 159),
    (41, HUFFMAN_EMIT_SYMBOL, 159),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 159),

    # Node 180
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 171),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 206),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 215),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 225),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 236),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 237),
    (188, 0, 0),
    (189, 0, 0),
    (193, 0, 0),
    (196, 0, 0),
    (200, 0, 0),
    (203, 0, 0),
    (209, 0, 0),
    (216, 0, 0),
    (224, 0, 0),
    (238, 0, 0),

    # Node 181
    (1, HUFFMAN_EMIT_SYMBOL, 171),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 171),
    (1, HUFFMAN_EMIT_SYMBOL, 206),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 206),
    (1, HUFFMAN_EMIT_SYMBOL, 215),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 215),
    (1, HUFFMAN_EMIT_SYMBOL, 225),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 225),
    (1, HUFFMAN_EMIT_SYMBOL, 236),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 236),
    (1, HUFFMAN_EMIT_SYMBOL, 237),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 237),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 199),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 207),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 234),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 235),

    # Node 182
    (2, HUFFMAN_EMIT_SYMBOL, 171),
    (9, HUFFMAN_EMIT_SYMBOL, 171),
    (23, HUFFMAN_EMIT_SYMBOL, 171),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 171),
    (2, HUFFMAN_EMIT_SYMBOL, 206),
    (9, HUFFMAN_EMIT_SYMBOL, 206),
    (23, HUFFMAN_EMIT_SYMBOL, 206),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 206),
    (2, HUFFMAN_EMIT_SYMBOL, 215),
    (9, HUFFMAN_EMIT_SYMBOL, 215),
    (23, HUFFMAN_EMIT_SYMBOL, 215),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 215),
    (2, HUFFMAN_EMIT_SYMBOL, 225),
    (9, HUFFMAN_EMIT_SYMBOL, 225),
    (23, HUFFMAN_EMIT_SYMBOL, 225),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 225),

    # Node 183
    (3, HUFFMAN_EMIT_SYMBOL, 171),
    (6, HUFFMAN_EMIT_SYMBOL, 171),
    (10, HUFFMAN_EMIT_SYMBOL, 171),
    (15, HUFFMAN_EMIT_SYMBOL, 171),
    (24, HUFFMAN_EMIT_SYMBOL, 171),
    (31, HUFFMAN_EMIT_SYMBOL, 171),
    (41, HUFFMAN_EMIT_SYMBOL, 171),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 171),
    (3, HUFFMAN_EMIT_SYMBOL, 206),
    (6, HUFFMAN_EMIT_SYMBOL, 206),
    (10, HUFFMAN_EMIT_SYMBOL, 206),
    (15, HUFFMAN_EMIT_SYMBOL, 206),
    (24, HUFFMAN_EMIT_SYMBOL, 206),
    (31, HUFFMAN_EMIT_SYMBOL, 206),
    (41, HUFFMAN_EMIT_SYMBOL, 206),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 206),

    # Node 184
    (3, HUFFMAN_EMIT_SYMBOL, 215),
    (6, HUFFMAN_EMIT_SYMBOL, 215),
    (10, HUFFMAN_EMIT_SYMBOL, 215),
    (15, HUFFMAN_EMIT_SYMBOL, 215),
    (24, HUFFMAN_EMIT_SYMBOL, 215),
    (31, HUFFMAN_EMIT_SYMBOL, 215),
    (41, HUFFMAN_EMIT_SYMBOL, 215),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 215),
    (3, HUFFMAN_EMIT_SYMBOL, 225),
    (6, HUFFMAN_EMIT_SYMBOL, 225),
    (10, HUFFMAN_EMIT_SYMBOL, 225),
    (15, HUFFMAN_EMIT_SYMBOL, 225),
    (24, HUFFMAN_EMIT_SYMBOL, 225),
    (31, HUFFMAN_EMIT_SYMBOL, 225),
    (41, HUFFMAN_EMIT_SYMBOL, 225),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 225),

    # Node 185
    (2, HUFFMAN_EMIT_SYMBOL, 236),
    (9, HUFFMAN_EMIT_SYMBOL, 236),
    (23, HUFFMAN_EMIT_SYMBOL, 236),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 236),
    (2, HUFFMAN_EMIT_SYMBOL, 237),
    (9, HUFFMAN_EMIT_SYMBOL, 237),
    (23, HUFFMAN_EMIT_SYMBOL, 237),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 237),
    (1, HUFFMAN_EMIT_SYMBOL, 199),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 199),
    (1, HUFFMAN_EMIT_SYMBOL, 207),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 207),
    (1, HUFFMAN_EMIT_SYMBOL, 234),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 234),
    (1, HUFFMAN_EMIT_SYMBOL, 235),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 235),

    # Node 186
    (3, HUFFMAN_EMIT_SYMBOL, 236),
    (6, HUFFMAN_EMIT_SYMBOL, 236),
    (10, HUFFMAN_EMIT_SYMBOL, 236),
    (15, HUFFMAN_EMIT_SYMBOL, 236),
    (24, HUFFMAN_EMIT_SYMBOL, 236),
    (31, HUFFMAN_EMIT_SYMBOL, 236),
    (41, HUFFMAN_EMIT_SYMBOL, 236),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 236),
    (3, HUFFMAN_EMIT_SYMBOL, 237),
    (6, HUFFMAN_EMIT_SYMBOL, 237),
    (10, HUFFMAN_EMIT_SYMBOL, 237),
    (15, HUFFMAN_EMIT_SYMBOL, 237),
    (24, HUFFMAN_EMIT_SYMBOL, 237),
    (31, HUFFMAN_EMIT_SYMBOL, 237),
    (41, HUFFMAN_EMIT_SYMBOL, 237),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 237),

    # Node 187
    (2, HUFFMAN_EMIT_SYMBOL, 199),
    (9, HUFFMAN_EMIT_SYMBOL, 199),
    (23, HUFFMAN_EMIT_SYMBOL, 199),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 199),
    (2, HUFFMAN_EMIT_SYMBOL, 207),
    (9, HUFFMAN_EMIT_SYMBOL, 207),
    (23, HUFFMAN_EMIT_SYMBOL, 207),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 207),
    (2, HUFFMAN_EMIT_SYMBOL, 234),
    (9, HUFFMAN_EMIT_SYMBOL, 234),
    (23, HUFFMAN_EMIT_SYMBOL, 234),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 234),
    (2, HUFFMAN_EMIT_SYMBOL, 235),
    (9, HUFFMAN_EMIT_SYMBOL, 235),
    (23, HUFFMAN_EMIT_SYMBOL, 235),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 235),

    # Node 188
    (3, HUFFMAN_EMIT_SYMBOL, 199),
    (6, HUFFMAN_EMIT_SYMBOL, 199),
    (10, HUFFMAN_EMIT_SYMBOL, 199),
    (15, HUFFMAN_EMIT_SYMBOL, 199),
    (24, HUFFMAN_EMIT_SYMBOL, 199),
    (31, HUFFMAN_EMIT_SYMBOL, 199),
    (41, HUFFMAN_EMIT_SYMBOL, 199),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 199),
    (3, HUFFMAN_EMIT_SYMBOL, 207),
    (6, HUFFMAN_EMIT_SYMBOL, 207),
    (10, HUFFMAN_EMIT_SYMBOL, 207),
    (15, HUFFMAN_EMIT_SYMBOL, 207),
    (24, HUFFMAN_EMIT_SYMBOL, 207),
    (31, HUFFMAN_EMIT_SYMBOL, 207),
    (41, HUFFMAN_EMIT_SYMBOL, 207),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 207),

    # Node 189
    (3, HUFFMAN_EMIT_SYMBOL, 234),
    (6, HUFFMAN_EMIT_SYMBOL, 234),
    (10, HUFFMAN_EMIT_SYMBOL, 234),
    (15, HUFFMAN_EMIT_SYMBOL, 234),
    (24, HUFFMAN_EMIT_SYMBOL, 234),
    (31, HUFFMAN_EMIT_SYMBOL, 234),
    (41, HUFFMAN_EMIT_SYMBOL, 234),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 234),
    (3, HUFFMAN_EMIT_SYMBOL, 235),
    (6, HUFFMAN_EMIT_SYMBOL, 235),
    (10, HUFFMAN_EMIT_SYMBOL, 235),
    (15, HUFFMAN_EMIT_SYMBOL, 235),
    (24, HUFFMAN_EMIT_SYMBOL, 235),
    (31, HUFFMAN_EMIT_SYMBOL, 235),
    (41, HUFFMAN_EMIT_SYMBOL, 235),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 235),

    # Node 190
    (194, 0, 0),
    (195, 0, 0),
    (197, 0, 0),
    (198, 0, 0),
    (201, 0, 0),
    (202, 0, 0),
    (204, 0, 0),
    (205, 0, 0),
    (210, 0, 0),
    (213, 0, 0),
    (217, 0, 0),
    (220, 0, 0),
    (225, 0, 0),
    (231, 0, 0),
    (239, 0, 0),
    (246, 0, 0),

    # Node 191
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 192),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 193),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 200),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 201),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 202),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 205),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 210),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 213),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 218),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 219),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 238),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 240),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 242),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 243),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 255),
    (206, 0, 0),

    # Node 192
    (1, HUFFMAN_EMIT_SYMBOL, 192),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 192),
    (1, HUFFMAN_EMIT_SYMBOL, 193),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 193),
    (1, HUFFMAN_EMIT_SYMBOL, 200),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 200),
    (1, HUFFMAN_EMIT_SYMBOL, 201),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 201),
    (1, HUFFMAN_EMIT_SYMBOL, 202),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 202),
    (1, HUFFMAN_EMIT_SYMBOL, 205),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 205),
    (1, HUFFMAN_EMIT_SYMBOL, 210),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 210),
    (1, HUFFMAN_EMIT_SYMBOL, 213),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 213),

    # Node 193
    (2, HUFFMAN_EMIT_SYMBOL, 192),
    (9, HUFFMAN_EMIT_SYMBOL, 192),
    (23, HUFFMAN_EMIT_SYMBOL, 192),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 192),
    (2, HUFFMAN_EMIT_SYMBOL, 193),
    (9, HUFFMAN_EMIT_SYMBOL, 193),
    (23, HUFFMAN_EMIT_SYMBOL, 193),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 193),
    (2, HUFFMAN_EMIT_SYMBOL, 200),
    (9, HUFFMAN_EMIT_SYMBOL, 200),
    (23, HUFFMAN_EMIT_SYMBOL, 200),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 200),
    (2, HUFFMAN_EMIT_SYMBOL, 201),
    (9, HUFFMAN_EMIT_SYMBOL, 201),
    (23, HUFFMAN_EMIT_SYMBOL, 201),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 201),

    # Node 194
    (3, HUFFMAN_EMIT_SYMBOL, 192),
    (6, HUFFMAN_EMIT_SYMBOL, 192),
    (10, HUFFMAN_EMIT_SYMBOL, 192),
    (15, HUFFMAN_EMIT_SYMBOL, 192),
    (24, HUFFMAN_EMIT_SYMBOL, 192),
    (31, HUFFMAN_EMIT_SYMBOL, 192),
    (41, HUFFMAN_EMIT_SYMBOL, 192),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 192),
    (3, HUFFMAN_EMIT_SYMBOL, 193),
    (6, HUFFMAN_EMIT_SYMBOL, 193),
    (10, HUFFMAN_EMIT_SYMBOL, 193),
    (15, HUFFMAN_EMIT_SYMBOL, 193),
    (24, HUFFMAN_EMIT_SYMBOL, 193),
    (31, HUFFMAN_EMIT_SYMBOL, 193),
    (41, HUFFMAN_EMIT_SYMBOL, 193),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 193),

    # Node 195
    (3, HUFFMAN_EMIT_SYMBOL, 200),
    (6, HUFFMAN_EMIT_SYMBOL, 200),
    (10, HUFFMAN_EMIT_SYMBOL, 200),
    (15, HUFFMAN_EMIT_SYMBOL, 200),
    (24, HUFFMAN_EMIT_SYMBOL, 200),
    (31, HUFFMAN_EMIT_SYMBOL, 200),
    (41, HUFFMAN_EMIT_SYMBOL, 200),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 200),
    (3, HUFFMAN_EMIT_SYMBOL, 201),
    (6, HUFFMAN_EMIT_SYMBOL, 201),
    (10, HUFFMAN_EMIT_SYMBOL, 201),
    (15, HUFFMAN_EMIT_SYMBOL, 201),
    (24, HUFFMAN_EMIT_SYMBOL, 201),
    (31, HUFFMAN_EMIT_SYMBOL, 201),
    (41, HUFFMAN_EMIT_SYMBOL, 201),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 201),

    # Node 196
    (2, HUFFMAN_EMIT_SYMBOL, 202),
    (9, HUFFMAN_EMIT_SYMBOL, 202),
    (23, HUFFMAN_EMIT_SYMBOL, 202),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 202),
    (2, HUFFMAN_EMIT_SYMBOL, 205),
    (9, HUFFMAN_EMIT_SYMBOL, 205),
    (23, HUFFMAN_EMIT_SYMBOL, 205),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 205),
    (2, HUFFMAN_EMIT_SYMBOL, 210),
    (9, HUFFMAN_EMIT_SYMBOL, 210),
    (23, HUFFMAN_EMIT_SYMBOL, 210),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 210),
    (2, HUFFMAN_EMIT_SYMBOL, 213),
    (9, HUFFMAN_EMIT_SYMBOL, 213),
    (23, HUFFMAN_EMIT_SYMBOL, 213),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 213),

    # Node 197
    (3, HUFFMAN_EMIT_SYMBOL, 202),
    (6, HUFFMAN_EMIT_SYMBOL, 202),
    (10, HUFFMAN_EMIT_SYMBOL, 202),
    (15, HUFFMAN_EMIT_SYMBOL, 202),
    (24, HUFFMAN_EMIT_SYMBOL, 202),
    (31, HUFFMAN_EMIT_SYMBOL, 202),
    (41, HUFFMAN_EMIT_SYMBOL, 202),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 202),
    (3, HUFFMAN_EMIT_SYMBOL, 205),
    (6, HUFFMAN_EMIT_SYMBOL, 205),
    (10, HUFFMAN_EMIT_SYMBOL, 205),
    (15, HUFFMAN_EMIT_SYMBOL, 205),
    (24, HUFFMAN_EMIT_SYMBOL, 205),
    (31, HUFFMAN_EMIT_SYMBOL, 205),
    (41, HUFFMAN_EMIT_SYMBOL, 205),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 205),

    # Node 198
    (3, HUFFMAN_EMIT_SYMBOL, 210),
    (6, HUFFMAN_EMIT_SYMBOL, 210),
    (10, HUFFMAN_EMIT_SYMBOL, 210),
    (15, HUFFMAN_EMIT_SYMBOL, 210),
    (24, HUFFMAN_EMIT_SYMBOL, 210),
    (31, HUFFMAN_EMIT_SYMBOL, 210),
    (41, HUFFMAN_EMIT_SYMBOL, 210),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 210),
    (3, HUFFMAN_EMIT_SYMBOL, 213),
    (6, HUFFMAN_EMIT_SYMBOL, 213),
    (10, HUFFMAN_EMIT_SYMBOL, 213),
    (15, HUFFMAN_EMIT_SYMBOL, 213),
    (24, HUFFMAN_EMIT_SYMBOL, 213),
    (31, HUFFMAN_EMIT_SYMBOL, 213),
    (41, HUFFMAN_EMIT_SYMBOL, 213),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 213),

    # Node 199
    (1, HUFFMAN_EMIT_SYMBOL, 218),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 218),
    (1, HUFFMAN_EMIT_SYMBOL, 219),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 219),
    (1, HUFFMAN_EMIT_SYMBOL, 238),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 238),
    (1, HUFFMAN_EMIT_SYMBOL, 240),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 240),
    (1, HUFFMAN_EMIT_SYMBOL, 242),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 242),
    (1, HUFFMAN_EMIT_SYMBOL, 243),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 243),
    (1, HUFFMAN_EMIT_SYMBOL, 255),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 255),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 203),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 204),

    # Node 200
    (2, HUFFMAN_EMIT_SYMBOL, 218),
    (9, HUFFMAN_EMIT_SYMBOL, 218),
    (23, HUFFMAN_EMIT_SYMBOL, 218),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 218),
    (2, HUFFMAN_EMIT_SYMBOL, 219),
    (9, HUFFMAN_EMIT_SYMBOL, 219),
    (23, HUFFMAN_EMIT_SYMBOL, 219),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 219),
    (2, HUFFMAN_EMIT_SYMBOL, 238),
    (9, HUFFMAN_EMIT_SYMBOL, 238),
    (23, HUFFMAN_EMIT_SYMBOL, 238),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 238),
    (2, HUFFMAN_EMIT_SYMBOL, 240),
    (9, HUFFMAN_EMIT_SYMBOL, 240),
    (23, HUFFMAN_EMIT_SYMBOL, 240),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 240),

    # Node 201
    (3, HUFFMAN_EMIT_SYMBOL, 218),
    (6, HUFFMAN_EMIT_SYMBOL, 218),
    (10, HUFFMAN_EMIT_SYMBOL, 218),
    (15, HUFFMAN_EMIT_SYMBOL, 218),
    (24, HUFFMAN_EMIT_SYMBOL, 218),
    (31, HUFFMAN_EMIT_SYMBOL, 218),
    (41, HUFFMAN_EMIT_SYMBOL, 218),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 218),
    (3, HUFFMAN_EMIT_SYMBOL, 219),
    (6, HUFFMAN_EMIT_SYMBOL, 219),
    (10, HUFFMAN_EMIT_SYMBOL, 219),
    (15, HUFFMAN_EMIT_SYMBOL, 219),
    (24, HUFFMAN_EMIT_SYMBOL, 219),
    (31, HUFFMAN_EMIT_SYMBOL, 219),
    (41, HUFFMAN_EMIT_SYMBOL, 219),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 219),

    # Node 202
    (3, HUFFMAN_EMIT_SYMBOL, 238),
    (6, HUFFMAN_EMIT_SYMBOL, 238),
    (10, HUFFMAN_EMIT_SYMBOL, 238),
    (15, HUFFMAN_EMIT_SYMBOL, 238),
    (24, HUFFMAN_EMIT_SYMBOL, 238),
    (31, HUFFMAN_EMIT_SYMBOL, 238),
    (41, HUFFMAN_EMIT_SYMBOL, 238),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 238),
    (3, HUFFMAN_EMIT_SYMBOL, 240),
    (6, HUFFMAN_EMIT_SYMBOL, 240),
    (10, HUFFMAN_EMIT_SYMBOL, 240),
    (15, HUFFMAN_EMIT_SYMBOL, 240),
    (24, HUFFMAN_EMIT_SYMBOL, 240),
    (31, HUFFMAN_EMIT_SYMBOL, 240),
    (41, HUFFMAN_EMIT_SYMBOL, 240),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 240),

    # Node 203
    (2, HUFFMAN_EMIT_SYMBOL, 242),
    (9, HUFFMAN_EMIT_SYMBOL, 242),
    (23, HUFFMAN_EMIT_SYMBOL, 242),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 242),
    (2, HUFFMAN_EMIT_SYMBOL, 243),
    (9, HUFFMAN_EMIT_SYMBOL, 243),
    (23, HUFFMAN_EMIT_SYMBOL, 243),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 243),
    (2, HUFFMAN_EMIT_SYMBOL, 255),
    (9, HUFFMAN_EMIT_SYMBOL, 255),
    (23, HUFFMAN_EMIT_SYMBOL, 255),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 255),
    (1, HUFFMAN_EMIT_SYMBOL, 203),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 203),
    (1, HUFFMAN_EMIT_SYMBOL, 204),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 204),

    # Node 204
    (3, HUFFMAN_EMIT_SYMBOL, 242),
    (6, HUFFMAN_EMIT_SYMBOL, 242),
    (10, HUFFMAN_EMIT_SYMBOL, 242),
    (15, HUFFMAN_EMIT_SYMBOL, 242),
    (24, HUFFMAN_EMIT_SYMBOL, 242),
    (31, HUFFMAN_EMIT_SYMBOL, 242),
    (41, HUFFMAN_EMIT_SYMBOL, 242),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 242),
    (3, HUFFMAN_EMIT_SYMBOL, 243),
    (6, HUFFMAN_EMIT_SYMBOL, 243),
    (10, HUFFMAN_EMIT_SYMBOL, 243),
    (15, HUFFMAN_EMIT_SYMBOL, 243),
    (24, HUFFMAN_EMIT_SYMBOL, 243),
    (31, HUFFMAN_EMIT_SYMBOL, 243),
    (41, HUFFMAN_EMIT_SYMBOL, 243),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 243),

    # Node 205
    (3, HUFFMAN_EMIT_SYMBOL, 255),
    (6, HUFFMAN_EMIT_SYMBOL, 255),
    (10, HUFFMAN_EMIT_SYMBOL, 255),
    (15, HUFFMAN_EMIT_SYMBOL, 255),
    (24, HUFFMAN_EMIT_SYMBOL, 255),
    (31, HUFFMAN_EMIT_SYMBOL, 255),
    (41, HUFFMAN_EMIT_SYMBOL, 255),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 255),
    (2, HUFFMAN_EMIT_SYMBOL, 203),
    (9, HUFFMAN_EMIT_SYMBOL, 203),
    (23, HUFFMAN_EMIT_SYMBOL, 203),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 203),
    (2, HUFFMAN_EMIT_SYMBOL, 204),
    (9, HUFFMAN_EMIT_SYMBOL, 204),
    (23, HUFFMAN_EMIT_SYMBOL, 204),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 204),

    # Node 206
    (3, HUFFMAN_EMIT_SYMBOL, 203),
    (6, HUFFMAN_EMIT_SYMBOL, 203),
    (10, HUFFMAN_EMIT_SYMBOL, 203),
    (15, HUFFMAN_EMIT_SYMBOL, 203),
    (24, HUFFMAN_EMIT_SYMBOL, 203),
    (31, HUFFMAN_EMIT_SYMBOL, 203),
    (41, HUFFMAN_EMIT_SYMBOL, 203),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 203),
    (3, HUFFMAN_EMIT_SYMBOL, 204),
    (6, HUFFMAN_EMIT_SYMBOL, 204),
    (10, HUFFMAN_EMIT_SYMBOL, 204),
    (15, HUFFMAN_EMIT_SYMBOL, 204),
    (24, HUFFMAN_EMIT_SYMBOL, 204),
    (31, HUFFMAN_EMIT_SYMBOL, 204),
    (41, HUFFMAN_EMIT_SYMBOL, 204),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 204),

    # Node 207
    (211, 0, 0),
    (212, 0, 0),
    (214, 0, 0),
    (215, 0, 0),
    (218, 0, 0),
    (219, 0, 0),
    (221, 0, 0),
    (222, 0, 0),
    (226, 0, 0),
    (228, 0, 0),
    (232, 0, 0),
    (235, 0, 0),
    (240, 0, 0),
    (243, 0, 0),
    (247, 0, 0),
    (250, 0, 0),

    # Node 208
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 211),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 212),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 214),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 221),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 222),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 223),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 241),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 244),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 245),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 246),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 247),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 248),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 250),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 251),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 252),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 253),

    # Node 209
    (1, HUFFMAN_EMIT_SYMBOL, 211),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 211),
    (1, HUFFMAN_EMIT_SYMBOL, 212),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 212),
    (1, HUFFMAN_EMIT_SYMBOL, 214),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 214),
    (1, HUFFMAN_EMIT_SYMBOL, 221),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 221),
    (1, HUFFMAN_EMIT_SYMBOL, 222),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 222),
    (1, HUFFMAN_EMIT_SYMBOL, 223),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 223),
    (1, HUFFMAN_EMIT_SYMBOL, 241),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 241),
    (1, HUFFMAN_EMIT_SYMBOL, 244),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 244),

    # Node 210
    (2, HUFFMAN_EMIT_SYMBOL, 211),
    (9, HUFFMAN_EMIT_SYMBOL, 211),
    (23, HUFFMAN_EMIT_SYMBOL, 211),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 211),
    (2, HUFFMAN_EMIT_SYMBOL, 212),
    (9, HUFFMAN_EMIT_SYMBOL, 212),
    (23, HUFFMAN_EMIT_SYMBOL, 212),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 212),
    (2, HUFFMAN_EMIT_SYMBOL, 214),
    (9, HUFFMAN_EMIT_SYMBOL, 214),
    (23, HUFFMAN_EMIT_SYMBOL, 214),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 214),
    (2, HUFFMAN_EMIT_SYMBOL, 221),
    (9, HUFFMAN_EMIT_SYMBOL, 221),
    (23, HUFFMAN_EMIT_SYMBOL, 221),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 221),

    # Node 211
    (3, HUFFMAN_EMIT_SYMBOL, 211),
    (6, HUFFMAN_EMIT_SYMBOL, 211),
    (10, HUFFMAN_EMIT_SYMBOL, 211),
    (15, HUFFMAN_EMIT_SYMBOL, 211),
    (24, HUFFMAN_EMIT_SYMBOL, 211),
    (31, HUFFMAN_EMIT_SYMBOL, 211),
    (41, HUFFMAN_EMIT_SYMBOL, 211),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 211),
    (3, HUFFMAN_EMIT_SYMBOL, 212),
    (6, HUFFMAN_EMIT_SYMBOL, 212),
    (10, HUFFMAN_EMIT_SYMBOL, 212),
    (15, HUFFMAN_EMIT_SYMBOL, 212),
    (24, HUFFMAN_EMIT_SYMBOL, 212),
    (31, HUFFMAN_EMIT_SYMBOL, 212),
    (41, HUFFMAN_EMIT_SYMBOL, 212),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 212),

    # Node 212
    (3, HUFFMAN_EMIT_SYMBOL, 214),
    (6, HUFFMAN_EMIT_SYMBOL, 214),
    (10, HUFFMAN_EMIT_SYMBOL, 214),
    (15, HUFFMAN_EMIT_SYMBOL, 214),
    (24, HUFFMAN_EMIT_SYMBOL, 214),
    (31, HUFFMAN_EMIT_SYMBOL, 214),
    (41, HUFFMAN_EMIT_SYMBOL, 214),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 214),
    (3, HUFFMAN_EMIT_SYMBOL, 221),
    (6, HUFFMAN_EMIT_SYMBOL, 221),
    (10, HUFFMAN_EMIT_SYMBOL, 221),
    (15, HUFFMAN_EMIT_SYMBOL, 221),
    (24, HUFFMAN_EMIT_SYMBOL, 221),
    (31, HUFFMAN_EMIT_SYMBOL, 221),
    (41, HUFFMAN_EMIT_SYMBOL, 221),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 221),

    # Node 213
    (2, HUFFMAN_EMIT_SYMBOL, 222),
    (9, HUFFMAN_EMIT_SYMBOL, 222),
    (23, HUFFMAN_EMIT_SYMBOL, 222),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 222),
    (2, HUFFMAN_EMIT_SYMBOL, 223),
    (9, HUFFMAN_EMIT_SYMBOL, 223),
    (23, HUFFMAN_EMIT_SYMBOL, 223),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 223),
    (2, HUFFMAN_EMIT_SYMBOL, 241),
    (9, HUFFMAN_EMIT_SYMBOL, 241),
    (23, HUFFMAN_EMIT_SYMBOL, 241),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 241),
    (2, HUFFMAN_EMIT_SYMBOL, 244),
    (9, HUFFMAN_EMIT_SYMBOL, 244),
    (23, HUFFMAN_EMIT_SYMBOL, 244),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 244),

    # Node 214
    (3, HUFFMAN_EMIT_SYMBOL, 222),
    (6, HUFFMAN_EMIT_SYMBOL, 222),
    (10, HUFFMAN_EMIT_SYMBOL, 222),
    (15, HUFFMAN_EMIT_SYMBOL, 222),
    (24, HUFFMAN_EMIT_SYMBOL, 222),
    (31, HUFFMAN_EMIT_SYMBOL, 222),
    (41, HUFFMAN_EMIT_SYMBOL, 222),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 222),
    (3, HUFFMAN_EMIT_SYMBOL, 223),
    (6, HUFFMAN_EMIT_SYMBOL, 223),
    (10, HUFFMAN_EMIT_SYMBOL, 223),
    (15, HUFFMAN_EMIT_SYMBOL, 223),
    (24, HUFFMAN_EMIT_SYMBOL, 223),
    (31, HUFFMAN_EMIT_SYMBOL, 223),
    (41, HUFFMAN_EMIT_SYMBOL, 223),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 223),

    # Node 215
    (3, HUFFMAN_EMIT_SYMBOL, 241),
    (6, HUFFMAN_EMIT_SYMBOL, 241),
    (10, HUFFMAN_EMIT_SYMBOL, 241),
    (15, HUFFMAN_EMIT_SYMBOL, 241),
    (24, HUFFMAN_EMIT_SYMBOL, 241),
    (31, HUFFMAN_EMIT_SYMBOL, 241),
    (41, HUFFMAN_EMIT_SYMBOL, 241),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 241),
    (3, HUFFMAN_EMIT_SYMBOL, 244),
    (6, HUFFMAN_EMIT_SYMBOL, 244),
    (10, HUFFMAN_EMIT_SYMBOL, 244),
    (15, HUFFMAN_EMIT_SYMBOL, 244),
    (24, HUFFMAN_EMIT_SYMBOL, 244),
    (31, HUFFMAN_EMIT_SYMBOL, 244),
    (41, HUFFMAN_EMIT_SYMBOL, 244),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 244),

    # Node 216
    (1, HUFFMAN_EMIT_SYMBOL, 245),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 245),
    (1, HUFFMAN_EMIT_SYMBOL, 246),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 246),
    (1, HUFFMAN_EMIT_SYMBOL, 247),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 247),
    (1, HUFFMAN_EMIT_SYMBOL, 248),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 248),
    (1, HUFFMAN_EMIT_SYMBOL, 250),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 250),
    (1, HUFFMAN_EMIT_SYMBOL, 251),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 251),
    (1, HUFFMAN_EMIT_SYMBOL, 252),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 252),
    (1, HUFFMAN_EMIT_SYMBOL, 253),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 253),

    # Node 217
    (2, HUFFMAN_EMIT_SYMBOL, 245),
    (9, HUFFMAN_EMIT_SYMBOL, 245),
    (23, HUFFMAN_EMIT_SYMBOL, 245),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 245),
    (2, HUFFMAN_EMIT_SYMBOL, 246),
    (9, HUFFMAN_EMIT_SYMBOL, 246),
    (23, HUFFMAN_EMIT_SYMBOL, 246),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 246),
    (2, HUFFMAN_EMIT_SYMBOL, 247),
    (9, HUFFMAN_EMIT_SYMBOL, 247),
    (23, HUFFMAN_EMIT_SYMBOL, 247),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 247),
    (2, HUFFMAN_EMIT_SYMBOL, 248),
    (9, HUFFMAN_EMIT_SYMBOL, 248),
    (23, HUFFMAN_EMIT_SYMBOL, 248),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 248),

    # Node 218
    (3, HUFFMAN_EMIT_SYMBOL, 245),
    (6, HUFFMAN_EMIT_SYMBOL, 245),
    (10, HUFFMAN_EMIT_SYMBOL, 245),
    (15, HUFFMAN_EMIT_SYMBOL, 245),
    (24, HUFFMAN_EMIT_SYMBOL, 245),
    (31, HUFFMAN_EMIT_SYMBOL, 245),
    (41, HUFFMAN_EMIT_SYMBOL, 245),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 245),
    (3, HUFFMAN_EMIT_SYMBOL, 246),
    (6, HUFFMAN_EMIT_SYMBOL, 246),
    (10, HUFFMAN_EMIT_SYMBOL, 246),
    (15, HUFFMAN_EMIT_SYMBOL, 246),
    (24, HUFFMAN_EMIT_SYMBOL, 246),
    (31, HUFFMAN_EMIT_SYMBOL, 246),
    (41, HUFFMAN_EMIT_SYMBOL, 246),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 246),

    # Node 219
    (3, HUFFMAN_EMIT_SYMBOL, 247),
    (6, HUFFMAN_EMIT_SYMBOL, 247),
    (10, HUFFMAN_EMIT_SYMBOL, 247),
    (15, HUFFMAN_EMIT_SYMBOL, 247),
    (24, HUFFMAN_EMIT_SYMBOL, 247),
    (31, HUFFMAN_EMIT_SYMBOL, 247),
    (41, HUFFMAN_EMIT_SYMBOL, 247),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 247),
    (3, HUFFMAN_EMIT_SYMBOL, 248),
    (6, HUFFMAN_EMIT_SYMBOL, 248),
    (10, HUFFMAN_EMIT_SYMBOL, 248),
    (15, HUFFMAN_EMIT_SYMBOL, 248),
    (24, HUFFMAN_EMIT_SYMBOL, 248),
    (31, HUFFMAN_EMIT_SYMBOL, 248),
    (41, HUFFMAN_EMIT_SYMBOL, 248),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 248),

    # Node 220
    (2, HUFFMAN_EMIT_SYMBOL, 250),
    (9, HUFFMAN_EMIT_SYMBOL, 250),
    (23, HUFFMAN_EMIT_SYMBOL, 250),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 250),
    (2, HUFFMAN_EMIT_SYMBOL, 251),
    (9, HUFFMAN_EMIT_SYMBOL, 251),
    (23, HUFFMAN_EMIT_SYMBOL, 251),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 251),
    (2, HUFFMAN_EMIT_SYMBOL, 252),
    (9, HUFFMAN_EMIT_SYMBOL, 252),
    (23, HUFFMAN_EMIT_SYMBOL, 252),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 252),
    (2, HUFFMAN_EMIT_SYMBOL, 253),
    (9, HUFFMAN_EMIT_SYMBOL, 253),
    (23, HUFFMAN_EMIT_SYMBOL, 253),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 253),

    # Node 221
    (3, HUFFMAN_EMIT_SYMBOL, 250),
    (6, HUFFMAN_EMIT_SYMBOL, 250),
    (10, HUFFMAN_EMIT_SYMBOL, 250),
    (15, HUFFMAN_EMIT_SYMBOL, 250),
    (24, HUFFMAN_EMIT_SYMBOL, 250),
    (31, HUFFMAN_EMIT_SYMBOL, 250),
    (41, HUFFMAN_EMIT_SYMBOL, 250),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 250),
    (3, HUFFMAN_EMIT_SYMBOL, 251),
    (6, HUFFMAN_EMIT_SYMBOL, 251),
    (10, HUFFMAN_EMIT_SYMBOL, 251),
    (15, HUFFMAN_EMIT_SYMBOL, 251),
    (24, HUFFMAN_EMIT_SYMBOL, 251),
    (31, HUFFMAN_EMIT_SYMBOL, 251),
    (41, HUFFMAN_EMIT_SYMBOL, 251),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 251),

    # Node 222
    (3, HUFFMAN_EMIT_SYMBOL, 252),
    (6, HUFFMAN_EMIT_SYMBOL, 252),
    (10, HUFFMAN_EMIT_SYMBOL, 252),
    (15, HUFFMAN_EMIT_SYMBOL, 252),
    (24, HUFFMAN_EMIT_SYMBOL, 252),
    (31, HUFFMAN_EMIT_SYMBOL, 252),
    (41, HUFFMAN_EMIT_SYMBOL, 252),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 252),
    (3, HUFFMAN_EMIT_SYMBOL, 253),
    (6, HUFFMAN_EMIT_SYMBOL, 253),
    (10, HUFFMAN_EMIT_SYMBOL, 253),
    (15, HUFFMAN_EMIT_SYMBOL, 253),
    (24, HUFFMAN_EMIT_SYMBOL, 253),
    (31, HUFFMAN_EMIT_SYMBOL, 253),
    (41, HUFFMAN_EMIT_SYMBOL, 253),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 253),

    # Node 223
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 254),
    (227, 0, 0),
    (229, 0, 0),
    (230, 0, 0),
    (233, 0, 0),
    (234, 0, 0),
    (236, 0, 0),
    (237, 0, 0),
    (241, 0, 0),
    (242, 0, 0),
    (244, 0, 0),
    (245, 0, 0),
    (248, 0, 0),
    (249, 0, 0),
    (251, 0, 0),
    (252, 0, 0),

    # Node 224
    (1, HUFFMAN_EMIT_SYMBOL, 254),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 254),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 2),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 3),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 4),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 5),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 6),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 7),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 8),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 11),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 12),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 14),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 15),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 16),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 17),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 18),

    # Node 225
    (2, HUFFMAN_EMIT_SYMBOL, 254),
    (9, HUFFMAN_EMIT_SYMBOL, 254),
    (23, HUFFMAN_EMIT_SYMBOL, 254),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 254),
    (1, HUFFMAN_EMIT_SYMBOL, 2),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 2),
    (1, HUFFMAN_EMIT_SYMBOL, 3),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 3),
    (1, HUFFMAN_EMIT_SYMBOL, 4),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 4),
    (1, HUFFMAN_EMIT_SYMBOL, 5),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 5),
    (1, HUFFMAN_EMIT_SYMBOL, 6),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 6),
    (1, HUFFMAN_EMIT_SYMBOL, 7),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 7),

    # Node 226
    (3, HUFFMAN_EMIT_SYMBOL, 254),
    (6, HUFFMAN_EMIT_SYMBOL, 254),
    (10, HUFFMAN_EMIT_SYMBOL, 254),
    (15, HUFFMAN_EMIT_SYMBOL, 254),
    (24, HUFFMAN_EMIT_SYMBOL, 254),
    (31, HUFFMAN_EMIT_SYMBOL, 254),
    (41, HUFFMAN_EMIT_SYMBOL, 254),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 254),
    (2, HUFFMAN_EMIT_SYMBOL, 2),
    (9, HUFFMAN_EMIT_SYMBOL, 2),
    (23, HUFFMAN_EMIT_SYMBOL, 2),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 2),
    (2, HUFFMAN_EMIT_SYMBOL, 3),
    (9, HUFFMAN_EMIT_SYMBOL, 3),
    (23, HUFFMAN_EMIT_SYMBOL, 3),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 3),

    # Node 227
    (3, HUFFMAN_EMIT_SYMBOL, 2),
    (6, HUFFMAN_EMIT_SYMBOL, 2),
    (10, HUFFMAN_EMIT_SYMBOL, 2),
    (15, HUFFMAN_EMIT_SYMBOL, 2),
    (24, HUFFMAN_EMIT_SYMBOL, 2),
    (31, HUFFMAN_EMIT_SYMBOL, 2),
    (41, HUFFMAN_EMIT_SYMBOL, 2),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 2),
    (3, HUFFMAN_EMIT_SYMBOL, 3),
    (6, HUFFMAN_EMIT_SYMBOL, 3),
    (10, HUFFMAN_EMIT_SYMBOL, 3),
    (15, HUFFMAN_EMIT_SYMBOL, 3),
    (24, HUFFMAN_EMIT_SYMBOL, 3),
    (31, HUFFMAN_EMIT_SYMBOL, 3),
    (41, HUFFMAN_EMIT_SYMBOL, 3),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 3),

    # Node 228
    (2, HUFFMAN_EMIT_SYMBOL, 4),
    (9, HUFFMAN_EMIT_SYMBOL, 4),
    (23, HUFFMAN_EMIT_SYMBOL, 4),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 4),
    (2, HUFFMAN_EMIT_SYMBOL, 5),
    (9, HUFFMAN_EMIT_SYMBOL, 5),
    (23, HUFFMAN_EMIT_SYMBOL, 5),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 5),
    (2, HUFFMAN_EMIT_SYMBOL, 6),
    (9, HUFFMAN_EMIT_SYMBOL, 6),
    (23, HUFFMAN_EMIT_SYMBOL, 6),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 6),
    (2, HUFFMAN_EMIT_SYMBOL, 7),
    (9, HUFFMAN_EMIT_SYMBOL, 7),
    (23, HUFFMAN_EMIT_SYMBOL, 7),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 7),

    # Node 229
    (3, HUFFMAN_EMIT_SYMBOL, 4),
    (6, HUFFMAN_EMIT_SYMBOL, 4),
    (10, HUFFMAN_EMIT_SYMBOL, 4),
    (15, HUFFMAN_EMIT_SYMBOL, 4),
    (24, HUFFMAN_EMIT_SYMBOL, 4),
    (31, HUFFMAN_EMIT_SYMBOL, 4),
    (41, HUFFMAN_EMIT_SYMBOL, 4),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 4),
    (3, HUFFMAN_EMIT_SYMBOL, 5),
    (6, HUFFMAN_EMIT_SYMBOL, 5),
    (10, HUFFMAN_EMIT_SYMBOL, 5),
    (15, HUFFMAN_EMIT_SYMBOL, 5),
    (24, HUFFMAN_EMIT_SYMBOL, 5),
    (31, HUFFMAN_EMIT_SYMBOL, 5),
    (41, HUFFMAN_EMIT_SYMBOL, 5),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 5),

    # Node 230
    (3, HUFFMAN_EMIT_SYMBOL, 6),
    (6, HUFFMAN_EMIT_SYMBOL, 6),
    (10, HUFFMAN_EMIT_SYMBOL, 6),
    (15, HUFFMAN_EMIT_SYMBOL, 6),
    (24, HUFFMAN_EMIT_SYMBOL, 6),
    (31, HUFFMAN_EMIT_SYMBOL, 6),
    (41, HUFFMAN_EMIT_SYMBOL, 6),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 6),
    (3, HUFFMAN_EMIT_SYMBOL, 7),
    (6, HUFFMAN_EMIT_SYMBOL, 7),
    (10, HUFFMAN_EMIT_SYMBOL, 7),
    (15, HUFFMAN_EMIT_SYMBOL, 7),
    (24, HUFFMAN_EMIT_SYMBOL, 7),
    (31, HUFFMAN_EMIT_SYMBOL, 7),
    (41, HUFFMAN_EMIT_SYMBOL, 7),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 7),

    # Node 231
    (1, HUFFMAN_EMIT_SYMBOL, 8),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 8),
    (1, HUFFMAN_EMIT_SYMBOL, 11),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 11),
    (1, HUFFMAN_EMIT_SYMBOL, 12),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 12),
    (1, HUFFMAN_EMIT_SYMBOL, 14),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 14),
    (1, HUFFMAN_EMIT_SYMBOL, 15),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 15),
    (1, HUFFMAN_EMIT_SYMBOL, 16),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 16),
    (1, HUFFMAN_EMIT_SYMBOL, 17),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 17),
    (1, HUFFMAN_EMIT_SYMBOL, 18),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 18),

    # Node 232
    (2, HUFFMAN_EMIT_SYMBOL, 8),
    (9, HUFFMAN_EMIT_SYMBOL, 8),
    (23, HUFFMAN_EMIT_SYMBOL, 8),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 8),
    (2, HUFFMAN_EMIT_SYMBOL, 11),
    (9, HUFFMAN_EMIT_SYMBOL, 11),
    (23, HUFFMAN_EMIT_SYMBOL, 11),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 11),
    (2, HUFFMAN_EMIT_SYMBOL, 12),
    (9, HUFFMAN_EMIT_SYMBOL, 12),
    (23, HUFFMAN_EMIT_SYMBOL, 12),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 12),
    (2, HUFFMAN_EMIT_SYMBOL, 14),
    (9, HUFFMAN_EMIT_SYMBOL, 14),
    (23, HUFFMAN_EMIT_SYMBOL, 14),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 14),

    # Node 233
    (3, HUFFMAN_EMIT_SYMBOL, 8),
    (6, HUFFMAN_EMIT_SYMBOL, 8),
    (10, HUFFMAN_EMIT_SYMBOL, 8),
    (15, HUFFMAN_EMIT_SYMBOL, 8),
    (24, HUFFMAN_EMIT_SYMBOL, 8),
    (31, HUFFMAN_EMIT_SYMBOL, 8),
    (41, HUFFMAN_EMIT_SYMBOL, 8),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 8),
    (3, HUFFMAN_EMIT_SYMBOL, 11),
    (6, HUFFMAN_EMIT_SYMBOL, 11),
    (10, HUFFMAN_EMIT_SYMBOL, 11),
    (15, HUFFMAN_EMIT_SYMBOL, 11),
    (24, HUFFMAN_EMIT_SYMBOL, 11),
    (31, HUFFMAN_EMIT_SYMBOL, 11),
    (41, HUFFMAN_EMIT_SYMBOL, 11),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 11),

    # Node 234
    (3, HUFFMAN_EMIT_SYMBOL, 12),
    (6, HUFFMAN_EMIT_SYMBOL, 12),
    (10, HUFFMAN_EMIT_SYMBOL, 12),
    (15, HUFFMAN_EMIT_SYMBOL, 12),
    (24, HUFFMAN_EMIT_SYMBOL, 12),
    (31, HUFFMAN_EMIT_SYMBOL, 12),
    (41, HUFFMAN_EMIT_SYMBOL, 12),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 12),
    (3, HUFFMAN_EMIT_SYMBOL, 14),
    (6, HUFFMAN_EMIT_SYMBOL, 14),
    (10, HUFFMAN_EMIT_SYMBOL, 14),
    (15, HUFFMAN_EMIT_SYMBOL, 14),
    (24, HUFFMAN_EMIT_SYMBOL, 14),
    (31, HUFFMAN_EMIT_SYMBOL, 14),
    (41, HUFFMAN_EMIT_SYMBOL, 14),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 14),

    # Node 235
    (2, HUFFMAN_EMIT_SYMBOL, 15),
    (9, HUFFMAN_EMIT_SYMBOL, 15),
    (23, HUFFMAN_EMIT_SYMBOL, 15),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 15),
    (2, HUFFMAN_EMIT_SYMBOL, 16),
    (9, HUFFMAN_EMIT_SYMBOL, 16),
    (23, HUFFMAN_EMIT_SYMBOL, 16),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 16),
    (2, HUFFMAN_EMIT_SYMBOL, 17),
    (9, HUFFMAN_EMIT_SYMBOL, 17),
    (23, HUFFMAN_EMIT_SYMBOL, 17),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 17),
    (2, HUFFMAN_EMIT_SYMBOL, 18),
    (9, HUFFMAN_EMIT_SYMBOL, 18),
    (23, HUFFMAN_EMIT_SYMBOL, 18),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 18),

    # Node 236
    (3, HUFFMAN_EMIT_SYMBOL, 15),
    (6, HUFFMAN_EMIT_SYMBOL, 15),
    (10, HUFFMAN_EMIT_SYMBOL, 15),
    (15, HUFFMAN_EMIT_SYMBOL, 15),
    (24, HUFFMAN_EMIT_SYMBOL, 15),
    (31, HUFFMAN_EMIT_SYMBOL, 15),
    (41, HUFFMAN_EMIT_SYMBOL, 15),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 15),
    (3, HUFFMAN_EMIT_SYMBOL, 16),
    (6, HUFFMAN_EMIT_SYMBOL, 16),
    (10, HUFFMAN_EMIT_SYMBOL, 16),
    (15, HUFFMAN_EMIT_SYMBOL, 16),
    (24, HUFFMAN_EMIT_SYMBOL, 16),
    (31, HUFFMAN_EMIT_SYMBOL, 16),
    (41, HUFFMAN_EMIT_SYMBOL, 16),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 16),

    # Node 237
    (3, HUFFMAN_EMIT_SYMBOL, 17),
    (6, HUFFMAN_EMIT_SYMBOL, 17),
    (10, HUFFMAN_EMIT_SYMBOL, 17),
    (15, HUFFMAN_EMIT_SYMBOL, 17),
    (24, HUFFMAN_EMIT_SYMBOL, 17),
    (31, HUFFMAN_EMIT_SYMBOL, 17),
    (41, HUFFMAN_EMIT_SYMBOL, 17),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 17),
    (3, HUFFMAN_EMIT_SYMBOL, 18),
    (6, HUFFMAN_EMIT_SYMBOL, 18),
    (10, HUFFMAN_EMIT_SYMBOL, 18),
    (15, HUFFMAN_EMIT_SYMBOL, 18),
    (24, HUFFMAN_EMIT_SYMBOL, 18),
    (31, HUFFMAN_EMIT_SYMBOL, 18),
    (41, HUFFMAN_EMIT_SYMBOL, 18),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 18),

    # Node 238
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 19),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 20),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 21),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 23),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 24),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 25),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 26),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 27),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 28),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 29),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 30),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 31),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 127),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 220),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 249),
    (253, 0, 0),

    # Node 239
    (1, HUFFMAN_EMIT_SYMBOL, 19),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 19),
    (1, HUFFMAN_EMIT_SYMBOL, 20),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 20),
    (1, HUFFMAN_EMIT_SYMBOL, 21),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 21),
    (1, HUFFMAN_EMIT_SYMBOL, 23),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 23),
    (1, HUFFMAN_EMIT_SYMBOL, 24),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 24),
    (1, HUFFMAN_EMIT_SYMBOL, 25),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 25),
    (1, HUFFMAN_EMIT_SYMBOL, 26),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 26),
    (1, HUFFMAN_EMIT_SYMBOL, 27),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 27),

    # Node 240
    (2, HUFFMAN_EMIT_SYMBOL, 19),
    (9, HUFFMAN_EMIT_SYMBOL, 19),
    (23, HUFFMAN_EMIT_SYMBOL, 19),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 19),
    (2, HUFFMAN_EMIT_SYMBOL, 20),
    (9, HUFFMAN_EMIT_SYMBOL, 20),
    (23, HUFFMAN_EMIT_SYMBOL, 20),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 20),
    (2, HUFFMAN_EMIT_SYMBOL, 21),
    (9, HUFFMAN_EMIT_SYMBOL, 21),
    (23, HUFFMAN_EMIT_SYMBOL, 21),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 21),
    (2, HUFFMAN_EMIT_SYMBOL, 23),
    (9, HUFFMAN_EMIT_SYMBOL, 23),
    (23, HUFFMAN_EMIT_SYMBOL, 23),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 23),

    # Node 241
    (3, HUFFMAN_EMIT_SYMBOL, 19),
    (6, HUFFMAN_EMIT_SYMBOL, 19),
    (10, HUFFMAN_EMIT_SYMBOL, 19),
    (15, HUFFMAN_EMIT_SYMBOL, 19),
    (24, HUFFMAN_EMIT_SYMBOL, 19),
    (31, HUFFMAN_EMIT_SYMBOL, 19),
    (41, HUFFMAN_EMIT_SYMBOL, 19),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 19),
    (3, HUFFMAN_EMIT_SYMBOL, 20),
    (6, HUFFMAN_EMIT_SYMBOL, 20),
    (10, HUFFMAN_EMIT_SYMBOL, 20),
    (15, HUFFMAN_EMIT_SYMBOL, 20),
    (24, HUFFMAN_EMIT_SYMBOL, 20),
    (31, HUFFMAN_EMIT_SYMBOL, 20),
    (41, HUFFMAN_EMIT_SYMBOL, 20),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 20),

    # Node 242
    (3, HUFFMAN_EMIT_SYMBOL, 21),
    (6, HUFFMAN_EMIT_SYMBOL, 21),
    (10, HUFFMAN_EMIT_SYMBOL, 21),
    (15, HUFFMAN_EMIT_SYMBOL, 21),
    (24, HUFFMAN_EMIT_SYMBOL, 21),
    (31, HUFFMAN_EMIT_SYMBOL, 21),
    (41, HUFFMAN_EMIT_SYMBOL, 21),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 21),
    (3, HUFFMAN_EMIT_SYMBOL, 23),
    (6, HUFFMAN_EMIT_SYMBOL, 23),
    (10, HUFFMAN_EMIT_SYMBOL, 23),
    (15, HUFFMAN_EMIT_SYMBOL, 23),
    (24, HUFFMAN_EMIT_SYMBOL, 23),
    (31, HUFFMAN_EMIT_SYMBOL, 23),
    (41, HUFFMAN_EMIT_SYMBOL, 23),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 23),

    # Node 243
    (2, HUFFMAN_EMIT_SYMBOL, 24),
    (9, HUFFMAN_EMIT_SYMBOL, 24),
    (23, HUFFMAN_EMIT_SYMBOL, 24),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 24),
    (2, HUFFMAN_EMIT_SYMBOL, 25),
    (9, HUFFMAN_EMIT_SYMBOL, 25),
    (23, HUFFMAN_EMIT_SYMBOL, 25),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 25),
    (2, HUFFMAN_EMIT_SYMBOL, 26),
    (9, HUFFMAN_EMIT_SYMBOL, 26),
    (23, HUFFMAN_EMIT_SYMBOL, 26),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 26),
    (2, HUFFMAN_EMIT_SYMBOL, 27),
    (9, HUFFMAN_EMIT_SYMBOL, 27),
    (23, HUFFMAN_EMIT_SYMBOL, 27),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 27),

    # Node 244
    (3, HUFFMAN_EMIT_SYMBOL, 24),
    (6, HUFFMAN_EMIT_SYMBOL, 24),
    (10, HUFFMAN_EMIT_SYMBOL, 24),
    (15, HUFFMAN_EMIT_SYMBOL, 24),
    (24, HUFFMAN_EMIT_SYMBOL, 24),
    (31, HUFFMAN_EMIT_SYMBOL, 24),
    (41, HUFFMAN_EMIT_SYMBOL, 24),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 24),
    (3, HUFFMAN_EMIT_SYMBOL, 25),
    (6, HUFFMAN_EMIT_SYMBOL, 25),
    (10, HUFFMAN_EMIT_SYMBOL, 25),
    (15, HUFFMAN_EMIT_SYMBOL, 25),
    (24, HUFFMAN_EMIT_SYMBOL, 25),
    (31, HUFFMAN_EMIT_SYMBOL, 25),
    (41, HUFFMAN_EMIT_SYMBOL, 25),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 25),

    # Node 245
    (3, HUFFMAN_EMIT_SYMBOL, 26),
    (6, HUFFMAN_EMIT_SYMBOL, 26),
    (10, HUFFMAN_EMIT_SYMBOL, 26),
    (15, HUFFMAN_EMIT_SYMBOL, 26),
    (24, HUFFMAN_EMIT_SYMBOL, 26),
    (31, HUFFMAN_EMIT_SYMBOL, 26),
    (41, HUFFMAN_EMIT_SYMBOL, 26),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 26),
    (3, HUFFMAN_EMIT_SYMBOL, 27),
    (6, HUFFMAN_EMIT_SYMBOL, 27),
    (10, HUFFMAN_EMIT_SYMBOL, 27),
    (15, HUFFMAN_EMIT_SYMBOL, 27),
    (24, HUFFMAN_EMIT_SYMBOL, 27),
    (31, HUFFMAN_EMIT_SYMBOL, 27),
    (41, HUFFMAN_EMIT_SYMBOL, 27),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 27),

    # Node 246
    (1, HUFFMAN_EMIT_SYMBOL, 28),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 28),
    (1, HUFFMAN_EMIT_SYMBOL, 29),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 29),
    (1, HUFFMAN_EMIT_SYMBOL, 30),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 30),
    (1, HUFFMAN_EMIT_SYMBOL, 31),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 31),
    (1, HUFFMAN_EMIT_SYMBOL, 127),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 127),
    (1, HUFFMAN_EMIT_SYMBOL, 220),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 220),
    (1, HUFFMAN_EMIT_SYMBOL, 249),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 249),
    (254, 0, 0),
    (255, 0, 0),

    # Node 247
    (2, HUFFMAN_EMIT_SYMBOL, 28),
    (9, HUFFMAN_EMIT_SYMBOL, 28),
    (23, HUFFMAN_EMIT_SYMBOL, 28),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 28),
    (2, HUFFMAN_EMIT_SYMBOL, 29),
    (9, HUFFMAN_EMIT_SYMBOL, 29),
    (23, HUFFMAN_EMIT_SYMBOL, 29),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 29),
    (2, HUFFMAN_EMIT_SYMBOL, 30),
    (9, HUFFMAN_EMIT_SYMBOL, 30),
    (23, HUFFMAN_EMIT_SYMBOL, 30),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 30),
    (2, HUFFMAN_EMIT_SYMBOL, 31),
    (9, HUFFMAN_EMIT_SYMBOL, 31),
    (23, HUFFMAN_EMIT_SYMBOL, 31),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 31),

    # Node 248
    (3, HUFFMAN_EMIT_SYMBOL, 28),
    (6, HUFFMAN_EMIT_SYMBOL, 28),
    (10, HUFFMAN_EMIT_SYMBOL, 28),
    (15, HUFFMAN_EMIT_SYMBOL, 28),
    (24, HUFFMAN_EMIT_SYMBOL, 28),
    (31, HUFFMAN_EMIT_SYMBOL, 28),
    (41, HUFFMAN_EMIT_SYMBOL, 28),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 28),
    (3, HUFFMAN_EMIT_SYMBOL, 29),
    (6, HUFFMAN_EMIT_SYMBOL, 29),
    (10, HUFFMAN_EMIT_SYMBOL, 29),
    (15, HUFFMAN_EMIT_SYMBOL, 29),
    (24, HUFFMAN_EMIT_SYMBOL, 29),
    (31, HUFFMAN_EMIT_SYMBOL, 29),
    (41, HUFFMAN_EMIT_SYMBOL, 29),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 29),

    # Node 249
    (3, HUFFMAN_EMIT_SYMBOL, 30),
    (6, HUFFMAN_EMIT_SYMBOL, 30),
    (10, HUFFMAN_EMIT_SYMBOL, 30),
    (15, HUFFMAN_EMIT_SYMBOL, 30),
    (24, HUFFMAN_EMIT_SYMBOL, 30),
    (31, HUFFMAN_EMIT_SYMBOL, 30),
    (41, HUFFMAN_EMIT_SYMBOL, 30),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 30),
    (3, HUFFMAN_EMIT_SYMBOL, 31),
    (6, HUFFMAN_EMIT_SYMBOL, 31),
    (10, HUFFMAN_EMIT_SYMBOL, 31),
    (15, HUFFMAN_EMIT_SYMBOL, 31),
    (24, HUFFMAN_EMIT_SYMBOL, 31),
    (31, HUFFMAN_EMIT_SYMBOL, 31),
    (41, HUFFMAN_EMIT_SYMBOL, 31),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 31),

    # Node 250
    (2, HUFFMAN_EMIT_SYMBOL, 127),
    (9, HUFFMAN_EMIT_SYMBOL, 127),
    (23, HUFFMAN_EMIT_SYMBOL, 127),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 127),
    (2, HUFFMAN_EMIT_SYMBOL, 220),
    (9, HUFFMAN_EMIT_SYMBOL, 220),
    (23, HUFFMAN_EMIT_SYMBOL, 220),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 220),
    (2, HUFFMAN_EMIT_SYMBOL, 249),
    (9, HUFFMAN_EMIT_SYMBOL, 249),
    (23, HUFFMAN_EMIT_SYMBOL, 249),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 249),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 10),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 13),
    (0, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 22),
    (0, HUFFMAN_FAIL, 0),

    # Node 251
    (3, HUFFMAN_EMIT_SYMBOL, 127),
    (6, HUFFMAN_EMIT_SYMBOL, 127),
    (10, HUFFMAN_EMIT_SYMBOL, 127),
    (15, HUFFMAN_EMIT_SYMBOL, 127),
    (24, HUFFMAN_EMIT_SYMBOL, 127),
    (31, HUFFMAN_EMIT_SYMBOL, 127),
    (41, HUFFMAN_EMIT_SYMBOL, 127),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 127),
    (3, HUFFMAN_EMIT_SYMBOL, 220),
    (6, HUFFMAN_EMIT_SYMBOL, 220),
    (10, HUFFMAN_EMIT_SYMBOL, 220),
    (15, HUFFMAN_EMIT_SYMBOL, 220),
    (24, HUFFMAN_EMIT_SYMBOL, 220),
    (31, HUFFMAN_EMIT_SYMBOL, 220),
    (41, HUFFMAN_EMIT_SYMBOL, 220),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 220),

    # Node 252
    (3, HUFFMAN_EMIT_SYMBOL, 249),
    (6, HUFFMAN_EMIT_SYMBOL, 249),
    (10, HUFFMAN_EMIT_SYMBOL, 249),
    (15, HUFFMAN_EMIT_SYMBOL, 249),
    (24, HUFFMAN_EMIT_SYMBOL, 249),
    (31, HUFFMAN_EMIT_SYMBOL, 249),
    (41, HUFFMAN_EMIT_SYMBOL, 249),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 249),
    (1, HUFFMAN_EMIT_SYMBOL, 10),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 10),
    (1, HUFFMAN_EMIT_SYMBOL, 13),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 13),
    (1, HUFFMAN_EMIT_SYMBOL, 22),
    (22, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 22),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),

    # Node 253
    (2, HUFFMAN_EMIT_SYMBOL, 10),
    (9, HUFFMAN_EMIT_SYMBOL, 10),
    (23, HUFFMAN_EMIT_SYMBOL, 10),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 10),
    (2, HUFFMAN_EMIT_SYMBOL, 13),
    (9, HUFFMAN_EMIT_SYMBOL, 13),
    (23, HUFFMAN_EMIT_SYMBOL, 13),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 13),
    (2, HUFFMAN_EMIT_SYMBOL, 22),
    (9, HUFFMAN_EMIT_SYMBOL, 22),
    (23, HUFFMAN_EMIT_SYMBOL, 22),
    (40, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 22),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),

    # Node 254
    (3, HUFFMAN_EMIT_SYMBOL, 10),
    (6, HUFFMAN_EMIT_SYMBOL, 10),
    (10, HUFFMAN_EMIT_SYMBOL, 10),
    (15, HUFFMAN_EMIT_SYMBOL, 10),
    (24, HUFFMAN_EMIT_SYMBOL, 10),
    (31, HUFFMAN_EMIT_SYMBOL, 10),
    (41, HUFFMAN_EMIT_SYMBOL, 10),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 10),
    (3, HUFFMAN_EMIT_SYMBOL, 13),
    (6, HUFFMAN_EMIT_SYMBOL, 13),
    (10, HUFFMAN_EMIT_SYMBOL, 13),
    (15, HUFFMAN_EMIT_SYMBOL, 13),
    (24, HUFFMAN_EMIT_SYMBOL, 13),
    (31, HUFFMAN_EMIT_SYMBOL, 13),
    (41, HUFFMAN_EMIT_SYMBOL, 13),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 13),

    # Node 255
    (3, HUFFMAN_EMIT_SYMBOL, 22),
    (6, HUFFMAN_EMIT_SYMBOL, 22),
    (10, HUFFMAN_EMIT_SYMBOL, 22),
    (15, HUFFMAN_EMIT_SYMBOL, 22),
    (24, HUFFMAN_EMIT_SYMBOL, 22),
    (31, HUFFMAN_EMIT_SYMBOL, 22),
    (41, HUFFMAN_EMIT_SYMBOL, 22),
    (56, HUFFMAN_COMPLETE | HUFFMAN_EMIT_SYMBOL, 22),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
    (0, HUFFMAN_FAIL, 0),
]


# ---------------------------------------------------------------------------
# hpack/struct.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
Contains structures for representing header fields with associated metadata.
"""

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from typing_extensions import Self, TypeAlias  # noqa: UP035, pragma: no cover


class HeaderTuple(tuple[bytes, bytes]):
    """
    A data structure that stores a single header field.

    HTTP headers can be thought of as tuples of ``(field name, field value)``.
    A single header block is a sequence of such tuples.

    In HTTP/2, however, certain bits of additional information are required for
    compressing these headers: in particular, whether the header field can be
    safely added to the HPACK compression context.

    This class stores a header that can be added to the compression context. In
    all other ways it behaves exactly like a tuple.
    """

    __slots__ = ()

    indexable = True

    def __new__(cls, *args: Any) -> Self:
        return tuple.__new__(cls, args)


class NeverIndexedHeaderTuple(HeaderTuple):
    """
    A data structure that stores a single header field that cannot be added to
    a HTTP/2 header compression context.
    """

    __slots__ = ()

    indexable = False

    def __new__(cls, *args: Any) -> Self:
        return tuple.__new__(cls, args)


Header: TypeAlias = "HeaderTuple | NeverIndexedHeaderTuple | tuple[bytes, bytes]"
HeaderWeaklyTyped: TypeAlias = "HeaderTuple | NeverIndexedHeaderTuple | tuple[bytes | str, bytes | str]"


# ---------------------------------------------------------------------------
# hpack/table.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

# flake8: noqa
from collections import deque
import logging
from typing import Optional


_hpack_table_log = logging.getLogger('hpack.table')


def table_entry_size(name: bytes, value: bytes) -> int:
    """
    Calculates the size of a single entry

    This size is mostly irrelevant to us and defined
    specifically to accommodate memory management for
    lower level implementations. The 32 extra bytes are
    considered the "maximum" overhead that would be
    required to represent each entry in the table.

    See RFC7541 Section 4.1
    """
    return 32 + len(name) + len(value)


class HeaderTable:
    """
    Implements the combined static and dynamic header table

    The name and value arguments for all the functions
    should ONLY be byte strings (b'') however this is not
    strictly enforced in the interface.

    See RFC7541 Section 2.3
    """
    #: Default maximum size of the dynamic table. See
    #:  RFC7540 Section 6.5.2.
    DEFAULT_SIZE = 4096

    #: Constant list of static headers. See RFC7541 Section
    #:  2.3.1 and Appendix A
    STATIC_TABLE = (
        (b':authority'                  , b''             ),  # noqa
        (b':method'                     , b'GET'          ),  # noqa
        (b':method'                     , b'POST'         ),  # noqa
        (b':path'                       , b'/'            ),  # noqa
        (b':path'                       , b'/index.html'  ),  # noqa
        (b':scheme'                     , b'http'         ),  # noqa
        (b':scheme'                     , b'https'        ),  # noqa
        (b':status'                     , b'200'          ),  # noqa
        (b':status'                     , b'204'          ),  # noqa
        (b':status'                     , b'206'          ),  # noqa
        (b':status'                     , b'304'          ),  # noqa
        (b':status'                     , b'400'          ),  # noqa
        (b':status'                     , b'404'          ),  # noqa
        (b':status'                     , b'500'          ),  # noqa
        (b'accept-charset'              , b''             ),  # noqa
        (b'accept-encoding'             , b'gzip, deflate'),  # noqa
        (b'accept-language'             , b''             ),  # noqa
        (b'accept-ranges'               , b''             ),  # noqa
        (b'accept'                      , b''             ),  # noqa
        (b'access-control-allow-origin' , b''             ),  # noqa
        (b'age'                         , b''             ),  # noqa
        (b'allow'                       , b''             ),  # noqa
        (b'authorization'               , b''             ),  # noqa
        (b'cache-control'               , b''             ),  # noqa
        (b'content-disposition'         , b''             ),  # noqa
        (b'content-encoding'            , b''             ),  # noqa
        (b'content-language'            , b''             ),  # noqa
        (b'content-length'              , b''             ),  # noqa
        (b'content-location'            , b''             ),  # noqa
        (b'content-range'               , b''             ),  # noqa
        (b'content-type'                , b''             ),  # noqa
        (b'cookie'                      , b''             ),  # noqa
        (b'date'                        , b''             ),  # noqa
        (b'etag'                        , b''             ),  # noqa
        (b'expect'                      , b''             ),  # noqa
        (b'expires'                     , b''             ),  # noqa
        (b'from'                        , b''             ),  # noqa
        (b'host'                        , b''             ),  # noqa
        (b'if-match'                    , b''             ),  # noqa
        (b'if-modified-since'           , b''             ),  # noqa
        (b'if-none-match'               , b''             ),  # noqa
        (b'if-range'                    , b''             ),  # noqa
        (b'if-unmodified-since'         , b''             ),  # noqa
        (b'last-modified'               , b''             ),  # noqa
        (b'link'                        , b''             ),  # noqa
        (b'location'                    , b''             ),  # noqa
        (b'max-forwards'                , b''             ),  # noqa
        (b'proxy-authenticate'          , b''             ),  # noqa
        (b'proxy-authorization'         , b''             ),  # noqa
        (b'range'                       , b''             ),  # noqa
        (b'referer'                     , b''             ),  # noqa
        (b'refresh'                     , b''             ),  # noqa
        (b'retry-after'                 , b''             ),  # noqa
        (b'server'                      , b''             ),  # noqa
        (b'set-cookie'                  , b''             ),  # noqa
        (b'strict-transport-security'   , b''             ),  # noqa
        (b'transfer-encoding'           , b''             ),  # noqa
        (b'user-agent'                  , b''             ),  # noqa
        (b'vary'                        , b''             ),  # noqa
        (b'via'                         , b''             ),  # noqa
        (b'www-authenticate'            , b''             ),  # noqa
    )  # noqa

    STATIC_TABLE_LENGTH = len(STATIC_TABLE)

    STATIC_TABLE_MAPPING: dict[bytes, tuple[int, dict[bytes, int]]]

    def __init__(self) -> None:
        self._maxsize = HeaderTable.DEFAULT_SIZE
        self._current_size = 0
        self.resized = False
        self.dynamic_entries: deque[tuple[bytes, bytes]] = deque()

    def get_by_index(self, index: int) -> tuple[bytes, bytes]:
        """
        Returns the entry specified by index

        Note that the table is 1-based ie an index of 0 is
        invalid.  This is due to the fact that a zero value
        index signals that a completely unindexed header
        follows.

        The entry will either be from the static table or
        the dynamic table depending on the value of index.
        """
        original_index = index
        index -= 1
        if 0 <= index:
            if index < HeaderTable.STATIC_TABLE_LENGTH:
                return HeaderTable.STATIC_TABLE[index]

            index -= HeaderTable.STATIC_TABLE_LENGTH
            if index < len(self.dynamic_entries):
                return self.dynamic_entries[index]

        raise InvalidTableIndex("Invalid table index %d" % original_index)

    def __repr__(self) -> str:
        return "HeaderTable(%d, %s, %r)" % (
            self._maxsize,
            self.resized,
            self.dynamic_entries
        )

    def add(self, name: bytes, value: bytes) -> None:
        """
        Adds a new entry to the table

        We reduce the table size if the entry will make the
        table size greater than maxsize.
        """
        # We just clear the table if the entry is too big
        size = table_entry_size(name, value)
        if size > self._maxsize:
            self.dynamic_entries.clear()
            self._current_size = 0
        else:
            # Add new entry
            self.dynamic_entries.appendleft((name, value))
            self._current_size += size
            self._shrink()

    def search(self, name: bytes, value: bytes) -> Optional[tuple[int, bytes, Optional[bytes]]]:
        """
        Searches the table for the entry specified by name
        and value

        Returns one of the following:
            - ``None``, no match at all
            - ``(index, name, None)`` for partial matches on name only.
            - ``(index, name, value)`` for perfect matches.
        """
        partial = None

        header_name_search_result = HeaderTable.STATIC_TABLE_MAPPING.get(name)
        if header_name_search_result:
            index = header_name_search_result[1].get(value)
            if index is not None:
                return index, name, value
            else:
                partial = (header_name_search_result[0], name, None)

        offset = HeaderTable.STATIC_TABLE_LENGTH + 1
        for (i, (n, v)) in enumerate(self.dynamic_entries):
            if n == name:
                if v == value:
                    return i + offset, n, v
                elif partial is None:
                    partial = (i + offset, n, None)
        return partial

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @maxsize.setter
    def maxsize(self, newmax: int) -> None:
        newmax = int(newmax)
        _hpack_table_log.debug("Resizing header table to %d from %d", newmax, self._maxsize)
        oldmax = self._maxsize
        self._maxsize = newmax
        self.resized = (newmax != oldmax)
        if newmax <= 0:
            self.dynamic_entries.clear()
            self._current_size = 0
        elif oldmax > newmax:
            self._shrink()

    def _shrink(self) -> None:
        """
        Shrinks the dynamic table to be at or below maxsize
        """
        cursize = self._current_size
        while cursize > self._maxsize:
            name, value = self.dynamic_entries.pop()
            cursize -= table_entry_size(name, value)
            _hpack_table_log.debug("Evicting %s: %s from the header table", name, value)
        self._current_size = cursize


def _build_static_table_mapping() -> dict[bytes, tuple[int, dict[bytes, int]]]:
    """
    Build static table mapping from header name to tuple with next structure:
    (<minimal index of header>, <mapping from header value to it index>).

    static_table_mapping used for hash searching.
    """
    static_table_mapping: dict[bytes, tuple[int, dict[bytes, int]]] = {}
    for index, (name, value) in enumerate(HeaderTable.STATIC_TABLE, 1):
        header_name_search_result = static_table_mapping.setdefault(name, (index, {}))
        header_name_search_result[1][value] = index
    return static_table_mapping


HeaderTable.STATIC_TABLE_MAPPING = _build_static_table_mapping()


# ---------------------------------------------------------------------------
# hpack/hpack.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
Implements the HPACK header compression algorithm as detailed by RFC 7541.
"""

import logging
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Iterable  # pragma: no cover

_hpack_hpack_log = logging.getLogger('hpack.hpack')

INDEX_NONE = b"\x00"
INDEX_NEVER = b"\x10"
INDEX_INCREMENTAL = b"\x40"

VARINT_MAX_LENGTH = 5 # octets, enough for encoding prefix + uint32

# Precompute 2^i for 1-8 for use in prefix calcs.
# Zero index is not used but there to save a subtraction
# as prefix numbers are not zero indexed.
_PREFIX_BIT_MAX_NUMBERS = [(2 ** i) - 1 for i in range(9)]

# We default the maximum header list we're willing to accept to 64kB. That's a
# lot of headers, but if applications want to raise it they can do.
DEFAULT_MAX_HEADER_LIST_SIZE = 2 ** 16


def _unicode_if_needed(header: HeaderWeaklyTyped, raw: bool) -> HeaderTuple:
    """
    Provides a header as a unicode string if raw is False, otherwise returns
    it as a bytestring.
    """
    name = bytes(header[0])  # type: ignore
    value = bytes(header[1])  # type: ignore

    if not raw:
        return header.__class__(name.decode("utf-8"), value.decode("utf-8"))  # type: ignore
    return header.__class__(name, value)  # type: ignore


def encode_integer(integer: int, prefix_bits: int) -> bytearray:
    """
    Encodes an integer according to the wacky integer encoding rules
    defined in the HPACK spec.
    """
    _hpack_hpack_log.debug("Encoding %d with %d bits", integer, prefix_bits)

    if integer < 0:
        msg = f"Can only encode positive integers, got {integer}"
        raise ValueError(msg)

    if prefix_bits < 1 or prefix_bits > 8:
        msg = f"Prefix bits must be between 1 and 8, got {prefix_bits}"
        raise ValueError(msg)

    max_number = _PREFIX_BIT_MAX_NUMBERS[prefix_bits]

    if integer < max_number:
        return bytearray([integer])  # Seriously?
    elements = [max_number]
    integer -= max_number

    while integer >= 128:
        elements.append((integer & 127) + 128)
        integer >>= 7

    elements.append(integer)

    return bytearray(elements)


def decode_integer(data: bytes | memoryview, prefix_bits: int) -> tuple[int, int]:
    """
    Decodes an integer according to the wacky integer encoding rules
    defined in the HPACK spec. Returns a tuple of the decoded integer and the
    number of bytes that were consumed from ``data`` in order to get that
    integer.
    """
    if prefix_bits < 1 or prefix_bits > 8:
        msg = f"Prefix bits must be between 1 and 8, got {prefix_bits}"
        raise ValueError(msg)

    max_number = _PREFIX_BIT_MAX_NUMBERS[prefix_bits]
    index = 1
    shift = 0
    mask = (0xFF >> (8 - prefix_bits))

    try:
        number = data[0] & mask
        if number == max_number:
            while True:
                next_byte = data[index]
                index += 1

                if next_byte >= 128:
                    number += (next_byte - 128) << shift
                else:
                    number += next_byte << shift
                    break
                shift += 7

                if index > VARINT_MAX_LENGTH:  # sanity check to prevent infinite loops
                    # We have consumed more than enough bytes for a typical unsigned integer.
                    # The maximum size is not defined in HPACK RFC7541 Section 5.1:
                    #   > This integer representation allows for values of indefinite size.  It
                    #   > is also possible for an encoder to send a large number of zero
                    #   > values, which can waste octets and could be used to overflow integer
                    #   > values.  Integer encodings that exceed implementation limits -- in
                    #   > value or octet length -- MUST be treated as decoding errors.
                    msg = f"Variable integer representation is too long: {data!r}"
                    raise HPACKDecodingError(msg)

    except IndexError as err:
        msg = f"Unable to decode HPACK integer representation from {data!r}"
        raise HPACKDecodingError(msg) from err

    _hpack_hpack_log.debug("Decoded %d, consumed %d bytes", number, index)

    return number, index


def _dict_to_iterable(header_dict: dict[bytes | str, bytes | str]) \
        -> Iterable[tuple[bytes | str, bytes | str]]:
    """
    Converts a dictionary to an iterable of key-value tuples. This is a
    HPACK-specific function because it pulls "special-headers" out first and
    then emits them.
    """
    if not isinstance(header_dict, dict):  # pragma: no cover
        msg = f"header_dict not a dict, but {type(header_dict)}"
        raise TypeError(msg)

    keys = sorted(
        header_dict.keys(),
        key=lambda k: not _hpack_hpack_to_bytes(k).startswith(b":"),
    )
    for key in keys:
        yield key, header_dict[key]


def _hpack_hpack_to_bytes(value: bytes | str | Any) -> bytes:
    """
    Convert anything to bytes through a UTF-8 encoded string
    """
    t = type(value)
    if t is bytes:
        return value  # type: ignore
    if t is not str:
        value = str(value)
    return value.encode("utf-8")  # type: ignore


class Encoder:
    """
    An HPACK encoder object. This object takes HTTP headers and emits encoded
    HTTP/2 header blocks.
    """

    def __init__(self) -> None:
        self.header_table = HeaderTable()
        self.huffman_coder = HuffmanEncoder(
            REQUEST_CODES, REQUEST_CODES_LENGTH,
        )
        self.table_size_changes: list[int] = []

    @property
    def header_table_size(self) -> int:
        """
        Controls the size of the HPACK header table.
        """
        return self.header_table.maxsize

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self.header_table.maxsize = value
        if self.header_table.resized:
            self.table_size_changes.append(value)

    def encode(self,
               headers: Iterable[\
                   HeaderTuple | \
                   tuple[bytes | str, bytes | str] | \
                   tuple[bytes | str, bytes | str, bool | None]] | \
                   dict[bytes | str, bytes | str],
               huffman: bool = True) -> bytes:
        """
        Takes a set of headers and encodes them into a HPACK-encoded header
        block.

        :param headers: The headers to encode. Must be either an iterable of
                        tuples, an iterable of :class:`HeaderTuple
                        <hpack.HeaderTuple>`, or a ``dict``.

                        If an iterable of tuples, the tuples may be either
                        two-tuples or three-tuples. If they are two-tuples, the
                        tuples must be of the format ``(name, value)``. If they
                        are three-tuples, they must be of the format
                        ``(name, value, sensitive)``, where ``sensitive`` is a
                        boolean value indicating whether the header should be
                        added to header tables anywhere. If not present,
                        ``sensitive`` defaults to ``False``.

                        If an iterable of :class:`HeaderTuple
                        <hpack.HeaderTuple>`, the tuples must always be
                        two-tuples. Instead of using ``sensitive`` as a third
                        tuple entry, use :class:`NeverIndexedHeaderTuple
                        <hpack.NeverIndexedHeaderTuple>` to request that
                        the field never be indexed.

                        .. warning:: HTTP/2 requires that all special headers
                            (headers whose names begin with ``:`` characters)
                            appear at the *start* of the header block. While
                            this method will ensure that happens for ``dict``
                            subclasses, callers using any other iterable of
                            tuples **must** ensure they place their special
                            headers at the start of the iterable.

                            For efficiency reasons users should prefer to use
                            iterables of two-tuples: fixing the ordering of
                            dictionary headers is an expensive operation that
                            should be avoided if possible.

        :param huffman: (optional) Whether to Huffman-encode any header sent as
                        a literal value. Except for use when debugging, it is
                        recommended that this be left enabled.

        :returns: A bytestring containing the HPACK-encoded header block.
        """
        # Transforming the headers into a header block is a procedure that can
        # be modeled as a chain or pipe. First, the headers are encoded. This
        # encoding can be done a number of ways. If the header name-value pair
        # are already in the header table we can represent them using the
        # indexed representation: the same is true if they are in the static
        # table. Otherwise, a literal representation will be used.
        header_block = []

        # Before we begin, if the header table size has been changed we need
        # to signal all changes since last emission appropriately.
        if self.header_table.resized:
            header_block.append(self._encode_table_size_change())
            self.header_table.resized = False

        if isinstance(headers, dict):
            # Turn the headers into a list of tuples if possible. This is the
            # natural way to interact with them in HPACK. Because dictionaries are
            # un-ordered, we need to make sure we grab the "special" headers first.
            hpack_headers = _dict_to_iterable(headers)
        else:
            """
            Assume headers is an iterable of HeaderTuples, or plain 2-tuples, or plain 3-tuples:

            examples:
            [
                HeaderTuple(':method', 'GET'),
                NeverIndexedHeaderTuple('customkey', 'sensitiveinfo'),
            ]
            or
            [
                (':method', 'GET'),
                ('customkey', 'some-data'),
            ]
            or
            [
                (':method', 'GET', True),
                ('customkey', 'sensitiveinfo', True),
            ]
            """
            hpack_headers = iter(headers)  # type: ignore

        # Add each header to the header block
        for header in hpack_headers:
            sensitive = False
            if isinstance(header, HeaderTuple):
                # HeaderTuple implies it's a 2-tuple with the sensitive information stored as instance attribute
                sensitive = not header.indexable
            elif len(header) > 2:
                sensitive = header[2]

            new_header = (_hpack_hpack_to_bytes(header[0]), _hpack_hpack_to_bytes(header[1]))
            header_block.append(self.add(new_header, sensitive, huffman))

        encoded = b"".join(header_block)

        _hpack_hpack_log.debug("Encoded header block to %s", encoded)

        return encoded

    def add(self, to_add: tuple[bytes, bytes], sensitive: bool, huffman: bool = False) -> bytes:
        """
        Serializes a header key-value tuple.

        When sensitive is True, the header will not be added to the header table
        (see https://www.rfc-editor.org/rfc/rfc7541.html#section-7.1.3 for details),
        furthermore, the header value will be redacted in debug logs, as "SENSITIVE_REDACTED",
        to prevent accidental exposure of sensitive information.
        """
        name, value = to_add

        display_value = value if not sensitive else b"SENSITIVE_REDACTED"
        _hpack_hpack_log.debug(
            "Adding %s=%s to the header table, sensitive:%s, huffman:%s",
            name,
            display_value,
            sensitive,
            huffman,
        )

        # Set our indexing mode
        indexbit = INDEX_INCREMENTAL if not sensitive else INDEX_NEVER

        # Search for a matching header in the header table.
        match = self.header_table.search(name, value)

        if match is None:
            # Not in the header table. Encode using the literal syntax,
            # and add it to the header table.
            encoded = self._encode_literal(name, value, indexbit, huffman)
            if not sensitive:
                self.header_table.add(name, value)
            return encoded

        # The header is in the table, break out the values. If we matched
        # perfectly, we can use the indexed representation: otherwise we
        # can use the indexed literal.
        index, name, perfect = match

        if perfect is not None:
            # Indexed representation.
            encoded = self._encode_indexed(index)
        else:
            # Indexed literal. We are going to add header to the
            # header table unconditionally. It is a future todo to
            # filter out headers which are known to be ineffective for
            # indexing since they just take space in the table and
            # pushed out other valuable headers.
            encoded = self._encode_indexed_literal(
                index, value, indexbit, huffman,
            )
            if not sensitive:
                self.header_table.add(name, value)

        return encoded

    def _encode_indexed(self, index: int) -> bytes:
        """
        Encodes a header using the indexed representation.
        """
        field = encode_integer(index, 7)
        field[0] |= 0x80  # we set the top bit
        return bytes(field)

    def _encode_literal(self, name: bytes, value: bytes, indexbit: bytes, huffman: bool = False) -> bytes:
        """
        Encodes a header with a literal name and literal value. If ``indexing``
        is True, the header will be added to the header table: otherwise it
        will not.
        """
        if huffman:
            name = self.huffman_coder.encode(name)
            value = self.huffman_coder.encode(value)

        name_len = encode_integer(len(name), 7)
        value_len = encode_integer(len(value), 7)

        if huffman:
            name_len[0] |= 0x80
            value_len[0] |= 0x80

        return b"".join(
            [indexbit, bytes(name_len), name, bytes(value_len), value],
        )

    def _encode_indexed_literal(self, index: int, value: bytes, indexbit: bytes, huffman: bool = False) -> bytes:
        """
        Encodes a header with an indexed name and a literal value and performs
        incremental indexing.
        """
        if indexbit != INDEX_INCREMENTAL:
            prefix = encode_integer(index, 4)
        else:
            prefix = encode_integer(index, 6)

        prefix[0] |= ord(indexbit)

        if huffman:
            value = self.huffman_coder.encode(value)

        value_len = encode_integer(len(value), 7)

        if huffman:
            value_len[0] |= 0x80

        return b"".join([bytes(prefix), bytes(value_len), value])

    def _encode_table_size_change(self) -> bytes:
        """
        Produces the encoded form of all header table size change context
        updates.
        """
        block = b""
        for size_bytes in self.table_size_changes:
            b = encode_integer(size_bytes, 5)
            b[0] |= 0x20
            block += bytes(b)
        self.table_size_changes = []
        return block


class Decoder:
    """
    An HPACK decoder object.

    .. versionchanged:: 2.3.0
       Added ``max_header_list_size`` argument.

    :param max_header_list_size: The maximum decompressed size we will allow
        for any single header block. This is a protection against DoS attacks
        that attempt to force the application to expand a relatively small
        amount of data into a really large header list, allowing enormous
        amounts of memory to be allocated.

        If this amount of data is exceeded, a `OversizedHeaderListError
        <hpack.OversizedHeaderListError>` exception will be raised. At this
        point the connection should be shut down, as the HPACK state will no
        longer be usable.

        Defaults to 64kB.
    :type max_header_list_size: ``int``
    """

    def __init__(self, max_header_list_size: int = DEFAULT_MAX_HEADER_LIST_SIZE) -> None:
        self.header_table = HeaderTable()

        #: The maximum decompressed size we will allow for any single header
        #: block. This is a protection against DoS attacks that attempt to
        #: force the application to expand a relatively small amount of data
        #: into a really large header list, allowing enormous amounts of memory
        #: to be allocated.
        #:
        #: If this amount of data is exceeded, a `OversizedHeaderListError
        #: <hpack.OversizedHeaderListError>` exception will be raised. At this
        #: point the connection should be shut down, as the HPACK state will no
        #: longer be usable.
        #:
        #: Defaults to 64kB.
        #:
        #: .. versionadded:: 2.3.0
        self.max_header_list_size = max_header_list_size

        #: Maximum allowed header table size.
        #:
        #: A HTTP/2 implementation should set this to the most recent value of
        #: SETTINGS_HEADER_TABLE_SIZE that it sent *and has received an ACK
        #: for*. Once this setting is set, the actual header table size will be
        #: checked at the end of each decoding run and whenever it is changed,
        #: to confirm that it fits in this size.
        self.max_allowed_table_size = self.header_table.maxsize

    @property
    def header_table_size(self) -> int:
        """
        Controls the size of the HPACK header table.
        """
        return self.header_table.maxsize

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self.header_table.maxsize = value

    def decode(self, data: bytes, raw: bool = False) -> Iterable[HeaderTuple]:
        """
        Takes an HPACK-encoded header block and decodes it into a header set.

        :param data: A bytestring representing a complete HPACK-encoded header
                     block.
        :param raw: (optional) Whether to return the headers as tuples of raw
                    byte strings or to decode them as UTF-8 before returning
                    them. The default value is False, which returns tuples of
                    Unicode strings
        :returns: A list of two-tuples of ``(name, value)`` representing the
                  HPACK-encoded headers, in the order they were decoded.
        :raises HPACKDecodingError: If an error is encountered while decoding
                                    the header block.
        """
        _hpack_hpack_log.debug("Decoding %s", data)

        data_mem = memoryview(data)
        headers: list[HeaderTuple] = []
        data_len = len(data)
        inflated_size = 0
        current_index = 0

        while current_index < data_len:
            # Work out what kind of header we're decoding.
            # If the high bit is 1, it's an indexed field.
            current = data[current_index]
            indexed = bool(current & 0x80)

            # Otherwise, if the second-highest bit is 1 it's a field that does
            # alter the header table.
            literal_index = bool(current & 0x40)

            # Otherwise, if the third-highest bit is 1 it's an encoding context
            # update.
            encoding_update = bool(current & 0x20)

            if indexed:
                header, consumed = self._decode_indexed(
                    data_mem[current_index:],
                )
            elif literal_index:
                # It's a literal header that does affect the header table.
                header, consumed = self._decode_literal_index(
                    data_mem[current_index:],
                )
            elif encoding_update:
                # It's an update to the encoding context. These are forbidden
                # in a header block after any actual header.
                if headers:
                    msg = "Table size update not at the start of the block"
                    raise HPACKDecodingError(msg)
                consumed = self._update_encoding_context(
                    data_mem[current_index:],
                )
                header = None
            else:
                # It's a literal header that does not affect the header table.
                header, consumed = self._decode_literal_no_index(
                    data_mem[current_index:],
                )

            if header:
                headers.append(header)
                inflated_size += table_entry_size(header[0], header[1])

                if inflated_size > self.max_header_list_size:
                    msg = f"A header list larger than {self.max_header_list_size} has been received"
                    raise OversizedHeaderListError(msg)

            current_index += consumed

        # Confirm that the table size is lower than the maximum. We do this
        # here to ensure that we catch when the max has been *shrunk* and the
        # remote peer hasn't actually done that.
        self._assert_valid_table_size()

        try:
            return [_unicode_if_needed(h, raw) for h in headers]
        except UnicodeDecodeError as err:
            msg = "Unable to decode headers as UTF-8"
            raise HPACKDecodingError(msg) from err

    def _assert_valid_table_size(self) -> None:
        """
        Check that the table size set by the encoder is lower than the maximum
        we expect to have.
        """
        if self.header_table_size > self.max_allowed_table_size:
            msg = "Encoder did not shrink table size to within the max"
            raise InvalidTableSizeError(msg)

    def _update_encoding_context(self, data: bytes | memoryview) -> int:
        """
        Handles a byte that updates the encoding context.
        """
        # We've been asked to resize the header table.
        new_size, consumed = decode_integer(data, 5)
        if new_size > self.max_allowed_table_size:
            msg = "Encoder exceeded max allowable table size"
            raise InvalidTableSizeError(msg)
        self.header_table_size = new_size
        return consumed

    def _decode_indexed(self, data: bytes | memoryview) -> tuple[HeaderTuple, int]:
        """
        Decodes a header represented using the indexed representation.
        """
        index, consumed = decode_integer(data, 7)
        header = HeaderTuple(*self.header_table.get_by_index(index))
        _hpack_hpack_log.debug("Decoded %s, consumed %d", header, consumed)
        return header, consumed

    def _decode_literal_no_index(self, data: bytes | memoryview) -> tuple[HeaderTuple, int]:
        return self._decode_literal(data, should_index=False)

    def _decode_literal_index(self, data: bytes | memoryview) -> tuple[HeaderTuple, int]:
        return self._decode_literal(data, should_index=True)

    def _decode_literal(self, data: bytes | memoryview, should_index: bool) -> tuple[HeaderTuple, int]:
        """
        Decodes a header represented with a literal.
        """
        if isinstance(data, memoryview):
            data = data.tobytes()  # pragma: no cover

        total_consumed = 0

        # When should_index is true, if the low six bits of the first byte are
        # nonzero, the header name is indexed.
        # When should_index is false, if the low four bits of the first byte
        # are nonzero the header name is indexed.
        if should_index:
            indexed_name = data[0] & 0x3F
            name_len = 6
            not_indexable = False
        else:
            high_byte = data[0]
            indexed_name = high_byte & 0x0F
            name_len = 4
            not_indexable = bool(high_byte & 0x10)

        if indexed_name:
            # Indexed header name.
            index, consumed = decode_integer(data, name_len)
            name = self.header_table.get_by_index(index)[0]

            total_consumed = consumed
            length = 0
        else:
            # Literal header name. The first byte was consumed, so we need to
            # move forward.
            data = data[1:]

            length, consumed = decode_integer(data, 7)
            name = data[consumed:consumed + length]
            if len(name) != length:
                msg = "Truncated header block"
                raise HPACKDecodingError(msg)

            if data[0] & 0x80:
                name = decode_huffman(name)
            total_consumed = consumed + length + 1  # Since we moved forward 1.

        data = data[consumed + length:]

        # The header value is definitely length-based.
        length, consumed = decode_integer(data, 7)
        value = data[consumed:consumed + length]
        if len(value) != length:
            msg = "Truncated header block"
            raise HPACKDecodingError(msg)

        if data[0] & 0x80:
            value = decode_huffman(value)

        # Updated the total consumed length.
        total_consumed += length + consumed

        # If we have been told never to index the header field, encode that in
        # the tuple we use.
        header: HeaderTuple
        if not_indexable:
            header = NeverIndexedHeaderTuple(name, value)
        else:
            header = HeaderTuple(name, value)

        # If we've been asked to index this, add it to the header table.
        if should_index:
            self.header_table.add(name, value)

        _hpack_hpack_log.debug(
            "Decoded %s, total consumed %d bytes, indexed %s",
            header,
            total_consumed,
            should_index,
        )

        return header, total_consumed


# ---------------------------------------------------------------------------
# hpack/__init__.py  (hpack 4.2.0)
# ---------------------------------------------------------------------------

"""
HTTP/2 header encoding for Python.
"""


# ---------------------------------------------------------------------------
# h2/__init__.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
HTTP/2 protocol implementation for Python.
"""


# ---------------------------------------------------------------------------
# h2/_typing.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/_typing
~~~~~~~~~~

Shared typing helpers.
"""

from typing import Protocol


class Buffer(Protocol):
    """
    An object implementing the PEP 688 buffer protocol.
    """

    def __buffer__(self, flags: int, /) -> memoryview:
        """
        Return a memoryview over this object's bytes.
        """
        ...


# ---------------------------------------------------------------------------
# h2/config.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/config
~~~~~~~~~

Objects for controlling the configuration of the HTTP/2 stack.
"""

import sys
from typing import Any


class _BooleanConfigOption:
    """
    Descriptor for handling a boolean config option.  This will block
    attempts to set boolean config options to non-bools.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.attr_name = f"_{self.name}"

    def __get__(self, instance: Any, owner: Any) -> bool:
        return getattr(instance, self.attr_name)  # type: ignore

    def __set__(self, instance: Any, value: bool) -> None:
        if not isinstance(value, bool):
            msg = f"{self.name} must be a bool"
            raise ValueError(msg)  # noqa: TRY004
        setattr(instance, self.attr_name, value)


class DummyLogger:
    """
    A Logger object that does not actual logging, hence a DummyLogger.

    For the class the log operation is merely a no-op. The intent is to avoid
    conditionals being sprinkled throughout the h2 code for calls to
    logging functions when no logger is passed into the corresponding object.
    """

    def __init__(self, *vargs) -> None:  # type: ignore
        pass

    def debug(self, *vargs, **kwargs) -> None:  # type: ignore
        """
        No-op logging. Only level needed for now.
        """

    def trace(self, *vargs, **kwargs) -> None:  # type: ignore
        """
        No-op logging. Only level needed for now.
        """


class OutputLogger:
    """
    A Logger object that prints to stderr or any other file-like object.

    This class is provided for convenience and not part of the stable API.

    :param file: A file-like object passed to the print function.
        Defaults to ``sys.stderr``.
    :param trace: Enables trace-level output. Defaults to ``False``.
    """

    def __init__(self, file=None, trace_level=False) -> None:  # type: ignore
        super().__init__()
        self.file = file or sys.stderr
        self.trace_level = trace_level

    def debug(self, fmtstr, *args) -> None:  # type: ignore
        print(f"h2 (debug): {fmtstr % args}", file=self.file)

    def trace(self, fmtstr, *args) -> None:  # type: ignore
        if self.trace_level:
            print(f"h2 (trace): {fmtstr % args}", file=self.file)


class H2Configuration:
    """
    An object that controls the way a single HTTP/2 connection behaves.

    This object allows the users to customize behaviour. In particular, it
    allows users to enable or disable optional features, or to otherwise handle
    various unusual behaviours.

    This object has very little behaviour of its own: it mostly just ensures
    that configuration is self-consistent.

    :param client_side: Whether this object is to be used on the client side of
        a connection, or on the server side. Affects the logic used by the
        state machine, the default settings values, the allowable stream IDs,
        and several other properties. Defaults to ``True``.
    :type client_side: ``bool``

    :param header_encoding: Controls whether the headers emitted by this object
        in events are transparently decoded to ``unicode`` strings, and what
        encoding is used to do that decoding. This defaults to ``None``,
        meaning that headers will be returned as bytes. To automatically
        decode headers (that is, to return them as unicode strings), this can
        be set to the string name of any encoding, e.g. ``'utf-8'``.

        .. versionchanged:: 3.0.0
           Changed default value from ``'utf-8'`` to ``None``

    :type header_encoding: ``str``, ``False``, or ``None``

    :param validate_outbound_headers: Controls whether the headers emitted
        by this object are validated against the rules in RFC 7540.
        Disabling this setting will cause outbound header validation to
        be skipped, and allow the object to emit headers that may be illegal
        according to RFC 7540. Defaults to ``True``.
    :type validate_outbound_headers: ``bool``

    :param normalize_outbound_headers: Controls whether the headers emitted
        by this object are normalized before sending.  Disabling this setting
        will cause outbound header normalization to be skipped, and allow
        the object to emit headers that may be illegal according to
        RFC 7540. Defaults to ``True``.
    :type normalize_outbound_headers: ``bool``

    :param split_outbound_cookies: Controls whether the outbound cookie
        headers are split before sending or not. According to RFC 7540
        - 8.1.2.5 the outbound header cookie headers may be split to improve
        headers compression. Default is ``False``.
    :type split_outbound_cookies: ``bool``

    :param validate_inbound_headers: Controls whether the headers received
        by this object are validated against the rules in RFC 7540.
        Disabling this setting will cause inbound header validation to
        be skipped, and allow the object to receive headers that may be illegal
        according to RFC 7540. Defaults to ``True``.
    :type validate_inbound_headers: ``bool``

    :param normalize_inbound_headers: Controls whether the headers received by
        this object are normalized according to the rules of RFC 7540.
        Disabling this setting may lead to h2 emitting header blocks that
        some RFCs forbid, e.g. with multiple cookie fields.

        .. versionadded:: 3.0.0

    :type normalize_inbound_headers: ``bool``

    :param logger: A logger that conforms to the requirements for this module,
        those being no I/O and no context switches, which is needed in order
        to run in asynchronous operation.

        .. versionadded:: 2.6.0

    :type logger: ``logging.Logger``
    """

    client_side = _BooleanConfigOption("client_side")
    validate_outbound_headers = _BooleanConfigOption(
        "validate_outbound_headers",
    )
    normalize_outbound_headers = _BooleanConfigOption(
        "normalize_outbound_headers",
    )
    split_outbound_cookies = _BooleanConfigOption(
        "split_outbound_cookies",
    )
    validate_inbound_headers = _BooleanConfigOption(
        "validate_inbound_headers",
    )
    normalize_inbound_headers = _BooleanConfigOption(
        "normalize_inbound_headers",
    )

    def __init__(self,
                 client_side: bool = True,
                 header_encoding: bool | str | None = None,
                 validate_outbound_headers: bool = True,
                 normalize_outbound_headers: bool = True,
                 split_outbound_cookies: bool = False,
                 validate_inbound_headers: bool = True,
                 normalize_inbound_headers: bool = True,
                 logger: DummyLogger | OutputLogger | None = None) -> None:
        self.client_side = client_side
        self.header_encoding = header_encoding
        self.validate_outbound_headers = validate_outbound_headers
        self.normalize_outbound_headers = normalize_outbound_headers
        self.split_outbound_cookies = split_outbound_cookies
        self.validate_inbound_headers = validate_inbound_headers
        self.normalize_inbound_headers = normalize_inbound_headers
        self.logger = logger or DummyLogger('h2.config')

    @property
    def header_encoding(self) -> bool | str | None:
        """
        Controls whether the headers emitted by this object in events are
        transparently decoded to ``unicode`` strings, and what encoding is used
        to do that decoding. This defaults to ``None``, meaning that headers
        will be returned as bytes. To automatically decode headers (that is, to
        return them as unicode strings), this can be set to the string name of
        any encoding, e.g. ``'utf-8'``.
        """
        return self._header_encoding

    @header_encoding.setter
    def header_encoding(self, value: bool | str | None) -> None:
        """
        Enforces constraints on the value of header encoding.
        """
        if not isinstance(value, (bool, str, type(None))):
            msg = "header_encoding must be bool, string, or None"
            raise ValueError(msg)  # noqa: TRY004
        if value is True:
            msg = "header_encoding cannot be True"
            raise ValueError(msg)
        self._header_encoding = value


# ---------------------------------------------------------------------------
# h2/errors.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/errors
~~~~~~~~~

Global error code registry containing the established HTTP/2 error codes.

The current registry is available at:
https://tools.ietf.org/html/rfc7540#section-11.4
"""

import enum


class ErrorCodes(enum.IntEnum):
    """
    All known HTTP/2 error codes.

    .. versionadded:: 2.5.0
    """

    #: Graceful shutdown.
    NO_ERROR = 0x0

    #: Protocol error detected.
    PROTOCOL_ERROR = 0x1

    #: Implementation fault.
    INTERNAL_ERROR = 0x2

    #: Flow-control limits exceeded.
    FLOW_CONTROL_ERROR = 0x3

    #: Settings not acknowledged.
    SETTINGS_TIMEOUT = 0x4

    #: Frame received for closed stream.
    STREAM_CLOSED = 0x5

    #: Frame size incorrect.
    FRAME_SIZE_ERROR = 0x6

    #: Stream not processed.
    REFUSED_STREAM = 0x7

    #: Stream cancelled.
    CANCEL = 0x8

    #: Compression state not updated.
    COMPRESSION_ERROR = 0x9

    #: TCP connection error for CONNECT method.
    CONNECT_ERROR = 0xa

    #: Processing capacity exceeded.
    ENHANCE_YOUR_CALM = 0xb

    #: Negotiated TLS parameters not acceptable.
    INADEQUATE_SECURITY = 0xc

    #: Use HTTP/1.1 for the request.
    HTTP_1_1_REQUIRED = 0xd


def _error_code_from_int(code: int) -> ErrorCodes | int:
    """
    Given an integer error code, returns either one of :class:`ErrorCodes
    <h2.errors.ErrorCodes>` or, if not present in the known set of codes,
    returns the integer directly.
    """
    try:
        return ErrorCodes(code)
    except ValueError:
        return code


# ---------------------------------------------------------------------------
# h2/exceptions.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/exceptions
~~~~~~~~~~~~~

Exceptions for the HTTP/2 module.
"""


class H2Error(Exception):
    """
    The base class for all exceptions for the HTTP/2 module.
    """


class ProtocolError(H2Error):
    """
    An action was attempted in violation of the HTTP/2 protocol.
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.PROTOCOL_ERROR


class FrameTooLargeError(ProtocolError):
    """
    The frame that we tried to send or that we received was too large.
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.FRAME_SIZE_ERROR


class FrameDataMissingError(ProtocolError):
    """
    The frame that we received is missing some data.

    .. versionadded:: 2.0.0
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.FRAME_SIZE_ERROR


class TooManyStreamsError(ProtocolError):
    """
    An attempt was made to open a stream that would lead to too many concurrent
    streams.
    """


class FlowControlError(ProtocolError):
    """
    An attempted action violates flow control constraints.
    """

    #: The error code corresponds to this kind of Protocol Error.
    error_code = ErrorCodes.FLOW_CONTROL_ERROR


class StreamIDTooLowError(ProtocolError):
    """
    An attempt was made to open a stream that had an ID that is lower than the
    highest ID we have seen on this connection.
    """

    def __init__(self, stream_id: int, max_stream_id: int) -> None:
        #: The ID of the stream that we attempted to open.
        self.stream_id = stream_id

        #: The current highest-seen stream ID.
        self.max_stream_id = max_stream_id

    def __str__(self) -> str:
        return f"StreamIDTooLowError: {self.stream_id} is lower than {self.max_stream_id}"


class NoAvailableStreamIDError(ProtocolError):
    """
    There are no available stream IDs left to the connection. All stream IDs
    have been exhausted.

    .. versionadded:: 2.0.0
    """


class NoSuchStreamError(ProtocolError):
    """
    A stream-specific action referenced a stream that does not exist.

    .. versionchanged:: 2.0.0
       Became a subclass of :class:`ProtocolError
       <h2.exceptions.ProtocolError>`
    """

    def __init__(self, stream_id: int) -> None:
        #: The stream ID corresponds to the non-existent stream.
        self.stream_id = stream_id


class StreamClosedError(NoSuchStreamError):
    """
    A more specific form of
    :class:`NoSuchStreamError <h2.exceptions.NoSuchStreamError>`. Indicates
    that the stream has since been closed, and that all state relating to that
    stream has been removed.
    """

    def __init__(self, stream_id: int) -> None:
        #: The stream ID corresponds to the nonexistent stream.
        self.stream_id = stream_id

        #: The relevant HTTP/2 error code.
        self.error_code = ErrorCodes.STREAM_CLOSED

        # Any events that internal code may need to fire. Not relevant to
        # external users that may receive a StreamClosedError.
        self._events = []  # type: ignore


class InvalidSettingsValueError(ProtocolError, ValueError):
    """
    An attempt was made to set an invalid Settings value.

    .. versionadded:: 2.0.0
    """

    def __init__(self, msg: str, error_code: ErrorCodes) -> None:
        super().__init__(msg)
        self.error_code = error_code


class InvalidBodyLengthError(ProtocolError):
    """
    The remote peer sent more or less data that the Content-Length header
    indicated.

    .. versionadded:: 2.0.0
    """

    def __init__(self, expected: int, actual: int) -> None:
        self.expected_length = expected
        self.actual_length = actual

    def __str__(self) -> str:
        return f"InvalidBodyLengthError: Expected {self.expected_length} bytes, received {self.actual_length}"


class UnsupportedFrameError(ProtocolError):
    """
    The remote peer sent a frame that is unsupported in this context.

    .. versionadded:: 2.1.0

    .. versionchanged:: 4.0.0
       Removed deprecated KeyError parent class.
    """


class RFC1122Error(H2Error):
    """
    Emitted when users attempt to do something that is literally allowed by the
    relevant RFC, but is sufficiently ill-defined that it's unwise to allow
    users to actually do it.

    While there is some disagreement about whether or not we should be liberal
    in what accept, it is a truth universally acknowledged that we should be
    conservative in what emit.

    .. versionadded:: 2.4.0
    """

    # shazow says I'm going to regret naming the exception this way. If that
    # turns out to be true, TELL HIM NOTHING.


class DenialOfServiceError(ProtocolError):
    """
    Emitted when the remote peer exhibits a behaviour that is likely to be an
    attempt to perform a Denial of Service attack on the implementation. This
    is a form of ProtocolError that carries a different error code, and allows
    more easy detection of this kind of behaviour.

    .. versionadded:: 2.5.0
    """

    #: The error code corresponds to this kind of
    #: :class:`ProtocolError <h2.exceptions.ProtocolError>`
    error_code = ErrorCodes.ENHANCE_YOUR_CALM


# ---------------------------------------------------------------------------
# h2/settings.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/settings
~~~~~~~~~~~

This module contains a HTTP/2 settings object. This object provides a simple
API for manipulating HTTP/2 settings, keeping track of both the current active
state of the settings and the unacknowledged future values of the settings.
"""

import collections
import enum
from collections.abc import Iterator, MutableMapping


class SettingCodes(enum.IntEnum):
    """
    All known HTTP/2 setting codes.

    .. versionadded:: 2.6.0
    """

    #: Allows the sender to inform the remote endpoint of the maximum size of
    #: the header compression table used to decode header blocks, in octets.
    HEADER_TABLE_SIZE = SettingsFrame.HEADER_TABLE_SIZE

    #: This setting can be used to disable server push. To disable server push
    #: on a client, set this to 0.
    ENABLE_PUSH = SettingsFrame.ENABLE_PUSH

    #: Indicates the maximum number of concurrent streams that the sender will
    #: allow.
    MAX_CONCURRENT_STREAMS = SettingsFrame.MAX_CONCURRENT_STREAMS

    #: Indicates the sender's initial window size (in octets) for stream-level
    #: flow control.
    INITIAL_WINDOW_SIZE = SettingsFrame.INITIAL_WINDOW_SIZE

    #: Indicates the size of the largest frame payload that the sender is
    #: willing to receive, in octets.
    MAX_FRAME_SIZE = SettingsFrame.MAX_FRAME_SIZE

    #: This advisory setting informs a peer of the maximum size of header list
    #: that the sender is prepared to accept, in octets.  The value is based on
    #: the uncompressed size of header fields, including the length of the name
    #: and value in octets plus an overhead of 32 octets for each header field.
    MAX_HEADER_LIST_SIZE = SettingsFrame.MAX_HEADER_LIST_SIZE

    #: This setting can be used to enable the connect protocol. To enable on a
    #: client set this to 1.
    ENABLE_CONNECT_PROTOCOL = SettingsFrame.ENABLE_CONNECT_PROTOCOL


def _setting_code_from_int(code: int) -> SettingCodes | int:
    """
    Given an integer setting code, returns either one of :class:`SettingCodes
    <h2.settings.SettingCodes>` or, if not present in the known set of codes,
    returns the integer directly.
    """
    try:
        return SettingCodes(code)
    except ValueError:
        return code


class ChangedSetting:

    def __init__(self, setting: SettingCodes | int, original_value: int | None, new_value: int) -> None:
        #: The setting code given. Either one of :class:`SettingCodes
        #: <h2.settings.SettingCodes>` or ``int``
        #:
        #: .. versionchanged:: 2.6.0
        self.setting = setting

        #: The original value before being changed.
        self.original_value = original_value

        #: The new value after being changed.
        self.new_value = new_value

    def __repr__(self) -> str:
        return (
            f"ChangedSetting(setting={self.setting!s}, original_value={self.original_value}, new_value={self.new_value})"
        )


class Settings(MutableMapping[SettingCodes | int, int]):
    """
    An object that encapsulates HTTP/2 settings state.

    HTTP/2 Settings are a complex beast. Each party, remote and local, has its
    own settings and a view of the other party's settings. When a settings
    frame is emitted by a peer it cannot assume that the new settings values
    are in place until the remote peer acknowledges the setting. In principle,
    multiple settings changes can be "in flight" at the same time, all with
    different values.

    This object encapsulates this mess. It provides a dict-like interface to
    settings, which return the *current* values of the settings in question.
    Additionally, it keeps track of the stack of proposed values: each time an
    acknowledgement is sent/received, it updates the current values with the
    stack of proposed values. On top of all that, it validates the values to
    make sure they're allowed, and raises :class:`InvalidSettingsValueError
    <h2.exceptions.InvalidSettingsValueError>` if they are not.

    Finally, this object understands what the default values of the HTTP/2
    settings are, and sets those defaults appropriately.

    .. versionchanged:: 2.2.0
       Added the ``initial_values`` parameter.

    .. versionchanged:: 2.5.0
       Added the ``max_header_list_size`` property.

    :param client: (optional) Whether these settings should be defaulted for a
        client implementation or a server implementation. Defaults to ``True``.
    :type client: ``bool``
    :param initial_values: (optional) Any initial values the user would like
        set, rather than RFC 7540's defaults.
    :type initial_vales: ``MutableMapping``
    """

    def __init__(self, client: bool = True, initial_values: dict[SettingCodes, int] | None = None) -> None:
        self._client = client

        # Backing object for the settings. This is a dictionary of
        # (setting: [list of values]), where the first value in the list is the
        # current value of the setting. Strictly this doesn't use lists but
        # instead uses collections.deque to avoid repeated memory allocations.
        #
        # This contains the default values for HTTP/2.
        self._settings: dict[SettingCodes | int, collections.deque[int]] = {
            SettingCodes.HEADER_TABLE_SIZE: collections.deque([4096]),
            SettingCodes.ENABLE_PUSH: collections.deque([int(client)]),
            SettingCodes.INITIAL_WINDOW_SIZE: collections.deque([65535]),
            SettingCodes.MAX_FRAME_SIZE: collections.deque([16384]),
            SettingCodes.ENABLE_CONNECT_PROTOCOL: collections.deque([0]),
        }
        if initial_values is not None:
            for key, value in initial_values.items():
                invalid = _validate_setting(key, value)
                if invalid:
                    msg = f"Setting {key} has invalid value {value}"
                    raise InvalidSettingsValueError(
                        msg,
                        error_code=invalid,
                    )
                self._settings[key] = collections.deque([value])

    def acknowledge(self) -> dict[SettingCodes | int, ChangedSetting]:
        """
        The settings have been acknowledged, either by the user (remote
        settings) or by the remote peer (local settings).

        :returns: A dict of {setting: ChangedSetting} that were applied.
        """
        changed_settings: dict[SettingCodes | int, ChangedSetting] = {}

        # If there is more than one setting in the list, we have a setting
        # value outstanding. Update them.
        for k, v in self._settings.items():
            if len(v) > 1:
                old_setting = v.popleft()
                new_setting = v[0]
                changed_settings[k] = ChangedSetting(
                    k, old_setting, new_setting,
                )

        return changed_settings

    # Provide easy-access to well known settings.
    @property
    def header_table_size(self) -> int:
        """
        The current value of the :data:`HEADER_TABLE_SIZE
        <h2.settings.SettingCodes.HEADER_TABLE_SIZE>` setting.
        """
        return self[SettingCodes.HEADER_TABLE_SIZE]

    @header_table_size.setter
    def header_table_size(self, value: int) -> None:
        self[SettingCodes.HEADER_TABLE_SIZE] = value

    @property
    def enable_push(self) -> int:
        """
        The current value of the :data:`ENABLE_PUSH
        <h2.settings.SettingCodes.ENABLE_PUSH>` setting.
        """
        return self[SettingCodes.ENABLE_PUSH]

    @enable_push.setter
    def enable_push(self, value: int) -> None:
        self[SettingCodes.ENABLE_PUSH] = value

    @property
    def initial_window_size(self) -> int:
        """
        The current value of the :data:`INITIAL_WINDOW_SIZE
        <h2.settings.SettingCodes.INITIAL_WINDOW_SIZE>` setting.
        """
        return self[SettingCodes.INITIAL_WINDOW_SIZE]

    @initial_window_size.setter
    def initial_window_size(self, value: int) -> None:
        self[SettingCodes.INITIAL_WINDOW_SIZE] = value

    @property
    def max_frame_size(self) -> int:
        """
        The current value of the :data:`MAX_FRAME_SIZE
        <h2.settings.SettingCodes.MAX_FRAME_SIZE>` setting.
        """
        return self[SettingCodes.MAX_FRAME_SIZE]

    @max_frame_size.setter
    def max_frame_size(self, value: int) -> None:
        self[SettingCodes.MAX_FRAME_SIZE] = value

    @property
    def max_concurrent_streams(self) -> int:
        """
        The current value of the :data:`MAX_CONCURRENT_STREAMS
        <h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS>` setting.
        """
        return self.get(SettingCodes.MAX_CONCURRENT_STREAMS, 2**32+1)

    @max_concurrent_streams.setter
    def max_concurrent_streams(self, value: int) -> None:
        self[SettingCodes.MAX_CONCURRENT_STREAMS] = value

    @property
    def max_header_list_size(self) -> int | None:
        """
        The current value of the :data:`MAX_HEADER_LIST_SIZE
        <h2.settings.SettingCodes.MAX_HEADER_LIST_SIZE>` setting. If not set,
        returns ``None``, which means unlimited.

        .. versionadded:: 2.5.0
        """
        return self.get(SettingCodes.MAX_HEADER_LIST_SIZE, None)

    @max_header_list_size.setter
    def max_header_list_size(self, value: int) -> None:
        self[SettingCodes.MAX_HEADER_LIST_SIZE] = value

    @property
    def enable_connect_protocol(self) -> int:
        """
        The current value of the :data:`ENABLE_CONNECT_PROTOCOL
        <h2.settings.SettingCodes.ENABLE_CONNECT_PROTOCOL>` setting.
        """
        return self[SettingCodes.ENABLE_CONNECT_PROTOCOL]

    @enable_connect_protocol.setter
    def enable_connect_protocol(self, value: int) -> None:
        self[SettingCodes.ENABLE_CONNECT_PROTOCOL] = value

    # Implement the MutableMapping API.
    def __getitem__(self, key: SettingCodes | int) -> int:
        val = self._settings[key][0]

        # Things that were created when a setting was received should stay
        # KeyError'd.
        if val is None:
            raise KeyError

        return val

    def __setitem__(self, key: SettingCodes | int, value: int) -> None:
        invalid = _validate_setting(key, value)
        if invalid:
            msg = f"Setting {key} has invalid value {value}"
            raise InvalidSettingsValueError(
                msg,
                error_code=invalid,
            )

        try:
            items = self._settings[key]
        except KeyError:
            items = collections.deque([None])  # type: ignore
            self._settings[key] = items

        items.append(value)

    def validate_received_setting(self, setting: SettingCodes | int, value: int) -> None:
        """
        Validate a setting received from the peer that owns this Settings
        object.

        Servers may advertise ``ENABLE_PUSH`` only as ``0`` in received
        SETTINGS frames.
        """
        invalid = _validate_setting(setting, value, client=self._client)

        if invalid != ErrorCodes.NO_ERROR:
            msg = f"Setting {setting} has invalid value {value}"
            raise InvalidSettingsValueError(
                msg,
                error_code=invalid,
            )

    def __delitem__(self, key: SettingCodes | int) -> None:
        del self._settings[key]

    def __iter__(self) -> Iterator[SettingCodes | int]:
        return self._settings.__iter__()

    def __len__(self) -> int:
        return len(self._settings)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Settings):
            return self._settings == other._settings
        return NotImplemented

    def __ne__(self, other: object) -> bool:
        if isinstance(other, Settings):
            return not self == other
        return NotImplemented

    # be explicit that Settings is not providing a hash implementation
    # see https://docs.python.org/3/reference/datamodel.html#object.__hash__
    __hash__ = MutableMapping.__hash__


def _validate_setting(
    setting: SettingCodes | int,
    value: int,
    *,
    client: bool | None = None,
) -> ErrorCodes:
    """
    Confirms that a specific setting has a well-formed value. If the setting is
    invalid, returns an error code. Otherwise, returns 0 (NO_ERROR).

    If ``client`` is set, the setting originated from a peer with that role.
    """
    if setting == SettingCodes.ENABLE_PUSH:
        # RFC 9113 section 6.5.2: "A client MUST treat receipt of a
        # SETTINGS frame with SETTINGS_ENABLE_PUSH set to 1 as a connection
        # error (Section 5.4.1) of type PROTOCOL_ERROR."
        if value not in (0, 1) or (client is False and value != 0):
            return ErrorCodes.PROTOCOL_ERROR
    elif setting == SettingCodes.INITIAL_WINDOW_SIZE:
        if not 0 <= value <= 2147483647:  # 2^31 - 1
            return ErrorCodes.FLOW_CONTROL_ERROR
    elif setting == SettingCodes.MAX_FRAME_SIZE:
        if not 16384 <= value <= 16777215:  # 2^14 and 2^24 - 1
            return ErrorCodes.PROTOCOL_ERROR
    elif setting == SettingCodes.MAX_HEADER_LIST_SIZE:
        if value < 0:
            return ErrorCodes.PROTOCOL_ERROR
    elif setting == SettingCodes.ENABLE_CONNECT_PROTOCOL and value not in (0, 1):
        return ErrorCodes.PROTOCOL_ERROR

    return ErrorCodes.NO_ERROR


# ---------------------------------------------------------------------------
# h2/events.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/events
~~~~~~~~~

Defines Event types for HTTP/2.

Events are returned by the H2 state machine to allow implementations to keep
track of events triggered by receiving data. Each time data is provided to the
H2 state machine it processes the data and returns a list of Event objects.
"""

import binascii
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any


kw_only = {"kw_only": True}


_LAZY_INIT: Any = object()
"""
Some h2 events are instantiated by the state machine, but its attributes are
subsequently populated by H2Stream. To make this work with strict type annotations
on the events, they are temporarily set to this placeholder value.
This value should never be exposed to users.
"""


class Event:
    """
    Base class for h2 events.
    """


@dataclass(**kw_only)
class RequestReceived(Event):
    """
    The RequestReceived event is fired whenever all of a request's headers
    are received. This event carries the HTTP headers for the given request
    and the stream ID of the new stream.

    In HTTP/2, headers may be sent as a HEADERS frame followed by zero or more
    CONTINUATION frames with the final frame setting the END_HEADERS flag.
    This event is fired after the entire sequence is received.

    .. versionchanged:: 2.3.0
       Changed the type of ``headers`` to :class:`HeaderTuple
       <hpack:hpack.HeaderTuple>`. This has no effect on current users.

    .. versionchanged:: 2.4.0
       Added ``stream_ended`` and ``priority_updated`` properties.
    """

    stream_id: int
    """The Stream ID for the stream this request was made on."""

    headers: list[Header] = _LAZY_INIT
    """The request headers."""

    stream_ended: StreamEnded | None = None
    """
    If this request also ended the stream, the associated
    :class:`StreamEnded <h2.events.StreamEnded>` event will be available
    here.

    .. versionadded:: 2.4.0
    """

    priority_updated: PriorityUpdated | None = None
    """
    If this request also had associated priority information, the
    associated :class:`PriorityUpdated <h2.events.PriorityUpdated>`
    event will be available here.

    .. versionadded:: 2.4.0
    """

    def __repr__(self) -> str:
        return f"<RequestReceived stream_id:{self.stream_id}, headers:{self.headers}>"


@dataclass(**kw_only)
class ResponseReceived(Event):
    """
    The ResponseReceived event is fired whenever response headers are received.
    This event carries the HTTP headers for the given response and the stream
    ID of the new stream.

    .. versionchanged:: 2.3.0
       Changed the type of ``headers`` to :class:`HeaderTuple
       <hpack:hpack.HeaderTuple>`. This has no effect on current users.

    .. versionchanged:: 2.4.0
      Added ``stream_ended`` and ``priority_updated`` properties.
    """

    stream_id: int
    """The Stream ID for the stream this response was made on."""

    headers: list[Header] = _LAZY_INIT
    """The response headers."""

    stream_ended: StreamEnded | None = None
    """
    If this response also ended the stream, the associated
    :class:`StreamEnded <h2.events.StreamEnded>` event will be available
    here.

    .. versionadded:: 2.4.0
    """

    priority_updated: PriorityUpdated | None = None
    """
    If this response also had associated priority information, the
    associated :class:`PriorityUpdated <h2.events.PriorityUpdated>`
    event will be available here.

    .. versionadded:: 2.4.0
    """

    def __repr__(self) -> str:
        return f"<ResponseReceived stream_id:{self.stream_id}, headers:{self.headers}>"


@dataclass(**kw_only)
class TrailersReceived(Event):
    """
    The TrailersReceived event is fired whenever trailers are received on a
    stream. Trailers are a set of headers sent after the body of the
    request/response, and are used to provide information that wasn't known
    ahead of time (e.g. content-length). This event carries the HTTP header
    fields that form the trailers and the stream ID of the stream on which they
    were received.

    .. versionchanged:: 2.3.0
       Changed the type of ``headers`` to :class:`HeaderTuple
       <hpack:hpack.HeaderTuple>`. This has no effect on current users.

    .. versionchanged:: 2.4.0
       Added ``stream_ended`` and ``priority_updated`` properties.
    """

    stream_id: int
    """The Stream ID for the stream on which these trailers were received."""

    headers: list[Header] = _LAZY_INIT
    """The trailers themselves."""

    stream_ended: StreamEnded | None = None
    """
    Trailers always end streams. This property has the associated
    :class:`StreamEnded <h2.events.StreamEnded>` in it.

    .. versionadded:: 2.4.0
    """

    priority_updated: PriorityUpdated | None = None
    """
    If the trailers also set associated priority information, the
    associated :class:`PriorityUpdated <h2.events.PriorityUpdated>`
    event will be available here.

    .. versionadded:: 2.4.0
    """

    def __repr__(self) -> str:
        return f"<TrailersReceived stream_id:{self.stream_id}, headers:{self.headers}>"


class _HeadersSent(Event):
    """
    The _HeadersSent event is fired whenever headers are sent.

    This is an internal event, used to determine validation steps on
    outgoing header blocks.
    """


class _ResponseSent(_HeadersSent):
    """
    The _ResponseSent event is fired whenever response headers are sent
    on a stream.

    This is an internal event, used to determine validation steps on
    outgoing header blocks.
    """


class _RequestSent(_HeadersSent):
    """
    The _RequestSent event is fired whenever request headers are sent
    on a stream.

    This is an internal event, used to determine validation steps on
    outgoing header blocks.
    """


class _TrailersSent(_HeadersSent):
    """
    The _TrailersSent event is fired whenever trailers are sent on a
    stream. Trailers are a set of headers sent after the body of the
    request/response, and are used to provide information that wasn't known
    ahead of time (e.g. content-length).

    This is an internal event, used to determine validation steps on
    outgoing header blocks.
    """


class _PushedRequestSent(_HeadersSent):
    """
    The _PushedRequestSent event is fired whenever pushed request headers are
    sent.

    This is an internal event, used to determine validation steps on outgoing
    header blocks.
    """


@dataclass(**kw_only)
class InformationalResponseReceived(Event):
    """
    The InformationalResponseReceived event is fired when an informational
    response (that is, one whose status code is a 1XX code) is received from
    the remote peer.

    The remote peer may send any number of these, from zero upwards. These
    responses are most commonly sent in response to requests that have the
    ``expect: 100-continue`` header field present. Most users can safely
    ignore this event unless you are intending to use the
    ``expect: 100-continue`` flow, or are for any reason expecting a different
    1XX status code.

    .. versionadded:: 2.2.0

    .. versionchanged:: 2.3.0
       Changed the type of ``headers`` to :class:`HeaderTuple
       <hpack:hpack.HeaderTuple>`. This has no effect on current users.

    .. versionchanged:: 2.4.0
       Added ``priority_updated`` property.
    """

    stream_id: int
    """The Stream ID for the stream this informational response was made on."""

    headers: list[Header] = _LAZY_INIT
    """The headers for this informational response."""

    priority_updated: PriorityUpdated | None = None
    """
    If this response also had associated priority information, the
    associated :class:`PriorityUpdated <h2.events.PriorityUpdated>`
    event will be available here.

    .. versionadded:: 2.4.0
    """

    def __repr__(self) -> str:
        return f"<InformationalResponseReceived stream_id:{self.stream_id}, headers:{self.headers}>"


@dataclass(**kw_only)
class DataReceived(Event):
    """
    The DataReceived event is fired whenever data is received on a stream from
    the remote peer. The event carries the data itself, and the stream ID on
    which the data was received.

    .. versionchanged:: 2.4.0
       Added ``stream_ended`` property.
    """

    stream_id: int
    """The Stream ID for the stream this data was received on."""

    data: bytes = _LAZY_INIT
    """The data itself."""

    flow_controlled_length: int = _LAZY_INIT
    """
    The amount of data received that counts against the flow control
    window. Note that padding counts against the flow control window, so
    when adjusting flow control you should always use this field rather
    than ``len(data)``.
    """

    stream_ended: StreamEnded | None = None
    """
    If this data chunk also completed the stream, the associated
    :class:`StreamEnded <h2.events.StreamEnded>` event will be available
    here.

    .. versionadded:: 2.4.0
    """

    def __repr__(self) -> str:
        return (
            "<DataReceived stream_id:{}, "
            "flow_controlled_length:{}, "
            "data:{}>".format(
                self.stream_id,
                self.flow_controlled_length,
                _bytes_representation(self.data[:20]) if self.data else "",
            )
        )


@dataclass(**kw_only)
class WindowUpdated(Event):
    """
    The WindowUpdated event is fired whenever a flow control window changes
    size. HTTP/2 defines flow control windows for connections and streams: this
    event fires for both connections and streams. The event carries the ID of
    the stream to which it applies (set to zero if the window update applies to
    the connection), and the delta in the window size.
    """

    stream_id: int
    """
    The Stream ID of the stream whose flow control window was changed.
    May be ``0`` if the connection window was changed.
    """

    delta: int = _LAZY_INIT
    """
    The window delta.
    """

    def __repr__(self) -> str:
        return f"<WindowUpdated stream_id:{self.stream_id}, delta:{self.delta}>"


class RemoteSettingsChanged(Event):
    """
    The RemoteSettingsChanged event is fired whenever the remote peer changes
    its settings. It contains a complete inventory of changed settings,
    including their previous values.

    In HTTP/2, settings changes need to be acknowledged. h2 automatically
    acknowledges settings changes for efficiency. However, it is possible that
    the caller may not be happy with the changed setting.

    When this event is received, the caller should confirm that the new
    settings are acceptable. If they are not acceptable, the user should close
    the connection with the error code :data:`PROTOCOL_ERROR
    <h2.errors.ErrorCodes.PROTOCOL_ERROR>`.

    .. versionchanged:: 2.0.0
       Prior to this version the user needed to acknowledge settings changes.
       This is no longer the case: h2 now automatically acknowledges
       them.
    """

    def __init__(self) -> None:
        #: A dictionary of setting byte to
        #: :class:`ChangedSetting <h2.settings.ChangedSetting>`, representing
        #: the changed settings.
        self.changed_settings: dict[int, ChangedSetting] = {}

    @classmethod
    def from_settings(cls,
                      old_settings: Settings | dict[int, int],
                      new_settings: dict[int, int]) -> RemoteSettingsChanged:
        """
        Build a RemoteSettingsChanged event from a set of changed settings.

        :param old_settings: A complete collection of old settings, in the form
                             of a dictionary of ``{setting: value}``.
        :param new_settings: All the changed settings and their new values, in
                             the form of a dictionary of ``{setting: value}``.
        """
        e = cls()
        for setting, new_value in new_settings.items():
            s = _setting_code_from_int(setting)
            original_value = old_settings.get(s)
            change = ChangedSetting(s, original_value, new_value)
            e.changed_settings[s] = change

        return e

    def __repr__(self) -> str:
        return "<RemoteSettingsChanged changed_settings:{{{}}}>".format(
            ", ".join(repr(cs) for cs in self.changed_settings.values()),
        )


@dataclass(**kw_only)
class PingReceived(Event):
    """
    The PingReceived event is fired whenever a PING is received. It contains
    the 'opaque data' of the PING frame. A ping acknowledgment with the same
    'opaque data' is automatically emitted after receiving a ping.

    .. versionadded:: 3.1.0
    """

    ping_data: bytes
    """The data included on the ping."""

    def __repr__(self) -> str:
        return f"<PingReceived ping_data:{_bytes_representation(self.ping_data)}>"


@dataclass(**kw_only)
class PingAckReceived(Event):
    """
    The PingAckReceived event is fired whenever a PING acknowledgment is
    received. It contains the 'opaque data' of the PING+ACK frame, allowing the
    user to correlate PINGs and calculate RTT.

    .. versionadded:: 3.1.0

    .. versionchanged:: 4.0.0
       Removed deprecated but equivalent ``PingAcknowledged``.
    """

    ping_data: bytes
    """The data included on the ping."""

    def __repr__(self) -> str:
        return f"<PingAckReceived ping_data:{_bytes_representation(self.ping_data)}>"


@dataclass(**kw_only)
class StreamEnded(Event):
    """
    The StreamEnded event is fired whenever a stream is ended by a remote
    party. The stream may not be fully closed if it has not been closed
    locally, but no further data or headers should be expected on that stream.
    """

    stream_id: int
    """The Stream ID of the stream that was closed."""

    def __repr__(self) -> str:
        return f"<StreamEnded stream_id:{self.stream_id}>"


@dataclass(**kw_only)
class StreamReset(Event):
    """
    The StreamReset event is fired in two situations. The first is when the
    remote party forcefully resets the stream. The second is when the remote
    party has made a protocol error which only affects a single stream. In this
    case, h2 will terminate the stream early and return this event.

    .. versionchanged:: 2.0.0
       This event is now fired when h2 automatically resets a stream.
    """

    stream_id: int
    """
    The Stream ID of the stream that was reset.
    """

    error_code: ErrorCodes | int = _LAZY_INIT
    """
    The error code given.
    """

    remote_reset: bool = True
    """
    Whether the remote peer sent a RST_STREAM or we did.
    """

    def __repr__(self) -> str:
        return f"<StreamReset stream_id:{self.stream_id}, error_code:{self.error_code!s}, remote_reset:{self.remote_reset}>"


class PushedStreamReceived(Event):
    """
    The PushedStreamReceived event is fired whenever a pushed stream has been
    received from a remote peer. The event carries on it the new stream ID, the
    ID of the parent stream, and the request headers pushed by the remote peer.
    """

    def __init__(self) -> None:
        #: The Stream ID of the stream created by the push.
        self.pushed_stream_id: int | None = None

        #: The Stream ID of the stream that the push is related to.
        self.parent_stream_id: int | None = None

        #: The request headers, sent by the remote party in the push.
        self.headers: list[Header] | None = None

    def __repr__(self) -> str:
        return (
            f"<PushedStreamReceived pushed_stream_id:{self.pushed_stream_id}, parent_stream_id:{self.parent_stream_id}, "
            f"headers:{self.headers}>"
        )


class SettingsAcknowledged(Event):
    """
    The SettingsAcknowledged event is fired whenever a settings ACK is received
    from the remote peer. The event carries on it the settings that were
    acknowledged, in the same format as
    :class:`h2.events.RemoteSettingsChanged`.
    """

    def __init__(self) -> None:
        #: A dictionary of setting byte to
        #: :class:`ChangedSetting <h2.settings.ChangedSetting>`, representing
        #: the changed settings.
        self.changed_settings: dict[SettingCodes | int, ChangedSetting] = {}

    def __repr__(self) -> str:
        s = ", ".join(repr(cs) for cs in self.changed_settings.values())
        return f"<SettingsAcknowledged changed_settings:{{{s}}}>"


class PriorityUpdated(Event):
    """
    The PriorityUpdated event is fired whenever a stream sends updated priority
    information. This can occur when the stream is opened, or at any time
    during the stream lifetime.

    This event is purely advisory, and does not need to be acted on.

    .. versionadded:: 2.0.0
    """

    def __init__(self) -> None:
        #: The ID of the stream whose priority information is being updated.
        self.stream_id: int | None = None

        #: The new stream weight. May be the same as the original stream
        #: weight. An integer between 1 and 256.
        self.weight: int | None = None

        #: The stream ID this stream now depends on. May be ``0``.
        self.depends_on: int | None = None

        #: Whether the stream *exclusively* depends on the parent stream. If it
        #: does, this stream should inherit the current children of its new
        #: parent.
        self.exclusive: bool | None = None

    def __repr__(self) -> str:
        return (
            f"<PriorityUpdated stream_id:{self.stream_id}, weight:{self.weight}, depends_on:{self.depends_on}, "
            f"exclusive:{self.exclusive}>"
        )


class ConnectionTerminated(Event):
    """
    The ConnectionTerminated event is fired when a connection is torn down by
    the remote peer using a GOAWAY frame. Once received, no further action may
    be taken on the connection: a new connection must be established.
    """

    def __init__(self) -> None:
        #: The error code cited when tearing down the connection. Should be
        #: one of :class:`ErrorCodes <h2.errors.ErrorCodes>`, but may not be if
        #: unknown HTTP/2 extensions are being used.
        self.error_code: ErrorCodes | int | None = None

        #: The stream ID of the last stream the remote peer saw. This can
        #: provide an indication of what data, if any, never reached the remote
        #: peer and so can safely be resent.
        self.last_stream_id: int | None = None

        #: Additional debug data that can be appended to GOAWAY frame.
        self.additional_data: bytes | None = None

    def __repr__(self) -> str:
        return (
            "<ConnectionTerminated error_code:{!s}, last_stream_id:{}, "
            "additional_data:{}>".format(
                self.error_code,
                self.last_stream_id,
                _bytes_representation(
                    self.additional_data[:20]
                    if self.additional_data else None),
            )
        )


class AlternativeServiceAvailable(Event):
    """
    The AlternativeServiceAvailable event is fired when the remote peer
    advertises an `RFC 7838 <https://tools.ietf.org/html/rfc7838>`_ Alternative
    Service using an ALTSVC frame.

    This event always carries the origin to which the ALTSVC information
    applies. That origin is either supplied by the server directly, or inferred
    by h2 from the ``:authority`` pseudo-header field that was sent by
    the user when initiating a given stream.

    This event also carries what RFC 7838 calls the "Alternative Service Field
    Value", which is formatted like a HTTP header field and contains the
    relevant alternative service information. h2 does not parse or in any
    way modify that information: the user is required to do that.

    This event can only be fired on the client end of a connection.

    .. versionadded:: 2.3.0
    """

    def __init__(self) -> None:
        #: The origin to which the alternative service field value applies.
        #: This field is either supplied by the server directly, or inferred by
        #: h2 from the ``:authority`` pseudo-header field that was sent
        #: by the user when initiating the stream on which the frame was
        #: received.
        self.origin: bytes | None = None

        #: The ALTSVC field value. This contains information about the HTTP
        #: alternative service being advertised by the server. h2 does
        #: not parse this field: it is left exactly as sent by the server. The
        #: structure of the data in this field is given by `RFC 7838 Section 3
        #: <https://tools.ietf.org/html/rfc7838#section-3>`_.
        self.field_value: bytes | None = None

    def __repr__(self) -> str:
        return (
            "<AlternativeServiceAvailable origin:{}, field_value:{}>".format(
                (self.origin or b"").decode("utf-8", "ignore"),
                (self.field_value or b"").decode("utf-8", "ignore"),
            )
        )


@dataclass(**kw_only)
class UnknownFrameReceived(Event):
    """
    The UnknownFrameReceived event is fired when the remote peer sends a frame
    that h2 does not understand. This occurs primarily when the remote
    peer is employing HTTP/2 extensions that h2 doesn't know anything
    about.

    RFC 7540 requires that HTTP/2 implementations ignore these frames. h2
    does so. However, this event is fired to allow implementations to perform
    special processing on those frames if needed (e.g. if the implementation
    is capable of handling the frame itself).

    .. versionadded:: 2.7.0
    """

    frame: Frame

    def __repr__(self) -> str:
        return "<UnknownFrameReceived>"


def _bytes_representation(data: bytes | None) -> str | None:
    """
    Converts a bytestring into something that is safe to print on all Python
    platforms.

    This function is relatively expensive, so it should not be called on the
    mainline of the code. It's safe to use in things like object repr methods
    though.
    """
    if data is None:
        return None

    return binascii.hexlify(data).decode("ascii")


# ---------------------------------------------------------------------------
# h2/frame_buffer.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/frame_buffer
~~~~~~~~~~~~~~~

A data structure that provides a way to iterate over a byte buffer in terms of
frames.
"""

from typing import TYPE_CHECKING


# To avoid a DOS attack based on sending loads of continuation frames, we limit
# the maximum number we're prepared to receive. In this case, we'll set the
# limit to 64, which means the largest encoded header block we can receive by
# default is 262144 bytes long, and the largest possible *at all* is 1073741760
# bytes long.
#
# This value seems reasonable for now, but in future we may want to evaluate
# making it configurable.
CONTINUATION_BACKLOG = 64


class FrameBuffer:
    """
    A buffer data structure for HTTP/2 data that allows iteration in terms of
    H2 frames.
    """

    def __init__(self, server: bool = False) -> None:
        self._data = bytearray()
        self.max_frame_size = 0
        self._preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" if server else b""
        self._preamble_len = len(self._preamble)
        self._headers_buffer: list[HeadersFrame | ContinuationFrame | PushPromiseFrame] = []

    def add_data(self, data: Buffer) -> None:
        """
        Add more data to the frame buffer.

        :param data: A bytestring containing the byte buffer.
        """
        data_view = memoryview(data)

        if self._preamble_len:
            data_len = len(data_view)
            of_which_preamble = min(self._preamble_len, data_len)

            if self._preamble[:of_which_preamble] != data_view[:of_which_preamble]:
                msg = "Invalid HTTP/2 preamble."
                raise ProtocolError(msg)

            data_view = data_view[of_which_preamble:]
            self._preamble_len -= of_which_preamble
            self._preamble = self._preamble[of_which_preamble:]

        self._data += data_view

    def _validate_frame_length(self, length: int) -> None:
        """
        Confirm that the frame is an appropriate length.
        """
        if length > self.max_frame_size:
            msg = f"Received overlong frame: length {length}, max {self.max_frame_size}"
            raise FrameTooLargeError(msg)

    def _update_header_buffer(self, f: Frame | None) -> Frame | None:
        """
        Updates the internal header buffer. Returns a frame that should replace
        the current one. May throw exceptions if this frame is invalid.
        """
        # Check if we're in the middle of a headers block. If we are, this
        # frame *must* be a CONTINUATION frame with the same stream ID as the
        # leading HEADERS or PUSH_PROMISE frame. Anything else is a
        # ProtocolError. If the frame *is* valid, append it to the header
        # buffer.
        if self._headers_buffer:
            stream_id = self._headers_buffer[0].stream_id
            valid_frame = (
                f is not None and
                isinstance(f, ContinuationFrame) and
                f.stream_id == stream_id
            )
            if not valid_frame:
                msg = "Invalid frame during header block."
                raise ProtocolError(msg)
            assert isinstance(f, ContinuationFrame)

            # Append the frame to the buffer.
            self._headers_buffer.append(f)
            if len(self._headers_buffer) > CONTINUATION_BACKLOG:
                msg = "Too many continuation frames received."
                raise ProtocolError(msg)

            # If this is the end of the header block, then we want to build a
            # mutant HEADERS frame that's massive. Use the original one we got,
            # then set END_HEADERS and set its data appropriately. If it's not
            # the end of the block, lose the current frame: we can't yield it.
            if "END_HEADERS" in f.flags:
                f = self._headers_buffer[0]
                f.flags.add("END_HEADERS")
                f.data = b"".join(x.data for x in self._headers_buffer)
                self._headers_buffer = []
            else:
                f = None
        elif (isinstance(f, (HeadersFrame, PushPromiseFrame)) and
                "END_HEADERS" not in f.flags):
            # This is the start of a headers block! Save the frame off and then
            # act like we didn't receive one.
            self._headers_buffer.append(f)
            f = None

        return f

    # The methods below support the iterator protocol.
    def __iter__(self) -> FrameBuffer:
        return self

    def __next__(self) -> Frame:
        # First, check that we have enough data to successfully parse the
        # next frame header. If not, bail. Otherwise, parse it.
        if len(self._data) < 9:
            raise StopIteration

        try:
            f, length = Frame.parse_frame_header(memoryview(self._data[:9]))
        except (InvalidDataError, InvalidFrameError) as err:  # pragma: no cover
            msg = f"Received frame with invalid header: {err!s}"
            raise ProtocolError(msg) from err

        # Next, check that we have enough length to parse the frame body. If
        # not, bail, leaving the frame header data in the buffer for next time.
        if len(self._data) < length + 9:
            raise StopIteration

        # Confirm the frame has an appropriate length.
        self._validate_frame_length(length)

        # Try to parse the frame body
        try:
            f.parse_body(memoryview(self._data[9:9+length]))
        except InvalidDataError as err:
            msg = "Received frame with non-compliant data"
            raise ProtocolError(msg) from err
        except InvalidFrameError as err:
            msg = "Frame data missing or invalid"
            raise FrameDataMissingError(msg) from err

        # At this point, as we know we'll use or discard the entire frame, we
        # can update the data.
        # Deleting the consumed prefix mutates the bytearray in place instead
        # of copying the remaining bytes into a new object, as slicing would.
        # ``del s[i:j]`` is documented for mutable sequences in
        # https://docs.python.org/3/library/stdtypes.html#mutable-sequence-types
        # and CPython's bytearray tracks an internal offset (``ob_start`` in
        # Objects/bytearrayobject.c) that makes repeated deletes from the
        # front amortized O(1) per byte rather than O(len) per frame.
        del self._data[:9+length]

        # Pass the frame through the header buffer.
        new_frame = self._update_header_buffer(f)

        # If we got a frame we didn't understand or shouldn't yield, rather
        # than return None it'd be better if we just tried to get the next
        # frame in the sequence instead. Recurse back into ourselves to do
        # that. This is safe because the amount of work we have to do here is
        # strictly bounded by the length of the buffer.
        return new_frame if new_frame is not None else self.__next__()


# ---------------------------------------------------------------------------
# h2/utilities.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/utilities
~~~~~~~~~~~~

Utility functions that do not belong in a separate module.
"""

import collections
from typing import TYPE_CHECKING, Any, NamedTuple


if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Generator, Iterable


SIGIL = ord(b":")
INFORMATIONAL_START = ord(b"1")


# A set of headers that are hop-by-hop or connection-specific and thus
# forbidden in HTTP/2. This list comes from RFC 7540 § 8.1.2.2.
CONNECTION_HEADERS = frozenset([
    b"connection",
    b"proxy-connection",
    b"keep-alive",
    b"transfer-encoding",
    b"upgrade",
])


_ALLOWED_PSEUDO_HEADER_FIELDS = frozenset([
    b":method",
    b":scheme",
    b":authority",
    b":path",
    b":status",
    b":protocol",
])


_SECURE_HEADERS = frozenset([
    # May have basic credentials which are vulnerable to dictionary attacks.
    b"authorization",
    b"proxy-authorization",
])


_REQUEST_ONLY_HEADERS = frozenset([
    b":scheme",
    b":path",
    b":authority",
    b":method",
    b":protocol",
])


_RESPONSE_ONLY_HEADERS = frozenset([b":status"])


# A Set of pseudo headers that are only valid if the method is
# CONNECT, see RFC 8441 § 5
_CONNECT_REQUEST_ONLY_HEADERS = frozenset([b":protocol"])


def _secure_headers(headers: Iterable[Header],
                    hdr_validation_flags: HeaderValidationFlags | None) -> Generator[Header, None, None]:
    """
    Certain headers are at risk of being attacked during the header compression
    phase, and so need to be kept out of header compression contexts. This
    function automatically transforms certain specific headers into HPACK
    never-indexed fields to ensure they don't get added to header compression
    contexts.

    This function currently implements two rules:

    - 'authorization' and 'proxy-authorization' fields are automatically made
      never-indexed.
    - Any 'cookie' header field shorter than 20 bytes long is made
      never-indexed.

    These fields are the most at-risk. These rules are inspired by Firefox
    and nghttp2.
    """
    for header in headers:
        assert isinstance(header[0], bytes)
        if header[0] in _SECURE_HEADERS or (header[0] == b"cookie" and len(header[1]) < 20):
            yield NeverIndexedHeaderTuple(header[0], header[1])
        else:
            yield header


def extract_method_header(headers: Iterable[Header]) -> bytes | None:
    """
    Extracts the request method from the headers list.
    """
    for k, v in headers:
        if isinstance(v, bytes) and k == b":method":
            return v
        if isinstance(v, str) and k == ":method":
            return v.encode("utf-8")  # pragma: no cover
    return None


def is_informational_response(headers: Iterable[Header]) -> bool:
    """
    Searches headers list for a :status header to confirm that a given
    collection of headers are an informational response. Assumes the header
    are well formed and encoded as bytes: that is, that the HTTP/2 special
    headers are first in the block, and so that it can stop looking when it
    finds the first header field whose name does not begin with a colon.

    :param headers: The HTTP/2 headers.
    :returns: A boolean indicating if this is an informational response.
    """
    for n, v in headers:
        if not n.startswith(b":"):
            return False
        if n != b":status":
            # If we find a non-special header, we're done here: stop looping.
            continue
        # If the first digit is a 1, we've got informational headers.
        return v.startswith(b"1")
    return False


def guard_increment_window(current: int, increment: int) -> int:
    """
    Increments a flow control window, guarding against that window becoming too
    large.

    :param current: The current value of the flow control window.
    :param increment: The increment to apply to that window.
    :returns: The new value of the window.
    :raises: ``FlowControlError``
    """
    # The largest value the flow control window may take.
    LARGEST_FLOW_CONTROL_WINDOW = 2**31 - 1  # noqa: N806

    new_size = current + increment

    if new_size > LARGEST_FLOW_CONTROL_WINDOW:
        msg = f"May not increment flow control window past {LARGEST_FLOW_CONTROL_WINDOW}"
        raise FlowControlError(msg)

    return new_size


def authority_from_headers(headers: Iterable[Header]) -> bytes | None:
    """
    Given a header set, searches for the authority header and returns the
    value.

    Note that this doesn't use indexing, so should only be called if the
    headers are for a client request. Otherwise, will loop over the entire
    header set, which is potentially unwise.

    :param headers: The HTTP header set.
    :returns: The value of the authority header, or ``None``.
    :rtype: ``bytes`` or ``None``.
    """
    for n, v in headers:
        if n == b":authority":
            return v

    return None


# Flags used by the validate_headers pipeline to determine which checks
# should be applied to a given set of headers.
class HeaderValidationFlags(NamedTuple):
    is_client: bool
    is_trailer: bool
    is_response_header: bool
    is_push_promise: bool


def validate_headers(headers: Iterable[Header], hdr_validation_flags: HeaderValidationFlags) -> Iterable[Header]:
    """
    Validates a header sequence against a set of constraints from RFC 7540.

    :param headers: The HTTP header set.
    :param hdr_validation_flags: An instance of HeaderValidationFlags.
    """
    # This validation logic is built on a sequence of generators that are
    # iterated over to provide the final header list. This reduces some of the
    # overhead of doing this checking. However, it's worth noting that this
    # checking remains somewhat expensive, and attempts should be made wherever
    # possible to reduce the time spent doing them.
    #
    # For example, we avoid tuple unpacking in loops because it represents a
    # fixed cost that we don't want to spend, instead indexing into the header
    # tuples.
    headers = _reject_illegal_characters(
        headers, hdr_validation_flags,
    )
    headers = _reject_empty_header_names(
        headers, hdr_validation_flags,
    )
    headers = _reject_te(
        headers, hdr_validation_flags,
    )
    headers = _reject_connection_header(
        headers, hdr_validation_flags,
    )
    headers = _reject_pseudo_header_fields(
        headers, hdr_validation_flags,
    )
    headers = _check_host_authority_header(
        headers, hdr_validation_flags,
    )
    return _check_path_header(headers, hdr_validation_flags)


def _reject_illegal_characters(headers: Iterable[Header],
                               hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises a ProtocolError if any header names or values contain illegal characters.
    See <https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.1>.
    """
    for header in headers:
        # > A field name MUST NOT contain characters in the ranges 0x00-0x20, 0x41-0x5a,
        # > or 0x7f-0xff (all ranges inclusive).
        for c in header[0]:
            if 0x41 <= c <= 0x5a:
                msg = f"Received uppercase header name {header[0]!r}."
                raise ProtocolError(msg)
            if c <= 0x20 or c >= 0x7f:
                msg = f"Illegal character '{chr(c)}' in header name: {header[0]!r}"
                raise ProtocolError(msg)

        # > With the exception of pseudo-header fields (Section 8.3), which have a name
        # > that starts with a single colon, field names MUST NOT include a colon (ASCII
        # > COLON, 0x3a).
        if header[0].find(b":", 1) != -1:
            msg = f"Illegal character ':' in header name: {header[0]!r}"
            raise ProtocolError(msg)

        # For compatibility with RFC 7230 header fields, we need to allow the field
        # value to be an empty string. This is ludicrous, but technically allowed.
        if field_value := header[1]:

            # > A field value MUST NOT contain the zero value (ASCII NUL, 0x00), line feed
            # > (ASCII LF, 0x0a), or carriage return (ASCII CR, 0x0d) at any position.
            for c in field_value:
                if c == 0 or c == 0x0a or c == 0x0d:  # noqa: PLR1714
                    msg = f"Illegal character '{chr(c)}' in header value: {field_value!r}"
                    raise ProtocolError(msg)

            # > A field value MUST NOT start or end with an ASCII whitespace character
            # > (ASCII SP or HTAB, 0x20 or 0x09).
            if (
                field_value[0] == 0x20 or
                field_value[0] == 0x09 or
                field_value[-1] == 0x20 or
                field_value[-1] == 0x09
            ):
                msg = f"Received header value surrounded by whitespace {field_value!r}"
                raise ProtocolError(msg)

        yield header


def _reject_empty_header_names(headers: Iterable[Header],
                               hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises a ProtocolError if any header names are empty (length 0).
    While hpack decodes such headers without errors, they are semantically
    forbidden in HTTP, see RFC 7230, stating that they must be at least one
    character long.
    """
    for header in headers:
        if len(header[0]) == 0:
            msg = "Received header name with zero length."
            raise ProtocolError(msg)
        yield header


def _reject_te(headers: Iterable[Header], hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises a ProtocolError if the TE header is present in a header block and
    its value is anything other than "trailers".
    """
    for header in headers:
        if header[0] == b"te" and header[1].lower() != b"trailers":
            msg = f"Invalid value for TE header: {header[1]!r}"
            raise ProtocolError(msg)

        yield header


def _reject_connection_header(headers: Iterable[Header], hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises a ProtocolError if the Connection header is present in a header
    block.
    """
    for header in headers:
        if header[0] in CONNECTION_HEADERS:
            msg = f"Connection-specific header field present: {header[0]!r}."
            raise ProtocolError(msg)

        yield header


def _assert_header_in_set(bytes_header: bytes,
                          header_set: set[bytes | str] | set[bytes] | set[str]) -> None:
    """
    Given a set of header names, checks whether the string or byte version of
    the header name is present. Raises a Protocol error with the appropriate
    error if it's missing.
    """
    if bytes_header not in header_set:
        msg = f"Header block missing mandatory {bytes_header!r} header"
        raise ProtocolError(msg)


def _reject_pseudo_header_fields(headers: Iterable[Header],
                                 hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises a ProtocolError if duplicate pseudo-header fields are found in a
    header block or if a pseudo-header field appears in a block after an
    ordinary header field.

    Raises a ProtocolError if pseudo-header fields are found in trailers.
    """
    seen_pseudo_header_fields = set()
    seen_regular_header = False
    method = None

    for header in headers:
        if header[0][0] == SIGIL:
            if header[0] in seen_pseudo_header_fields:
                msg = f"Received duplicate pseudo-header field {header[0]!r}"
                raise ProtocolError(msg)

            seen_pseudo_header_fields.add(header[0])

            if seen_regular_header:
                msg = f"Received pseudo-header field out of sequence: {header[0]!r}"
                raise ProtocolError(msg)

            if header[0] not in _ALLOWED_PSEUDO_HEADER_FIELDS:
                msg = f"Received custom pseudo-header field {header[0]!r}"
                raise ProtocolError(msg)

            if header[0] == b":method":
                method = header[1]

        else:
            seen_regular_header = True

        yield header

    # Check the pseudo-headers we got to confirm they're acceptable.
    _check_pseudo_header_field_acceptability(
        seen_pseudo_header_fields, method, hdr_validation_flags,
    )


def _check_pseudo_header_field_acceptability(  # noqa: C901
        pseudo_headers: set[bytes | str] | set[bytes] | set[str],
        method: bytes | None,
        hdr_validation_flags: HeaderValidationFlags,
) -> None:
    """
    Given the set of pseudo-headers present in a header block and the
    validation flags, confirms that RFC 7540 allows them.
    """
    # Pseudo-header fields MUST NOT appear in trailers - RFC 7540 § 8.1.2.1
    if hdr_validation_flags.is_trailer and pseudo_headers:
        msg = f"Received pseudo-header in trailer {pseudo_headers}"
        raise ProtocolError(msg)

    # If ':status' pseudo-header is not there in a response header, reject it.
    # Similarly, if ':path', ':method', or ':scheme' are not there in a request
    # header, reject it. Additionally, if a response contains any request-only
    # headers or vice-versa, reject it.
    # Relevant RFC section: RFC 7540 § 8.1.2.4
    # https://tools.ietf.org/html/rfc7540#section-8.1.2.4
    if hdr_validation_flags.is_response_header:
        _assert_header_in_set(b":status", pseudo_headers)
        invalid_response_headers = pseudo_headers & _REQUEST_ONLY_HEADERS
        if invalid_response_headers:
            msg = f"Encountered request-only headers {invalid_response_headers}"
            raise ProtocolError(msg)
    elif (not hdr_validation_flags.is_response_header and
          not hdr_validation_flags.is_trailer):
        # Request header block.
        _assert_header_in_set(b":method", pseudo_headers)

        is_connect = (method == b"CONNECT")
        is_extended_connect = is_connect and (b":protocol" in pseudo_headers)

        if is_connect and not is_extended_connect:
            # Ordinary CONNECT (RFC 9113 s8.3):
            # MUST NOT include :scheme or :path.
            if b":scheme" in pseudo_headers or b":path" in pseudo_headers:
                msg = "Ordinary CONNECT MUST NOT include :scheme or :path"
                raise ProtocolError(msg)
            # :authority presence is enforced elsewhere; no extra asserts here.
        elif is_extended_connect:
            # Extended CONNECT (RFC 8441 s4): require the regular tuple.
            _assert_header_in_set(b":scheme", pseudo_headers)
            _assert_header_in_set(b":path", pseudo_headers)
            # :authority presence validated by host/authority checker.
        else:
            # Non-CONNECT requests require :scheme and :path (RFC 9113 s8.3).
            _assert_header_in_set(b":scheme", pseudo_headers)
            _assert_header_in_set(b":path", pseudo_headers)

        invalid_request_headers = pseudo_headers & _RESPONSE_ONLY_HEADERS
        if invalid_request_headers:
            msg = f"Encountered response-only headers {invalid_request_headers}"
            raise ProtocolError(msg)

        # If not CONNECT, then :protocol is invalid.
        if not is_connect:
            invalid_headers = pseudo_headers & _CONNECT_REQUEST_ONLY_HEADERS
            if invalid_headers:
                msg = f"Encountered connect-request-only headers {invalid_headers!r}"
                raise ProtocolError(msg)


def _validate_host_authority_header(headers: Iterable[Header]) -> Generator[Header, None, None]:
    """
    Given the :authority and Host headers from a request block that isn't
    a trailer, check that:
     1. At least one of these headers is set.
     2. If both headers are set, they match.

    :param headers: The HTTP header set.
    :raises: ``ProtocolError``
    """
    # We use None as a sentinel value.  Iterate over the list of headers,
    # and record the value of these headers (if present).  We don't need
    # to worry about receiving duplicate :authority headers, as this is
    # enforced by the _reject_pseudo_header_fields() pipeline.
    #
    # TODO: We should also guard against receiving duplicate Host headers,
    # and against sending duplicate headers.
    authority_header_val = None
    host_header_val = None

    for header in headers:
        if header[0] == b":authority":
            authority_header_val = header[1]
        elif header[0] == b"host":
            if host_header_val is not None:
                msg = "Request header block has multiple Host headers."
                raise ProtocolError(msg)
            host_header_val = header[1]

        yield header

    # If we have not-None values for these variables, then we know we saw
    # the corresponding header.
    authority_present = (authority_header_val is not None)
    host_present = (host_header_val is not None)

    # It is an error for a request header block to contain neither
    # an :authority header nor a Host header.
    if not authority_present and not host_present:
        msg = "Request header block does not have an :authority or Host header."
        raise ProtocolError(msg)

    # If we receive both headers, they should definitely match.
    if authority_present and host_present and authority_header_val != host_header_val:
        msg = (
            "Request header block has mismatched :authority and "
            f"Host headers: {authority_header_val!r} / {host_header_val!r}"
        )
        raise ProtocolError(msg)


def _check_host_authority_header(headers: Iterable[Header],
                                 hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises a ProtocolError if a header block arrives that does not contain an
    :authority or a Host header, or if a header block contains both fields,
    but their values do not match.
    """
    # We only expect to see :authority and Host headers on request header
    # blocks that aren't trailers, so skip this validation if this is a
    # response header or we're looking at trailer blocks.
    skip_validation = (
        hdr_validation_flags.is_response_header or
        hdr_validation_flags.is_trailer
    )
    if skip_validation:
        return (h for h in headers)

    return _validate_host_authority_header(headers)


def _check_path_header(headers: Iterable[Header],
                       hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raise a ProtocolError if a header block arrives or is sent that contains an
    empty :path header.
    """
    def inner() -> Generator[Header, None, None]:
        for header in headers:
            if header[0] == b":path" and not header[1]:
                msg = "An empty :path header is forbidden"
                raise ProtocolError(msg)

            yield header

    # We only expect to see :authority and Host headers on request header
    # blocks that aren't trailers, so skip this validation if this is a
    # response header or we're looking at trailer blocks.
    skip_validation = (
        hdr_validation_flags.is_response_header or
        hdr_validation_flags.is_trailer
    )
    if skip_validation:
        return (h for h in headers)
    return inner()


def _h2_utilities_to_bytes(v: bytes | str) -> bytes:
    """
    Given an assumed `str` (or anything that supports `.encode()`),
    encodes it using utf-8 into bytes. Returns the unmodified object
    if it is already a `bytes` object.
    """
    return v if isinstance(v, bytes) else v.encode("utf-8")


def utf8_encode_headers(headers: Iterable[HeaderWeaklyTyped]) -> list[Header]:
    """
    Given an iterable of header two-tuples, rebuilds that as a list with the
    header names and values encoded as utf-8 bytes. This function produces
    tuples that preserve the original type of the header tuple for tuple and
    any ``HeaderTuple``.
    """
    encoded_headers: list[Header] = []
    for header in headers:
        h = (_h2_utilities_to_bytes(header[0]), _h2_utilities_to_bytes(header[1]))
        if isinstance(header, HeaderTuple):
            encoded_headers.append(header.__class__(h[0], h[1]))
        else:
            encoded_headers.append(h)
    return encoded_headers


def _lowercase_header_names(headers: Iterable[Header],
                            hdr_validation_flags: HeaderValidationFlags | None) -> Generator[Header, None, None]:
    """
    Given an iterable of header two-tuples, rebuilds that iterable with the
    header names lowercased. This generator produces tuples that preserve the
    original type of the header tuple for tuple and any ``HeaderTuple``.
    """
    for header in headers:
        if isinstance(header, HeaderTuple):
            yield header.__class__(header[0].lower(), header[1])
        else:
            yield (header[0].lower(), header[1])


def _strip_surrounding_whitespace(headers: Iterable[Header],
                                  hdr_validation_flags: HeaderValidationFlags | None) -> Generator[Header, None, None]:
    """
    Given an iterable of header two-tuples, strip both leading and trailing
    whitespace from both header names and header values. This generator
    produces tuples that preserve the original type of the header tuple for
    tuple and any ``HeaderTuple``.
    """
    for header in headers:
        if isinstance(header, HeaderTuple):
            yield header.__class__(header[0].strip(), header[1].strip())
        else:
            yield (header[0].strip(), header[1].strip())


def _strip_connection_headers(headers: Iterable[Header],
                              hdr_validation_flags: HeaderValidationFlags | None) -> Generator[Header, None, None]:
    """
    Strip any connection headers as per RFC7540 § 8.1.2.2.
    """
    for header in headers:
        if header[0] not in CONNECTION_HEADERS:
            yield header


def _check_sent_host_authority_header(headers: Iterable[Header],
                                      hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Raises an InvalidHeaderBlockError if we try to send a header block
    that does not contain an :authority or a Host header, or if
    the header block contains both fields, but their values do not match.
    """
    # We only expect to see :authority and Host headers on request header
    # blocks that aren't trailers, so skip this validation if this is a
    # response header or we're looking at trailer blocks.
    skip_validation = (
        hdr_validation_flags.is_response_header or
        hdr_validation_flags.is_trailer
    )
    if skip_validation:
        return (h for h in headers)

    return _validate_host_authority_header(headers)


def _combine_cookie_fields(headers: Iterable[Header], hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    RFC 7540 § 8.1.2.5 allows HTTP/2 clients to split the Cookie header field,
    which must normally appear only once, into multiple fields for better
    compression. However, they MUST be joined back up again when received.
    This normalization step applies that transform. The side-effect is that
    all cookie fields now appear *last* in the header block.
    """
    # There is a problem here about header indexing. Specifically, it's
    # possible that all these cookies are sent with different header indexing
    # values. At this point it shouldn't matter too much, so we apply our own
    # logic and make them never-indexed.
    cookies: list[bytes] = []
    for header in headers:
        if header[0] == b"cookie":
            cookies.append(header[1])
        else:
            yield header
    if cookies:
        cookie_val = b"; ".join(cookies)
        yield NeverIndexedHeaderTuple(b"cookie", cookie_val)


def _split_outbound_cookie_fields(headers: Iterable[Header],
                                  hdr_validation_flags: HeaderValidationFlags | None) -> Generator[Header, None, None]:
    """
    RFC 7540 § 8.1.2.5 allows for better compression efficiency,
    to split the Cookie header field into separate header fields

    We want to do it for outbound requests, as we are doing for
    inbound.
    """
    for header in headers:
        assert isinstance(header[0], bytes)
        assert isinstance(header[1], bytes)
        if header[0] == b"cookie":
            for cookie_val in header[1].split(b"; "):
                if isinstance(header, HeaderTuple):
                    yield header.__class__(header[0], cookie_val)
                else:
                    yield header[0], cookie_val
        else:
            yield header


def normalize_outbound_headers(headers: Iterable[Header],
                               hdr_validation_flags: HeaderValidationFlags | None,
                               should_split_outbound_cookies: bool=False) -> Generator[Header, None, None]:
    """
    Normalizes a header sequence that we are about to send.

    :param headers: The HTTP header set.
    :param hdr_validation_flags: An instance of HeaderValidationFlags.
    :param should_split_outbound_cookies: boolean flag
    """
    headers = _lowercase_header_names(headers, hdr_validation_flags)
    if should_split_outbound_cookies:
        headers = _split_outbound_cookie_fields(headers, hdr_validation_flags)
    headers = _strip_surrounding_whitespace(headers, hdr_validation_flags)
    headers = _strip_connection_headers(headers, hdr_validation_flags)
    return _secure_headers(headers, hdr_validation_flags)


def normalize_inbound_headers(headers: Iterable[Header],
                              hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Normalizes a header sequence that we have received.

    :param headers: The HTTP header set.
    :param hdr_validation_flags: An instance of HeaderValidationFlags
    """
    return _combine_cookie_fields(headers, hdr_validation_flags)


def validate_outbound_headers(headers: Iterable[Header],
                              hdr_validation_flags: HeaderValidationFlags) -> Generator[Header, None, None]:
    """
    Validates and normalizes a header sequence that we are about to send.

    :param headers: The HTTP header set.
    :param hdr_validation_flags: An instance of HeaderValidationFlags.
    """
    headers = _reject_te(
        headers, hdr_validation_flags,
    )
    headers = _reject_connection_header(
        headers, hdr_validation_flags,
    )
    headers = _reject_pseudo_header_fields(
        headers, hdr_validation_flags,
    )
    headers = _check_sent_host_authority_header(
        headers, hdr_validation_flags,
    )
    return _check_path_header(headers, hdr_validation_flags)


class SizeLimitDict(collections.OrderedDict[int, Any]):

    def __init__(self, *args: dict[int, int], **kwargs: Any) -> None:
        self._size_limit = kwargs.pop("size_limit", None)
        super().__init__(*args, **kwargs)

        self._check_size_limit()

    def __setitem__(self, key: int, value: Any | int) -> None:
        super().__setitem__(key, value)

        self._check_size_limit()

    def _check_size_limit(self) -> None:
        if self._size_limit is not None:
            while len(self) > self._size_limit:
                self.popitem(last=False)


# ---------------------------------------------------------------------------
# h2/windows.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/windows
~~~~~~~~~~

Defines tools for managing HTTP/2 flow control windows.

The objects defined in this module are used to automatically manage HTTP/2
flow control windows. Specifically, they keep track of what the size of the
window is, how much data has been consumed from that window, and how much data
the user has already used. It then implements a basic algorithm that attempts
to manage the flow control window without user input, trying to ensure that it
does not emit too many WINDOW_UPDATE frames.
"""


# The largest acceptable value for a HTTP/2 flow control window.
LARGEST_FLOW_CONTROL_WINDOW = 2**31 - 1


class WindowManager:
    """
    A basic HTTP/2 window manager.

    :param max_window_size: The maximum size of the flow control window.
    :type max_window_size: ``int``
    """

    def __init__(self, max_window_size: int) -> None:
        assert max_window_size <= LARGEST_FLOW_CONTROL_WINDOW
        self.max_window_size = max_window_size
        self.current_window_size = max_window_size
        self._bytes_processed = 0

    def window_consumed(self, size: int) -> None:
        """
        We have received a certain number of bytes from the remote peer. This
        necessarily shrinks the flow control window!

        :param size: The number of flow controlled bytes we received from the
            remote peer.
        :type size: ``int``
        :returns: Nothing.
        :rtype: ``None``
        """
        self.current_window_size -= size
        if self.current_window_size < 0:
            msg = "Flow control window shrunk below 0"
            raise FlowControlError(msg)

    def window_opened(self, size: int) -> None:
        """
        The flow control window has been incremented, either because of manual
        flow control management or because of the user changing the flow
        control settings. This can have the effect of increasing what we
        consider to be the "maximum" flow control window size.

        This does not increase our view of how many bytes have been processed,
        only of how much space is in the window.

        :param size: The increment to the flow control window we received.
        :type size: ``int``
        :returns: Nothing
        :rtype: ``None``
        """
        self.current_window_size += size

        if self.current_window_size > LARGEST_FLOW_CONTROL_WINDOW:
            msg = f"Flow control window mustn't exceed {LARGEST_FLOW_CONTROL_WINDOW}"
            raise FlowControlError(msg)

        self.max_window_size = max(self.current_window_size, self.max_window_size)

    def process_bytes(self, size: int) -> int | None:
        """
        The application has informed us that it has processed a certain number
        of bytes. This may cause us to want to emit a window update frame. If
        we do want to emit a window update frame, this method will return the
        number of bytes that we should increment the window by.

        :param size: The number of flow controlled bytes that the application
            has processed.
        :type size: ``int``
        :returns: The number of bytes to increment the flow control window by,
            or ``None``.
        :rtype: ``int`` or ``None``
        """
        self._bytes_processed += size
        return self._maybe_update_window()

    def _maybe_update_window(self) -> int | None:
        """
        Run the algorithm.

        Our current algorithm can be described like this.

        1. If no bytes have been processed, we immediately return 0. There is
           no meaningful way for us to hand space in the window back to the
           remote peer, so let's not even try.
        2. If there is no space in the flow control window, and we have
           processed at least 1024 bytes (or 1/4 of the window, if the window
           is smaller), we will emit a window update frame. This is to avoid
           the risk of blocking a stream altogether.
        3. If there is space in the flow control window, and we have processed
           at least 1/2 of the window worth of bytes, we will emit a window
           update frame. This is to minimise the number of window update frames
           we have to emit.

        In a healthy system with large flow control windows, this will
        irregularly emit WINDOW_UPDATE frames. This prevents us starving the
        connection by emitting eleventy bajillion WINDOW_UPDATE frames,
        especially in situations where the remote peer is sending a lot of very
        small DATA frames.
        """
        # TODO: Can the window be smaller than 1024 bytes? If not, we can
        # streamline this algorithm.
        if not self._bytes_processed:
            return None

        max_increment = (self.max_window_size - self.current_window_size)
        increment = 0

        # Note that, even though we may increment less than _bytes_processed,
        # we still want to set it to zero whenever we emit an increment. This
        # is because we'll always increment up to the maximum we can.
        if ((self.current_window_size == 0) and (
                self._bytes_processed > min(1024, self.max_window_size // 4))) or self._bytes_processed >= (self.max_window_size // 2):
            increment = min(self._bytes_processed, max_increment)
            self._bytes_processed = 0

        self.current_window_size += increment
        return increment


# ---------------------------------------------------------------------------
# h2/stream.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/stream
~~~~~~~~~

An implementation of a HTTP/2 stream.
"""

from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Generator, Iterable


class StreamState(IntEnum):
    IDLE = 0
    RESERVED_REMOTE = 1
    RESERVED_LOCAL = 2
    OPEN = 3
    HALF_CLOSED_REMOTE = 4
    HALF_CLOSED_LOCAL = 5
    CLOSED = 6


class StreamInputs(Enum):
    SEND_HEADERS = 0
    SEND_PUSH_PROMISE = 1
    SEND_RST_STREAM = 2
    SEND_DATA = 3
    SEND_WINDOW_UPDATE = 4
    SEND_END_STREAM = 5
    RECV_HEADERS = 6
    RECV_PUSH_PROMISE = 7
    RECV_RST_STREAM = 8
    RECV_DATA = 9
    RECV_WINDOW_UPDATE = 10
    RECV_END_STREAM = 11
    RECV_CONTINUATION = 12  # Added in 2.0.0
    SEND_INFORMATIONAL_HEADERS = 13  # Added in 2.2.0
    RECV_INFORMATIONAL_HEADERS = 14  # Added in 2.2.0
    SEND_ALTERNATIVE_SERVICE = 15  # Added in 2.3.0
    RECV_ALTERNATIVE_SERVICE = 16  # Added in 2.3.0
    UPGRADE_CLIENT = 17  # Added 2.3.0
    UPGRADE_SERVER = 18  # Added 2.3.0


class StreamClosedBy(Enum):
    SEND_END_STREAM = 0
    RECV_END_STREAM = 1
    SEND_RST_STREAM = 2
    RECV_RST_STREAM = 3


# This array is initialized once, and is indexed by the stream states above.
# It indicates whether a stream in the given state is open. The reason we do
# this is that we potentially check whether a stream in a given state is open
# quite frequently: given that we check so often, we should do so in the
# fastest and most performant way possible.
STREAM_OPEN = [False for _ in range(len(StreamState))]
STREAM_OPEN[StreamState.OPEN] = True
STREAM_OPEN[StreamState.HALF_CLOSED_LOCAL] = True
STREAM_OPEN[StreamState.HALF_CLOSED_REMOTE] = True


class H2StreamStateMachine:
    """
    A single HTTP/2 stream state machine.

    This stream object implements basically the state machine described in
    RFC 7540 section 5.1.

    :param stream_id: The stream ID of this stream. This is stored primarily
        for logging purposes.
    """

    def __init__(self, stream_id: int) -> None:
        self.state = StreamState.IDLE
        self.stream_id = stream_id

        #: Whether this peer is the client side of this stream.
        self.client: bool | None = None

        # Whether trailers have been sent/received on this stream or not.
        self.headers_sent: bool | None = None
        self.trailers_sent: bool | None = None
        self.headers_received: bool | None = None
        self.trailers_received: bool | None = None

        # How the stream was closed. One of StreamClosedBy.
        self.stream_closed_by: StreamClosedBy | None = None

    def process_input(self, input_: StreamInputs) -> list[Event]:
        """
        Process a specific input in the state machine.
        """
        if not isinstance(input_, StreamInputs):
            msg = "Input must be an instance of StreamInputs"
            raise ValueError(msg)  # noqa: TRY004

        try:
            func, target_state = _transitions[(self.state, input_)]
        except KeyError as err:
            old_state = self.state
            self.state = StreamState.CLOSED
            msg = f"Invalid input {input_} in state {old_state}"
            raise ProtocolError(msg) from err
        else:
            previous_state = self.state
            self.state = target_state
            if func is not None:
                try:
                    return func(self, previous_state)
                except ProtocolError:
                    self.state = StreamState.CLOSED
                    raise
                except AssertionError as err:  # pragma: no cover
                    self.state = StreamState.CLOSED
                    raise ProtocolError(err) from err

            return []

    def request_sent(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when a request is sent.
        """
        self.client = True
        self.headers_sent = True
        event = _RequestSent()

        return [event]

    def response_sent(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when something that should be a response is sent. This 'response'
        may actually be trailers.
        """
        if not self.headers_sent:
            if self.client is True or self.client is None:
                msg = "Client cannot send responses."
                raise ProtocolError(msg)
            self.headers_sent = True
            return [_ResponseSent()]
        assert not self.trailers_sent
        self.trailers_sent = True
        return [_TrailersSent()]

    def request_received(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when a request is received.
        """
        assert not self.headers_received
        assert not self.trailers_received

        self.client = False
        self.headers_received = True
        event = RequestReceived(stream_id=self.stream_id)
        return [event]

    def response_received(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when a response is received. Also disambiguates between responses
        and trailers.
        """
        event: ResponseReceived | TrailersReceived
        if not self.headers_received:
            assert self.client is True
            self.headers_received = True
            event = ResponseReceived(stream_id=self.stream_id)
        else:
            assert not self.trailers_received
            self.trailers_received = True
            event = TrailersReceived(stream_id=self.stream_id)

        event.stream_id = self.stream_id
        return [event]

    def data_received(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when data is received.
        """
        if not self.headers_received:
            msg = "cannot receive data before headers"
            raise ProtocolError(msg)
        event = DataReceived(stream_id=self.stream_id)
        return [event]

    def window_updated(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when a window update frame is received.
        """
        return [WindowUpdated(stream_id=self.stream_id)]

    def stream_half_closed(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when an END_STREAM flag is received in the OPEN state,
        transitioning this stream to a HALF_CLOSED_REMOTE state.
        """
        event = StreamEnded(stream_id=self.stream_id)
        return [event]

    def stream_ended(self, previous_state: StreamState) -> list[Event]:
        """
        Fires when a stream is cleanly ended.
        """
        self.stream_closed_by = StreamClosedBy.RECV_END_STREAM
        event = StreamEnded(stream_id=self.stream_id)
        return [event]

    def stream_reset(self, previous_state: StreamState) -> list[Event]:
        """
        Fired when a stream is forcefully reset.
        """
        self.stream_closed_by = StreamClosedBy.RECV_RST_STREAM
        return [StreamReset(stream_id=self.stream_id)]

    def send_new_pushed_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Fires on the newly pushed stream, when pushed by the local peer.

        No event here, but definitionally this peer must be a server.
        """
        assert self.client is None
        self.client = False
        self.headers_received = True
        return []

    def recv_new_pushed_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Fires on the newly pushed stream, when pushed by the remote peer.

        No event here, but definitionally this peer must be a client.
        """
        assert self.client is None
        self.client = True
        self.headers_sent = True
        return []

    def send_push_promise(self, previous_state: StreamState) -> list[Event]:
        """
        Fires on the already-existing stream when a PUSH_PROMISE frame is sent.
        We may only send PUSH_PROMISE frames if we're a server.
        """
        if self.client is True:
            msg = "Cannot push streams from client peers."
            raise ProtocolError(msg)

        event = _PushedRequestSent()
        return [event]

    def recv_push_promise(self, previous_state: StreamState) -> list[Event]:
        """
        Fires on the already-existing stream when a PUSH_PROMISE frame is
        received. We may only receive PUSH_PROMISE frames if we're a client.

        Fires a PushedStreamReceived event.
        """
        if not self.client:
            if self.client is None:  # pragma: no cover
                msg = "Idle streams cannot receive pushes"
            else:  # pragma: no cover
                msg = "Cannot receive pushed streams as a server"
            raise ProtocolError(msg)

        event = PushedStreamReceived()
        event.parent_stream_id = self.stream_id
        return [event]

    def send_end_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an attempt is made to send END_STREAM in the
        HALF_CLOSED_REMOTE state.
        """
        self.stream_closed_by = StreamClosedBy.SEND_END_STREAM
        return []

    def send_reset_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an attempt is made to send RST_STREAM in a non-closed
        stream state.
        """
        self.stream_closed_by = StreamClosedBy.SEND_RST_STREAM
        return []

    def reset_stream_on_error(self, previous_state: StreamState) -> list[Event]:
        """
        Called when we need to forcefully emit another RST_STREAM frame on
        behalf of the state machine.

        If this is the first time we've done this, we should also hang an event
        off the StreamClosedError so that the user can be informed. We know
        it's the first time we've done this if the stream is currently in a
        state other than CLOSED.
        """
        self.stream_closed_by = StreamClosedBy.SEND_RST_STREAM

        error = StreamClosedError(self.stream_id)
        error._events = [
            StreamReset(
                stream_id=self.stream_id,
                error_code=ErrorCodes.STREAM_CLOSED,
                remote_reset=False,
            ),
        ]
        raise error

    def recv_on_closed_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an unexpected frame is received on an already-closed
        stream.

        An endpoint that receives an unexpected frame should treat it as
        a stream error or connection error with type STREAM_CLOSED, depending
        on the specific frame. The error handling is done at a higher level:
        this just raises the appropriate error.
        """
        raise StreamClosedError(self.stream_id)

    def send_on_closed_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an attempt is made to send data on an already-closed
        stream.

        This essentially overrides the standard logic by throwing a
        more-specific error: StreamClosedError. This is a ProtocolError, so it
        matches the standard API of the state machine, but provides more detail
        to the user.
        """
        raise StreamClosedError(self.stream_id)

    def recv_push_on_closed_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Called when a PUSH_PROMISE frame is received on a full stop
        stream.

        If the stream was closed by us sending a RST_STREAM frame, then we
        presume that the PUSH_PROMISE was in flight when we reset the parent
        stream. Rathen than accept the new stream, we just reset it.
        Otherwise, we should call this a PROTOCOL_ERROR: pushing a stream on a
        naturally closed stream is a real problem because it creates a brand
        new stream that the remote peer now believes exists.
        """
        assert self.stream_closed_by is not None

        if self.stream_closed_by == StreamClosedBy.SEND_RST_STREAM:
            raise StreamClosedError(self.stream_id)
        msg = "Attempted to push on closed stream."
        raise ProtocolError(msg)

    def send_push_on_closed_stream(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an attempt is made to push on an already-closed stream.

        This essentially overrides the standard logic by providing a more
        useful error message. It's necessary because simply indicating that the
        stream is closed is not enough: there is now a new stream that is not
        allowed to be there. The only recourse is to tear the whole connection
        down.
        """
        msg = "Attempted to push on closed stream."
        raise ProtocolError(msg)

    def send_informational_response(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an informational header block is sent (that is, a block
        where the :status header has a 1XX value).

        Only enforces that these are sent *before* final headers are sent.
        """
        if self.headers_sent:
            msg = "Information response after final response"
            raise ProtocolError(msg)

        event = _ResponseSent()
        return [event]

    def recv_informational_response(self, previous_state: StreamState) -> list[Event]:
        """
        Called when an informational header block is received (that is, a block
        where the :status header has a 1XX value).
        """
        if self.headers_received:
            msg = "Informational response after final response"
            raise ProtocolError(msg)

        return [InformationalResponseReceived(stream_id=self.stream_id)]

    def recv_alt_svc(self, previous_state: StreamState) -> list[Event]:
        """
        Called when receiving an ALTSVC frame.

        RFC 7838 allows us to receive ALTSVC frames at any stream state, which
        is really absurdly overzealous. For that reason, we want to limit the
        states in which we can actually receive it. It's really only sensible
        to receive it after we've sent our own headers and before the server
        has sent its header block: the server can't guarantee that we have any
        state around after it completes its header block, and the server
        doesn't know what origin we're talking about before we've sent ours.

        For that reason, this function applies a few extra checks on both state
        and some of the little state variables we keep around. If those suggest
        an unreasonable situation for the ALTSVC frame to have been sent in,
        we quietly ignore it (as RFC 7838 suggests).

        This function is also *not* always called by the state machine. In some
        states (IDLE, RESERVED_LOCAL, CLOSED) we don't bother to call it,
        because we know the frame cannot be valid in that state (IDLE because
        the server cannot know what origin the stream applies to, CLOSED
        because the server cannot assume we still have state around,
        RESERVED_LOCAL because by definition if we're in the RESERVED_LOCAL
        state then *we* are the server).
        """
        # Servers can't receive ALTSVC frames, but RFC 7838 tells us to ignore
        # them.
        if self.client is False:
            return []

        # If we've received the response headers from the server they can't
        # guarantee we still have any state around. Other implementations
        # (like nghttp2) ignore ALTSVC in this state, so we will too.
        if self.headers_received:
            return []

        # Otherwise, this is a sensible enough frame to have received. Return
        # the event and let it get populated.
        return [AlternativeServiceAvailable()]

    def send_alt_svc(self, previous_state: StreamState) -> list[Event]:
        """
        Called when sending an ALTSVC frame on this stream.

        For consistency with the restrictions we apply on receiving ALTSVC
        frames in ``recv_alt_svc``, we want to restrict when users can send
        ALTSVC frames to the situations when we ourselves would accept them.

        That means: when we are a server, when we have received the request
        headers, and when we have not yet sent our own response headers.
        """
        # We should not send ALTSVC after we've sent response headers, as the
        # client may have disposed of its state.
        if self.headers_sent:
            msg = "Cannot send ALTSVC after sending response headers."
            raise ProtocolError(msg)
        return []


# STATE MACHINE
#
# The stream state machine is defined here to avoid the need to allocate it
# repeatedly for each stream. It cannot be defined in the stream class because
# it needs to be able to reference the callbacks defined on the class, but
# because Python's scoping rules are weird the class object is not actually in
# scope during the body of the class object.
#
# For the sake of clarity, we reproduce the RFC 7540 state machine here:
#
#                          +--------+
#                  send PP |        | recv PP
#                 ,--------|  idle  |--------.
#                /         |        |         \
#               v          +--------+          v
#        +----------+          |           +----------+
#        |          |          | send H /  |          |
# ,------| reserved |          | recv H    | reserved |------.
# |      | (local)  |          |           | (remote) |      |
# |      +----------+          v           +----------+      |
# |          |             +--------+             |          |
# |          |     recv ES |        | send ES     |          |
# |   send H |     ,-------|  open  |-------.     | recv H   |
# |          |    /        |        |        \    |          |
# |          v   v         +--------+         v   v          |
# |      +----------+          |           +----------+      |
# |      |   half   |          |           |   half   |      |
# |      |  closed  |          | send R /  |  closed  |      |
# |      | (remote) |          | recv R    | (local)  |      |
# |      +----------+          |           +----------+      |
# |           |                |                 |           |
# |           | send ES /      |       recv ES / |           |
# |           | send R /       v        send R / |           |
# |           | recv R     +--------+   recv R   |           |
# | send R /  `----------->|        |<-----------'  send R / |
# | recv R                 | closed |               recv R   |
# `----------------------->|        |<----------------------'
#                          +--------+
#
#    send:   endpoint sends this frame
#    recv:   endpoint receives this frame
#
#    H:  HEADERS frame (with implied CONTINUATIONs)
#    PP: PUSH_PROMISE frame (with implied CONTINUATIONs)
#    ES: END_STREAM flag
#    R:  RST_STREAM frame
#
# For the purposes of this state machine we treat HEADERS and their
# associated CONTINUATION frames as a single jumbo frame. The protocol
# allows/requires this by preventing other frames from being interleved in
# between HEADERS/CONTINUATION frames. However, if a CONTINUATION frame is
# received without a prior HEADERS frame, it *will* be passed to this state
# machine. The state machine should always reject that frame, either as an
# invalid transition or because the stream is closed.
#
# There is a confusing relationship around PUSH_PROMISE frames. The state
# machine above considers them to be frames belonging to the new stream,
# which is *somewhat* true. However, they are sent with the stream ID of
# their related stream, and are only sendable in some cases.
# For this reason, our state machine implementation below allows for
# PUSH_PROMISE frames both in the IDLE state (as in the diagram), but also
# in the OPEN, HALF_CLOSED_LOCAL, and HALF_CLOSED_REMOTE states.
# Essentially, for h2, PUSH_PROMISE frames are effectively sent on
# two streams.
#
# The _transitions dictionary contains a mapping of tuples of
# (state, input) to tuples of (side_effect_function, end_state). This
# map contains all allowed transitions: anything not in this map is
# invalid and immediately causes a transition to ``closed``.
_transitions: dict[
    tuple[StreamState, StreamInputs],
    tuple[Callable[[H2StreamStateMachine, StreamState], list[Event]] | None, StreamState],
] = {
    # State: idle
    (StreamState.IDLE, StreamInputs.SEND_HEADERS):
        (H2StreamStateMachine.request_sent, StreamState.OPEN),
    (StreamState.IDLE, StreamInputs.RECV_HEADERS):
        (H2StreamStateMachine.request_received, StreamState.OPEN),
    (StreamState.IDLE, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.reset_stream_on_error, StreamState.CLOSED),
    (StreamState.IDLE, StreamInputs.SEND_PUSH_PROMISE):
        (H2StreamStateMachine.send_new_pushed_stream,
            StreamState.RESERVED_LOCAL),
    (StreamState.IDLE, StreamInputs.RECV_PUSH_PROMISE):
        (H2StreamStateMachine.recv_new_pushed_stream,
            StreamState.RESERVED_REMOTE),
    (StreamState.IDLE, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (None, StreamState.IDLE),
    (StreamState.IDLE, StreamInputs.UPGRADE_CLIENT):
        (H2StreamStateMachine.request_sent, StreamState.HALF_CLOSED_LOCAL),
    (StreamState.IDLE, StreamInputs.UPGRADE_SERVER):
        (H2StreamStateMachine.request_received,
            StreamState.HALF_CLOSED_REMOTE),

    # State: reserved local
    (StreamState.RESERVED_LOCAL, StreamInputs.SEND_HEADERS):
        (H2StreamStateMachine.response_sent, StreamState.HALF_CLOSED_REMOTE),
    (StreamState.RESERVED_LOCAL, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.reset_stream_on_error, StreamState.CLOSED),
    (StreamState.RESERVED_LOCAL, StreamInputs.SEND_WINDOW_UPDATE):
        (None, StreamState.RESERVED_LOCAL),
    (StreamState.RESERVED_LOCAL, StreamInputs.RECV_WINDOW_UPDATE):
        (H2StreamStateMachine.window_updated, StreamState.RESERVED_LOCAL),
    (StreamState.RESERVED_LOCAL, StreamInputs.SEND_RST_STREAM):
        (H2StreamStateMachine.send_reset_stream, StreamState.CLOSED),
    (StreamState.RESERVED_LOCAL, StreamInputs.RECV_RST_STREAM):
        (H2StreamStateMachine.stream_reset, StreamState.CLOSED),
    (StreamState.RESERVED_LOCAL, StreamInputs.SEND_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.send_alt_svc, StreamState.RESERVED_LOCAL),
    (StreamState.RESERVED_LOCAL, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (None, StreamState.RESERVED_LOCAL),

    # State: reserved remote
    (StreamState.RESERVED_REMOTE, StreamInputs.RECV_HEADERS):
        (H2StreamStateMachine.response_received,
            StreamState.HALF_CLOSED_LOCAL),
    (StreamState.RESERVED_REMOTE, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.reset_stream_on_error, StreamState.CLOSED),
    (StreamState.RESERVED_REMOTE, StreamInputs.SEND_WINDOW_UPDATE):
        (None, StreamState.RESERVED_REMOTE),
    (StreamState.RESERVED_REMOTE, StreamInputs.RECV_WINDOW_UPDATE):
        (H2StreamStateMachine.window_updated, StreamState.RESERVED_REMOTE),
    (StreamState.RESERVED_REMOTE, StreamInputs.SEND_RST_STREAM):
        (H2StreamStateMachine.send_reset_stream, StreamState.CLOSED),
    (StreamState.RESERVED_REMOTE, StreamInputs.RECV_RST_STREAM):
        (H2StreamStateMachine.stream_reset, StreamState.CLOSED),
    (StreamState.RESERVED_REMOTE, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.recv_alt_svc, StreamState.RESERVED_REMOTE),

    # State: open
    (StreamState.OPEN, StreamInputs.SEND_HEADERS):
        (H2StreamStateMachine.response_sent, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.RECV_HEADERS):
        (H2StreamStateMachine.response_received, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.SEND_DATA):
        (None, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.data_received, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.SEND_END_STREAM):
        (None, StreamState.HALF_CLOSED_LOCAL),
    (StreamState.OPEN, StreamInputs.RECV_END_STREAM):
        (H2StreamStateMachine.stream_half_closed,
         StreamState.HALF_CLOSED_REMOTE),
    (StreamState.OPEN, StreamInputs.SEND_WINDOW_UPDATE):
        (None, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.RECV_WINDOW_UPDATE):
        (H2StreamStateMachine.window_updated, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.SEND_RST_STREAM):
        (H2StreamStateMachine.send_reset_stream, StreamState.CLOSED),
    (StreamState.OPEN, StreamInputs.RECV_RST_STREAM):
        (H2StreamStateMachine.stream_reset, StreamState.CLOSED),
    (StreamState.OPEN, StreamInputs.SEND_PUSH_PROMISE):
        (H2StreamStateMachine.send_push_promise, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.RECV_PUSH_PROMISE):
        (H2StreamStateMachine.recv_push_promise, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.SEND_INFORMATIONAL_HEADERS):
        (H2StreamStateMachine.send_informational_response, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.RECV_INFORMATIONAL_HEADERS):
        (H2StreamStateMachine.recv_informational_response, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.SEND_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.send_alt_svc, StreamState.OPEN),
    (StreamState.OPEN, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.recv_alt_svc, StreamState.OPEN),

    # State: half-closed remote
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_HEADERS):
        (H2StreamStateMachine.response_sent, StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.RECV_HEADERS):
        (H2StreamStateMachine.reset_stream_on_error, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_DATA):
        (None, StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.reset_stream_on_error, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_END_STREAM):
        (H2StreamStateMachine.send_end_stream, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_WINDOW_UPDATE):
        (None, StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.RECV_WINDOW_UPDATE):
        (H2StreamStateMachine.window_updated, StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_RST_STREAM):
        (H2StreamStateMachine.send_reset_stream, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.RECV_RST_STREAM):
        (H2StreamStateMachine.stream_reset, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_PUSH_PROMISE):
        (H2StreamStateMachine.send_push_promise,
            StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.RECV_PUSH_PROMISE):
        (H2StreamStateMachine.reset_stream_on_error, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_INFORMATIONAL_HEADERS):
        (H2StreamStateMachine.send_informational_response,
            StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.SEND_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.send_alt_svc, StreamState.HALF_CLOSED_REMOTE),
    (StreamState.HALF_CLOSED_REMOTE, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.recv_alt_svc, StreamState.HALF_CLOSED_REMOTE),

    # State: half-closed local
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_HEADERS):
        (H2StreamStateMachine.response_received,
            StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.data_received, StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_END_STREAM):
        (H2StreamStateMachine.stream_ended, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.SEND_WINDOW_UPDATE):
        (None, StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_WINDOW_UPDATE):
        (H2StreamStateMachine.window_updated, StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.SEND_RST_STREAM):
        (H2StreamStateMachine.send_reset_stream, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_RST_STREAM):
        (H2StreamStateMachine.stream_reset, StreamState.CLOSED),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_PUSH_PROMISE):
        (H2StreamStateMachine.recv_push_promise,
            StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_INFORMATIONAL_HEADERS):
        (H2StreamStateMachine.recv_informational_response,
            StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.SEND_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.send_alt_svc, StreamState.HALF_CLOSED_LOCAL),
    (StreamState.HALF_CLOSED_LOCAL, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (H2StreamStateMachine.recv_alt_svc, StreamState.HALF_CLOSED_LOCAL),

    # State: closed
    (StreamState.CLOSED, StreamInputs.RECV_END_STREAM):
        (None, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.RECV_ALTERNATIVE_SERVICE):
        (None, StreamState.CLOSED),

    # RFC 7540 Section 5.1 defines how the end point should react when
    # receiving a frame on a closed stream with the following statements:
    #
    # > An endpoint that receives any frame other than PRIORITY after receiving
    # > a RST_STREAM MUST treat that as a stream error of type STREAM_CLOSED.
    # > An endpoint that receives any frames after receiving a frame with the
    # > END_STREAM flag set MUST treat that as a connection error of type
    # > STREAM_CLOSED.
    (StreamState.CLOSED, StreamInputs.RECV_HEADERS):
        (H2StreamStateMachine.recv_on_closed_stream, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.RECV_DATA):
        (H2StreamStateMachine.recv_on_closed_stream, StreamState.CLOSED),

    # > WINDOW_UPDATE or RST_STREAM frames can be received in this state
    # > for a short period after a DATA or HEADERS frame containing a
    # > END_STREAM flag is sent, as instructed in RFC 7540 Section 5.1. But we
    # > don't have access to a clock so we just always allow it.
    (StreamState.CLOSED, StreamInputs.RECV_WINDOW_UPDATE):
        (None, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.RECV_RST_STREAM):
        (None, StreamState.CLOSED),

    # > A receiver MUST treat the receipt of a PUSH_PROMISE on a stream that is
    # > neither "open" nor "half-closed (local)" as a connection error of type
    # > PROTOCOL_ERROR.
    (StreamState.CLOSED, StreamInputs.RECV_PUSH_PROMISE):
        (H2StreamStateMachine.recv_push_on_closed_stream, StreamState.CLOSED),

    # Also, users should be forbidden from sending on closed streams.
    (StreamState.CLOSED, StreamInputs.SEND_HEADERS):
        (H2StreamStateMachine.send_on_closed_stream, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.SEND_PUSH_PROMISE):
        (H2StreamStateMachine.send_push_on_closed_stream, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.SEND_RST_STREAM):
        (H2StreamStateMachine.send_on_closed_stream, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.SEND_DATA):
        (H2StreamStateMachine.send_on_closed_stream, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.SEND_WINDOW_UPDATE):
        (H2StreamStateMachine.send_on_closed_stream, StreamState.CLOSED),
    (StreamState.CLOSED, StreamInputs.SEND_END_STREAM):
        (H2StreamStateMachine.send_on_closed_stream, StreamState.CLOSED),
}


class H2Stream:
    """
    A low-level HTTP/2 stream object. This handles building and receiving
    frames and maintains per-stream state.

    This wraps a HTTP/2 Stream state machine implementation, ensuring that
    frames can only be sent/received when the stream is in a valid state.
    Attempts to create frames that cannot be sent will raise a
    ``ProtocolError``.
    """

    def __init__(self,
                 stream_id: int,
                 config: H2Configuration,
                 inbound_window_size: int,
                 outbound_window_size: int) -> None:
        self.state_machine = H2StreamStateMachine(stream_id)
        self.stream_id = stream_id
        self.max_outbound_frame_size: int | None = None
        self.request_method: bytes | None = None

        # The current value of the outbound stream flow control window
        self.outbound_flow_control_window = outbound_window_size

        # The flow control manager.
        self._inbound_window_manager = WindowManager(inbound_window_size)

        # The expected content length, if any.
        self._expected_content_length: int | None = None

        # The actual received content length. Always tracked.
        self._actual_content_length = 0

        # The authority we believe this stream belongs to.
        self._authority: bytes | None = None

        # The configuration for this stream.
        self.config = config

    def __repr__(self) -> str:
        return f"<{type(self).__name__} id:{self.stream_id} state:{self.state_machine.state!r}>"

    @property
    def inbound_flow_control_window(self) -> int:
        """
        The size of the inbound flow control window for the stream. This is
        rarely publicly useful: instead, use :meth:`remote_flow_control_window
        <h2.stream.H2Stream.remote_flow_control_window>`. This shortcut is
        largely present to provide a shortcut to this data.
        """
        return self._inbound_window_manager.current_window_size

    @property
    def open(self) -> bool:
        """
        Whether the stream is 'open' in any sense: that is, whether it counts
        against the number of concurrent streams.
        """
        # RFC 7540 Section 5.1.2 defines 'open' for this purpose to mean either
        # the OPEN state or either of the HALF_CLOSED states. Perplexingly,
        # this excludes the reserved states.
        # For more detail on why we're doing this in this slightly weird way,
        # see the comment on ``STREAM_OPEN`` at the top of the file.
        return STREAM_OPEN[self.state_machine.state]

    @property
    def closed(self) -> bool:
        """
        Whether the stream is closed.
        """
        return self.state_machine.state == StreamState.CLOSED

    @property
    def closed_by(self) -> StreamClosedBy | None:
        """
        Returns how the stream was closed, as one of StreamClosedBy.
        """
        return self.state_machine.stream_closed_by

    def upgrade(self, client_side: bool) -> None:
        """
        Called by the connection to indicate that this stream is the initial
        request/response of an upgraded connection. Places the stream into an
        appropriate state.
        """
        self.config.logger.debug("Upgrading %r", self)

        assert self.stream_id == 1
        input_ = (
            StreamInputs.UPGRADE_CLIENT if client_side
            else StreamInputs.UPGRADE_SERVER
        )

        # This may return events, we deliberately don't want them.
        self.state_machine.process_input(input_)

    def send_headers(self,
                     headers: Iterable[HeaderWeaklyTyped],
                     encoder: Encoder,
                     end_stream: bool = False) -> list[HeadersFrame | ContinuationFrame | PushPromiseFrame]:
        """
        Returns a list of HEADERS/CONTINUATION frames to emit as either headers
        or trailers.
        """
        self.config.logger.debug("Send headers %s on %r", headers, self)

        # Because encoding headers makes an irreversible change to the header
        # compression context, we make the state transition before we encode
        # them.

        # First, check if we're a client. If we are, no problem: if we aren't,
        # we need to scan the header block to see if this is an informational
        # response.
        input_ = StreamInputs.SEND_HEADERS

        bytes_headers = utf8_encode_headers(headers)

        if ((not self.state_machine.client) and
                is_informational_response(bytes_headers)):
            if end_stream:
                msg = "Cannot set END_STREAM on informational responses."
                raise ProtocolError(msg)

            input_ = StreamInputs.SEND_INFORMATIONAL_HEADERS

        events = self.state_machine.process_input(input_)

        hf = HeadersFrame(self.stream_id)
        hdr_validation_flags = self._build_hdr_validation_flags(events)
        frames = self._build_headers_frames(
            bytes_headers, encoder, hf, hdr_validation_flags,
        )

        if end_stream:
            # Not a bug: the END_STREAM flag is valid on the initial HEADERS
            # frame, not the CONTINUATION frames that follow.
            self.state_machine.process_input(StreamInputs.SEND_END_STREAM)
            frames[0].flags.add("END_STREAM")

        if self.state_machine.trailers_sent and not end_stream:
            msg = "Trailers must have END_STREAM set."
            raise ProtocolError(msg)

        if self.state_machine.client and self._authority is None:
            self._authority = authority_from_headers(bytes_headers)

        # store request method for _initialize_content_length
        self.request_method = extract_method_header(bytes_headers)

        return frames

    def push_stream_in_band(self,
                            related_stream_id: int,
                            headers: Iterable[HeaderWeaklyTyped],
                            encoder: Encoder) -> list[HeadersFrame | ContinuationFrame | PushPromiseFrame]:
        """
        Returns a list of PUSH_PROMISE/CONTINUATION frames to emit as a pushed
        stream header. Called on the stream that has the PUSH_PROMISE frame
        sent on it.
        """
        self.config.logger.debug("Push stream %r", self)

        # Because encoding headers makes an irreversible change to the header
        # compression context, we make the state transition *first*.

        events = self.state_machine.process_input(
            StreamInputs.SEND_PUSH_PROMISE,
        )

        ppf = PushPromiseFrame(self.stream_id)
        ppf.promised_stream_id = related_stream_id
        hdr_validation_flags = self._build_hdr_validation_flags(events)

        bytes_headers = utf8_encode_headers(headers)

        return self._build_headers_frames(
            bytes_headers, encoder, ppf, hdr_validation_flags,
        )


    def locally_pushed(self) -> list[Frame]:
        """
        Mark this stream as one that was pushed by this peer. Must be called
        immediately after initialization. Sends no frames, simply updates the
        state machine.
        """
        # This does not trigger any events.
        events = self.state_machine.process_input(
            StreamInputs.SEND_PUSH_PROMISE,
        )
        assert not events
        return []

    def send_data(self,
                  data: bytes | memoryview,
                  end_stream: bool = False,
                  pad_length: int | None = None) -> list[Frame]:
        """
        Prepare some data frames. Optionally end the stream.

        .. warning:: Does not perform flow control checks.
        """
        self.config.logger.debug(
            "Send data on %r with end stream set to %s", self, end_stream,
        )

        self.state_machine.process_input(StreamInputs.SEND_DATA)

        df = DataFrame(self.stream_id)
        if isinstance(data, memoryview):
            df.data = data.tobytes()
        else:
            df.data = data
        if end_stream:
            self.state_machine.process_input(StreamInputs.SEND_END_STREAM)
            df.flags.add("END_STREAM")
        if pad_length is not None:
            df.flags.add("PADDED")
            df.pad_length = pad_length

        # Subtract flow_controlled_length to account for possible padding
        self.outbound_flow_control_window -= df.flow_controlled_length
        assert self.outbound_flow_control_window >= 0 or df.flow_controlled_length == 0

        return [df]

    def end_stream(self) -> list[Frame]:
        """
        End a stream without sending data.
        """
        self.config.logger.debug("End stream %r", self)

        self.state_machine.process_input(StreamInputs.SEND_END_STREAM)
        df = DataFrame(self.stream_id)
        df.flags.add("END_STREAM")
        return [df]

    def advertise_alternative_service(self, field_value: bytes) -> list[Frame]:
        """
        Advertise an RFC 7838 alternative service. The semantics of this are
        better documented in the ``H2Connection`` class.
        """
        self.config.logger.debug(
            "Advertise alternative service of %r for %r", field_value, self,
        )
        self.state_machine.process_input(StreamInputs.SEND_ALTERNATIVE_SERVICE)
        asf = AltSvcFrame(self.stream_id)
        asf.field = field_value
        return [asf]

    def increase_flow_control_window(self, increment: int) -> list[Frame]:
        """
        Increase the size of the flow control window for the remote side.
        """
        self.config.logger.debug(
            "Increase flow control window for %r by %d",
            self, increment,
        )
        self.state_machine.process_input(StreamInputs.SEND_WINDOW_UPDATE)
        self._inbound_window_manager.window_opened(increment)

        wuf = WindowUpdateFrame(self.stream_id)
        wuf.window_increment = increment
        return [wuf]

    def receive_push_promise_in_band(self,
                                     promised_stream_id: int,
                                     headers: Iterable[Header],
                                     header_encoding: bool | str | None) -> tuple[list[Frame], list[Event]]:
        """
        Receives a push promise frame sent on this stream, pushing a remote
        stream. This is called on the stream that has the PUSH_PROMISE sent
        on it.
        """
        self.config.logger.debug(
            "Receive Push Promise on %r for remote stream %d",
            self, promised_stream_id,
        )
        events = self.state_machine.process_input(
            StreamInputs.RECV_PUSH_PROMISE,
        )
        push_event = cast("PushedStreamReceived", events[0])
        push_event.pushed_stream_id = promised_stream_id

        hdr_validation_flags = self._build_hdr_validation_flags(events)
        push_event.headers = self._process_received_headers(
            headers, hdr_validation_flags, header_encoding,
        )
        return [], events

    def remotely_pushed(self, pushed_headers: Iterable[Header]) -> tuple[list[Frame], list[Event]]:
        """
        Mark this stream as one that was pushed by the remote peer. Must be
        called immediately after initialization. Sends no frames, simply
        updates the state machine.
        """
        self.config.logger.debug("%r pushed by remote peer", self)
        events = self.state_machine.process_input(
            StreamInputs.RECV_PUSH_PROMISE,
        )
        self._authority = authority_from_headers(pushed_headers)
        return [], events

    def receive_headers(self,
                        headers: Iterable[Header],
                        end_stream: bool,
                        header_encoding: bool | str | None) -> tuple[list[Frame], list[Event]]:
        """
        Receive a set of headers (or trailers).
        """
        if is_informational_response(headers):
            if end_stream:
                msg = "Cannot set END_STREAM on informational responses"
                raise ProtocolError(msg)
            input_ = StreamInputs.RECV_INFORMATIONAL_HEADERS
        else:
            input_ = StreamInputs.RECV_HEADERS

        events = self.state_machine.process_input(input_)
        headers_event = cast(
            "RequestReceived | ResponseReceived | TrailersReceived | InformationalResponseReceived",
            events[0],
        )

        if end_stream:
            es_events = self.state_machine.process_input(
                StreamInputs.RECV_END_STREAM,
            )
            # We ensured it's not an information response at the beginning of the method.
            cast(
                "RequestReceived | ResponseReceived | TrailersReceived",
                headers_event,
            ).stream_ended = cast("StreamEnded", es_events[0])
            events += es_events

        self._initialize_content_length(headers)

        if isinstance(headers_event, TrailersReceived) and not end_stream:
            msg = "Trailers must have END_STREAM set"
            raise ProtocolError(msg)

        hdr_validation_flags = self._build_hdr_validation_flags(events)
        headers_event.headers = self._process_received_headers(
            headers, hdr_validation_flags, header_encoding,
        )
        return [], events

    def receive_data(self, data: bytes, end_stream: bool, flow_control_len: int) -> tuple[list[Frame], list[Event]]:
        """
        Receive some data.
        """
        self.config.logger.debug(
            "Receive data on %r with end stream %s and flow control length "
            "set to %d", self, end_stream, flow_control_len,
        )
        events = self.state_machine.process_input(StreamInputs.RECV_DATA)
        data_event = cast("DataReceived", events[0])
        self._inbound_window_manager.window_consumed(flow_control_len)
        self._track_content_length(len(data), end_stream)

        if end_stream:
            es_events = self.state_machine.process_input(
                StreamInputs.RECV_END_STREAM,
            )
            data_event.stream_ended = cast("StreamEnded", es_events[0])
            events.extend(es_events)

        data_event.data = data
        data_event.flow_controlled_length = flow_control_len
        return [], events

    def receive_window_update(self, increment: int) -> tuple[list[Frame], list[Event]]:
        """
        Handle a WINDOW_UPDATE increment.
        """
        self.config.logger.debug(
            "Receive Window Update on %r for increment of %d",
            self, increment,
        )
        events = self.state_machine.process_input(
            StreamInputs.RECV_WINDOW_UPDATE,
        )
        frames = []

        # If we encounter a problem with incrementing the flow control window,
        # this should be treated as a *stream* error, not a *connection* error.
        # That means we need to catch the error and forcibly close the stream.
        if events:
            cast("WindowUpdated", events[0]).delta = increment
            try:
                self.outbound_flow_control_window = guard_increment_window(
                    self.outbound_flow_control_window,
                    increment,
                )
            except FlowControlError:
                # Ok, this is bad. We're going to need to perform a local
                # reset.
                events = [
                    StreamReset(
                        stream_id=self.stream_id,
                        error_code=ErrorCodes.FLOW_CONTROL_ERROR,
                        remote_reset=False,
                    ),
                ]
                frames = self.reset_stream(ErrorCodes.FLOW_CONTROL_ERROR)

        return frames, events

    def receive_continuation(self) -> None:
        """
        A naked CONTINUATION frame has been received. This is always an error,
        but the type of error it is depends on the state of the stream and must
        transition the state of the stream, so we need to handle it.
        """
        self.config.logger.debug("Receive Continuation frame on %r", self)
        self.state_machine.process_input(
            StreamInputs.RECV_CONTINUATION,
        )
        msg = "Should not be reachable"  # pragma: no cover
        raise AssertionError(msg)  # pragma: no cover

    def receive_alt_svc(self, frame: AltSvcFrame) -> tuple[list[Frame], list[Event]]:
        """
        An Alternative Service frame was received on the stream. This frame
        inherits the origin associated with this stream.
        """
        self.config.logger.debug(
            "Receive Alternative Service frame on stream %r", self,
        )

        # If the origin is present, RFC 7838 says we have to ignore it.
        if frame.origin:
            return [], []

        events = self.state_machine.process_input(
            StreamInputs.RECV_ALTERNATIVE_SERVICE,
        )

        # There are lots of situations where we want to ignore the ALTSVC
        # frame. If we need to pay attention, we'll have an event and should
        # fill it out.
        if events:
            assert isinstance(events[0], AlternativeServiceAvailable)
            events[0].origin = self._authority
            events[0].field_value = frame.field

        return [], events

    def reset_stream(self, error_code: ErrorCodes | int = 0) -> list[Frame]:
        """
        Close the stream locally. Reset the stream with an error code.
        """
        self.config.logger.debug(
            "Local reset %r with error code: %d", self, error_code,
        )
        self.state_machine.process_input(StreamInputs.SEND_RST_STREAM)

        rsf = RstStreamFrame(self.stream_id)
        rsf.error_code = error_code
        return [rsf]

    def stream_reset(self, frame: RstStreamFrame) -> tuple[list[Frame], list[Event]]:
        """
        Handle a stream being reset remotely.
        """
        self.config.logger.debug(
            "Remote reset %r with error code: %d", self, frame.error_code,
        )
        events = self.state_machine.process_input(StreamInputs.RECV_RST_STREAM)

        if events:
            # We don't fire an event if this stream is already closed.
            cast("StreamReset", events[0]).error_code = _error_code_from_int(frame.error_code)

        return [], events

    def acknowledge_received_data(self, acknowledged_size: int) -> list[Frame]:
        """
        The user has informed us that they've processed some amount of data
        that was received on this stream. Pass that to the window manager and
        potentially return some WindowUpdate frames.
        """
        self.config.logger.debug(
            "Acknowledge received data with size %d on %r",
            acknowledged_size, self,
        )
        increment = self._inbound_window_manager.process_bytes(
            acknowledged_size,
        )
        if increment:
            f = WindowUpdateFrame(self.stream_id)
            f.window_increment = increment
            return [f]

        return []

    def _build_hdr_validation_flags(self, events: Any) -> HeaderValidationFlags:
        """
        Constructs a set of header validation flags for use when normalizing
        and validating header blocks.
        """
        is_trailer = isinstance(
            events[0], (_TrailersSent, TrailersReceived),
        )
        is_response_header = isinstance(
            events[0],
            (
                _ResponseSent,
                ResponseReceived,
                InformationalResponseReceived,
            ),
        )
        is_push_promise = isinstance(
            events[0], (PushedStreamReceived, _PushedRequestSent),
        )

        return HeaderValidationFlags(
            is_client=self.state_machine.client or False,
            is_trailer=is_trailer,
            is_response_header=is_response_header,
            is_push_promise=is_push_promise,
        )

    def _build_headers_frames(self,
                              headers: Iterable[Header],
                              encoder: Encoder,
                              first_frame: HeadersFrame | PushPromiseFrame,
                              hdr_validation_flags: HeaderValidationFlags) \
            -> list[HeadersFrame | ContinuationFrame | PushPromiseFrame]:
        """
        Helper method to build headers or push promise frames.
        """
        # We need to lowercase the header names, and to ensure that secure
        # header fields are kept out of compression contexts.
        if self.config.normalize_outbound_headers:
            # also we may want to split outbound cookies to improve
            # headers compression
            should_split_outbound_cookies = self.config.split_outbound_cookies

            headers = normalize_outbound_headers(
                headers, hdr_validation_flags, should_split_outbound_cookies,
            )
        if self.config.validate_outbound_headers:
            headers = validate_outbound_headers(
                headers, hdr_validation_flags,
            )

        encoded_headers = encoder.encode(headers)

        # Slice into blocks of max_outbound_frame_size. Be careful with this:
        # it only works right because we never send padded frames or priority
        # information on the frames. Revisit this if we do.
        header_blocks = [
            encoded_headers[i:i+(self.max_outbound_frame_size or 0)]
            for i in range(
                0, len(encoded_headers), (self.max_outbound_frame_size or 0),
            )
        ]

        frames: list[HeadersFrame | ContinuationFrame | PushPromiseFrame] = []
        first_frame.data = header_blocks[0]
        frames.append(first_frame)

        for block in header_blocks[1:]:
            cf = ContinuationFrame(self.stream_id)
            cf.data = block
            frames.append(cf)

        frames[-1].flags.add("END_HEADERS")
        return frames

    def _process_received_headers(self,
                                  headers: Iterable[Header],
                                  header_validation_flags: HeaderValidationFlags,
                                  header_encoding: bool | str | None) -> list[Header]:
        """
        When headers have been received from the remote peer, run a processing
        pipeline on them to transform them into the appropriate form for
        attaching to an event.
        """
        if self.config.normalize_inbound_headers:
            headers = normalize_inbound_headers(
                headers, header_validation_flags,
            )

        if self.config.validate_inbound_headers:
            headers = validate_headers(headers, header_validation_flags)

        if isinstance(header_encoding, str):
            headers = _h2_stream_decode_headers(headers, header_encoding)

        # The above steps are all generators, so we need to concretize the
        # headers now.
        return list(headers)

    def _initialize_content_length(self, headers: Iterable[Header]) -> None:
        """
        Checks the headers for a content-length header and initializes the
        _expected_content_length field from it. It's not an error for no
        Content-Length header to be present.
        """
        if self.request_method == b"HEAD":
            self._expected_content_length = 0
            return

        content_length = None

        for n, v in headers:
            if n == b"content-length":
                if not v.isdigit():
                    # https://www.rfc-editor.org/rfc/rfc9110.html#name-content-length
                    # RFC grammar for content-length is 1*DIGIT, so any non-digit value is invalid.
                    msg = f"Invalid content-length header: {v!r}"
                    raise ProtocolError(msg)
                try:
                    parsed_content_length = int(v, 10)
                except ValueError as err:
                    msg = f"Invalid content-length header: {v!r}"
                    raise ProtocolError(msg) from err

                if content_length is None:
                    content_length = parsed_content_length
                elif parsed_content_length != content_length:
                    msg = f"Conflicting content-length headers: {content_length} and {parsed_content_length}"
                    raise ProtocolError(msg)

        self._expected_content_length = content_length

    def _track_content_length(self, length: int, end_stream: bool) -> None:
        """
        Update the expected content length in response to data being received.
        Validates that the appropriate amount of data is sent. Always updates
        the received data, but only validates the length against the
        content-length header if one was sent.

        :param length: The length of the body chunk received.
        :param end_stream: If this is the last body chunk received.
        """
        self._actual_content_length += length
        actual = self._actual_content_length
        expected = self._expected_content_length

        if expected is not None:
            if expected < actual:
                raise InvalidBodyLengthError(expected, actual)

            if end_stream and expected != actual:
                raise InvalidBodyLengthError(expected, actual)

    def _inbound_flow_control_change_from_settings(self, delta: int) -> None:
        """
        We changed SETTINGS_INITIAL_WINDOW_SIZE, which means we need to
        update the target window size for flow control. For our flow control
        strategy, this means we need to do two things: we need to adjust the
        current window size, but we also need to set the target maximum window
        size to the new value.
        """
        new_max_size = self._inbound_window_manager.max_window_size + delta
        self._inbound_window_manager.window_opened(delta)
        self._inbound_window_manager.max_window_size = new_max_size


def _h2_stream_decode_headers(headers: Iterable[HeaderWeaklyTyped], encoding: str) -> Generator[HeaderTuple, None, None]:
    """
    Given an iterable of header two-tuples and an encoding, decodes those
    headers using that encoding while preserving the type of the header tuple.
    This ensures that the use of ``HeaderTuple`` is preserved.
    """
    for header in headers:
        # This function expects to work on decoded headers, which are always
        # HeaderTuple objects.
        assert isinstance(header, HeaderTuple)

        name, value = header
        assert isinstance(name, bytes)
        assert isinstance(value, bytes)

        n = name.decode(encoding)
        v = value.decode(encoding)
        yield header.__class__(n, v)


# ---------------------------------------------------------------------------
# h2/connection.py  (h2 4.4.1)
# ---------------------------------------------------------------------------

"""
h2/connection
~~~~~~~~~~~~~

An implementation of a HTTP/2 connection.
"""

import base64
from enum import Enum, IntEnum
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Callable, Iterable


class ConnectionState(Enum):
    IDLE = 0
    CLIENT_OPEN = 1
    SERVER_OPEN = 2
    CLOSED = 3


class ConnectionInputs(Enum):
    SEND_HEADERS = 0
    SEND_PUSH_PROMISE = 1
    SEND_DATA = 2
    SEND_GOAWAY = 3
    SEND_WINDOW_UPDATE = 4
    SEND_PING = 5
    SEND_SETTINGS = 6
    SEND_RST_STREAM = 7
    SEND_PRIORITY = 8
    RECV_HEADERS = 9
    RECV_PUSH_PROMISE = 10
    RECV_DATA = 11
    RECV_GOAWAY = 12
    RECV_WINDOW_UPDATE = 13
    RECV_PING = 14
    RECV_SETTINGS = 15
    RECV_RST_STREAM = 16
    RECV_PRIORITY = 17
    SEND_ALTERNATIVE_SERVICE = 18  # Added in 2.3.0
    RECV_ALTERNATIVE_SERVICE = 19  # Added in 2.3.0


class AllowedStreamIDs(IntEnum):
    EVEN = 0
    ODD = 1


class H2ConnectionStateMachine:
    """
    A single HTTP/2 connection state machine.

    This state machine, while defined in its own class, is logically part of
    the H2Connection class also defined in this file. The state machine itself
    maintains very little state directly, instead focusing entirely on managing
    state transitions.
    """

    # For the purposes of this state machine we treat HEADERS and their
    # associated CONTINUATION frames as a single jumbo frame. The protocol
    # allows/requires this by preventing other frames from being interleved in
    # between HEADERS/CONTINUATION frames.
    #
    # The _transitions dictionary contains a mapping of tuples of
    # (state, input) to tuples of (side_effect_function, end_state). This map
    # contains all allowed transitions: anything not in this map is invalid
    # and immediately causes a transition to ``closed``.

    _transitions = {
        # State: idle
        (ConnectionState.IDLE, ConnectionInputs.SEND_HEADERS):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.IDLE, ConnectionInputs.RECV_HEADERS):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.IDLE, ConnectionInputs.SEND_SETTINGS):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.RECV_SETTINGS):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.SEND_WINDOW_UPDATE):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.RECV_WINDOW_UPDATE):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.SEND_PING):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.RECV_PING):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.SEND_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.IDLE, ConnectionInputs.RECV_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.IDLE, ConnectionInputs.SEND_PRIORITY):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.RECV_PRIORITY):
            (None, ConnectionState.IDLE),
        (ConnectionState.IDLE, ConnectionInputs.SEND_ALTERNATIVE_SERVICE):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.IDLE, ConnectionInputs.RECV_ALTERNATIVE_SERVICE):
            (None, ConnectionState.CLIENT_OPEN),

        # State: open, client side.
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_HEADERS):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_DATA):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_WINDOW_UPDATE):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_PING):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_SETTINGS):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_PRIORITY):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_HEADERS):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_PUSH_PROMISE):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_DATA):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_WINDOW_UPDATE):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_PING):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_SETTINGS):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.SEND_RST_STREAM):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_RST_STREAM):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN, ConnectionInputs.RECV_PRIORITY):
            (None, ConnectionState.CLIENT_OPEN),
        (ConnectionState.CLIENT_OPEN,
            ConnectionInputs.RECV_ALTERNATIVE_SERVICE):
                (None, ConnectionState.CLIENT_OPEN),

        # State: open, server side.
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_HEADERS):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_PUSH_PROMISE):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_DATA):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_WINDOW_UPDATE):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_PING):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_SETTINGS):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_PRIORITY):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_HEADERS):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_DATA):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_WINDOW_UPDATE):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_PING):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_SETTINGS):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_PRIORITY):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.SEND_RST_STREAM):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN, ConnectionInputs.RECV_RST_STREAM):
            (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN,
            ConnectionInputs.SEND_ALTERNATIVE_SERVICE):
                (None, ConnectionState.SERVER_OPEN),
        (ConnectionState.SERVER_OPEN,
            ConnectionInputs.RECV_ALTERNATIVE_SERVICE):
                (None, ConnectionState.SERVER_OPEN),

        # State: closed
        (ConnectionState.CLOSED, ConnectionInputs.SEND_GOAWAY):
            (None, ConnectionState.CLOSED),
        (ConnectionState.CLOSED, ConnectionInputs.RECV_GOAWAY):
            (None, ConnectionState.CLOSED),
    }

    def __init__(self) -> None:
        self.state = ConnectionState.IDLE

    def process_input(self, input_: ConnectionInputs) -> list[Event]:
        """
        Process a specific input in the state machine.
        """
        if not isinstance(input_, ConnectionInputs):
            msg = "Input must be an instance of ConnectionInputs"
            raise ValueError(msg)  # noqa: TRY004

        try:
            func, target_state = self._transitions[(self.state, input_)]
        except KeyError as e:
            old_state = self.state
            self.state = ConnectionState.CLOSED
            msg = f"Invalid input {input_} in state {old_state}"
            raise ProtocolError(msg) from e
        else:
            self.state = target_state
            if func is not None:  # pragma: no cover
                return func()

            return []


class H2Connection:
    """
    A low-level HTTP/2 connection object. This handles building and receiving
    frames and maintains both connection and per-stream state for all streams
    on this connection.

    This wraps a HTTP/2 Connection state machine implementation, ensuring that
    frames can only be sent/received when the connection is in a valid state.
    It also builds stream state machines on demand to ensure that the
    constraints of those state machines are met as well. Attempts to create
    frames that cannot be sent will raise a ``ProtocolError``.

    .. versionchanged:: 2.3.0
       Added the ``header_encoding`` keyword argument.

    .. versionchanged:: 2.5.0
       Added the ``config`` keyword argument. Deprecated the ``client_side``
       and ``header_encoding`` parameters.

    .. versionchanged:: 3.0.0
       Removed deprecated parameters and properties.

    :param config: The configuration for the HTTP/2 connection.

        .. versionadded:: 2.5.0

    :type config: :class:`H2Configuration <h2.config.H2Configuration>`
    """

    # The initial maximum outbound frame size. This can be changed by receiving
    # a settings frame.
    DEFAULT_MAX_OUTBOUND_FRAME_SIZE = 65535

    # The initial maximum inbound frame size. This is somewhat arbitrarily
    # chosen.
    DEFAULT_MAX_INBOUND_FRAME_SIZE = 2**24

    # The highest acceptable stream ID.
    HIGHEST_ALLOWED_STREAM_ID = 2**31 - 1

    # The largest acceptable window increment.
    MAX_WINDOW_INCREMENT = 2**31 - 1

    # The initial default value of SETTINGS_MAX_HEADER_LIST_SIZE.
    DEFAULT_MAX_HEADER_LIST_SIZE = 2**16

    # Keep in memory limited amount of results for streams closes
    MAX_CLOSED_STREAMS = 2**16

    def __init__(self, config: H2Configuration | None = None) -> None:
        self.state_machine = H2ConnectionStateMachine()
        self.streams: dict[int, H2Stream] = {}
        self.highest_inbound_stream_id = 0
        self.highest_outbound_stream_id = 0
        self.encoder = Encoder()
        self.decoder = Decoder()

        # This won't always actually do anything: for versions of HPACK older
        # than 2.3.0 it does nothing. However, we have to try!
        self.decoder.max_header_list_size = self.DEFAULT_MAX_HEADER_LIST_SIZE

        #: The configuration for this HTTP/2 connection object.
        #:
        #: .. versionadded:: 2.5.0
        self.config = config or H2Configuration(client_side=True)

        # Objects that store settings, including defaults.
        #
        # We set the MAX_CONCURRENT_STREAMS value to 100 because its default is
        # unbounded, and that's a dangerous default because it allows
        # essentially unbounded resources to be allocated regardless of how
        # they will be used. 100 should be suitable for the average
        # application. This default obviously does not apply to the remote
        # peer's settings: the remote peer controls them!
        #
        # We also set MAX_HEADER_LIST_SIZE to a reasonable value. This is to
        # advertise our defence against CVE-2016-6581. However, not all
        # versions of HPACK will let us do it. That's ok: we should at least
        # suggest that we're not vulnerable.
        self.local_settings = Settings(
            client=self.config.client_side,
            initial_values={
                SettingCodes.MAX_CONCURRENT_STREAMS: 100,
                SettingCodes.MAX_HEADER_LIST_SIZE:
                    self.DEFAULT_MAX_HEADER_LIST_SIZE,
            },
        )
        self.remote_settings = Settings(client=not self.config.client_side)

        # The current value of the connection flow control windows on the
        # connection.
        self.outbound_flow_control_window = (
            self.remote_settings.initial_window_size
        )

        #: The maximum size of a frame that can be emitted by this peer, in
        #: bytes.
        self.max_outbound_frame_size = self.remote_settings.max_frame_size

        #: The maximum size of a frame that can be received by this peer, in
        #: bytes.
        self.max_inbound_frame_size = self.local_settings.max_frame_size

        # Buffer for incoming data.
        self.incoming_buffer = FrameBuffer(server=not self.config.client_side)

        # A private variable to store a sequence of received header frames
        # until completion.
        self._header_frames: list[Frame] = []

        # Data that needs to be sent.
        self._data_to_send = bytearray()

        # Keeps track of how streams are closed.
        # Used to ensure that we don't blow up in the face of frames that were
        # in flight when a RST_STREAM was sent.
        # Also used to determine whether we should consider a frame received
        # while a stream is closed as either a stream error or a connection
        # error.
        self._closed_streams: dict[int, StreamClosedBy | None] = SizeLimitDict(
            size_limit=self.MAX_CLOSED_STREAMS,
        )

        # The flow control window manager for the connection.
        self._inbound_flow_control_window_manager = WindowManager(
            max_window_size=self.local_settings.initial_window_size,
        )

        # When in doubt use dict-dispatch.
        self._frame_dispatch_table: dict[type[Frame], Callable] = {  # type: ignore
            HeadersFrame: self._receive_headers_frame,
            PushPromiseFrame: self._receive_push_promise_frame,
            SettingsFrame: self._receive_settings_frame,
            DataFrame: self._receive_data_frame,
            WindowUpdateFrame: self._receive_window_update_frame,
            PingFrame: self._receive_ping_frame,
            RstStreamFrame: self._receive_rst_stream_frame,
            PriorityFrame: self._receive_priority_frame,
            GoAwayFrame: self._receive_goaway_frame,
            ContinuationFrame: self._receive_naked_continuation,
            AltSvcFrame: self._receive_alt_svc_frame,
            ExtensionFrame: self._receive_unknown_frame,
        }

    def _prepare_for_sending(self, frames: list[Frame]) -> None:
        if not frames:
            return
        self._data_to_send += b"".join(f.serialize() for f in frames)
        assert all(f.body_len <= self.max_outbound_frame_size for f in frames)

    def _open_streams(self, remainder: int) -> int:
        """
        A common method of counting number of open streams. Returns the number
        of streams that are open *and* that have (stream ID % 2) == remainder.
        While it iterates, also deletes any closed streams.
        """
        count = 0
        to_delete = []

        for stream_id, stream in self.streams.items():
            if stream.open and (stream_id % 2 == remainder):
                count += 1
            elif stream.closed:
                to_delete.append(stream_id)

        for stream_id in to_delete:
            stream = self.streams.pop(stream_id)
            self._closed_streams[stream_id] = stream.closed_by

        return count

    @property
    def open_outbound_streams(self) -> int:
        """
        The current number of open outbound streams.
        """
        outbound_numbers = int(self.config.client_side)
        return self._open_streams(outbound_numbers)

    @property
    def open_inbound_streams(self) -> int:
        """
        The current number of open inbound streams.
        """
        inbound_numbers = int(not self.config.client_side)
        return self._open_streams(inbound_numbers)

    @property
    def inbound_flow_control_window(self) -> int:
        """
        The size of the inbound flow control window for the connection. This is
        rarely publicly useful: instead, use :meth:`remote_flow_control_window
        <h2.connection.H2Connection.remote_flow_control_window>`. This
        shortcut is largely present to provide a shortcut to this data.
        """
        return self._inbound_flow_control_window_manager.current_window_size

    def _begin_new_stream(self, stream_id: int, allowed_ids: AllowedStreamIDs) -> H2Stream:
        """
        Initiate a new stream.

        .. versionchanged:: 2.0.0
           Removed this function from the public API.

        :param stream_id: The ID of the stream to open.
        :param allowed_ids: What kind of stream ID is allowed.
        """
        self.config.logger.debug(
            "Attempting to initiate stream ID %d", stream_id,
        )
        outbound = self._stream_id_is_outbound(stream_id)
        highest_stream_id = (
            self.highest_outbound_stream_id if outbound else
            self.highest_inbound_stream_id
        )

        if stream_id <= highest_stream_id:
            raise StreamIDTooLowError(stream_id, highest_stream_id)

        if (stream_id % 2) != int(allowed_ids):
            msg = "Invalid stream ID for peer."
            raise ProtocolError(msg)

        s = H2Stream(
            stream_id,
            config=self.config,
            inbound_window_size=self.local_settings.initial_window_size,
            outbound_window_size=self.remote_settings.initial_window_size,
        )
        self.config.logger.debug("Stream ID %d created", stream_id)
        s.max_outbound_frame_size = self.max_outbound_frame_size

        self.streams[stream_id] = s
        self.config.logger.debug("Current streams: %s", self.streams.keys())

        if outbound:
            self.highest_outbound_stream_id = stream_id
        else:
            self.highest_inbound_stream_id = stream_id

        return s

    def initiate_connection(self) -> None:
        """
        Provides any data that needs to be sent at the start of the connection.
        Must be called for both clients and servers.
        """
        self.config.logger.debug("Initializing connection")
        self.state_machine.process_input(ConnectionInputs.SEND_SETTINGS)
        if self.config.client_side:
            preamble = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        else:
            preamble = b""

        f = SettingsFrame(0)
        for setting, value in self.local_settings.items():
            f.settings[setting] = value
        self.config.logger.debug(
            "Send Settings frame: %s", self.local_settings,
        )

        self._data_to_send += preamble + f.serialize()

    def initiate_upgrade_connection(self, settings_header: bytes | None = None) -> bytes | None:
        """
        Call to initialise the connection object for use with an upgraded
        HTTP/2 connection (i.e. a connection negotiated using the
        ``Upgrade: h2c`` HTTP header).

        This method differs from :meth:`initiate_connection
        <h2.connection.H2Connection.initiate_connection>` in several ways.
        Firstly, it handles the additional SETTINGS frame that is sent in the
        ``HTTP2-Settings`` header field. When called on a client connection,
        this method will return a bytestring that the caller can put in the
        ``HTTP2-Settings`` field they send on their initial request. When
        called on a server connection, the user **must** provide the value they
        received from the client in the ``HTTP2-Settings`` header field to the
        ``settings_header`` argument, which will be used appropriately.

        Additionally, this method sets up stream 1 in a half-closed state
        appropriate for this side of the connection, to reflect the fact that
        the request is already complete.

        Finally, this method also prepares the appropriate preamble to be sent
        after the upgrade.

        .. versionadded:: 2.3.0

        :param settings_header: (optional, server-only): The value of the
             ``HTTP2-Settings`` header field received from the client.
        :type settings_header: ``bytes``

        :returns: For clients, a bytestring to put in the ``HTTP2-Settings``.
            For servers, returns nothing.
        :rtype: ``bytes`` or ``None``
        """
        self.config.logger.debug(
            "Upgrade connection. Current settings: %s", self.local_settings,
        )

        frame_data = None
        # Begin by getting the preamble in place.
        self.initiate_connection()

        if self.config.client_side:
            f = SettingsFrame(0)
            for setting, value in self.local_settings.items():
                f.settings[setting] = value

            frame_data = f.serialize_body()
            frame_data = base64.urlsafe_b64encode(frame_data)
        elif settings_header:
            # We have a settings header from the client. This needs to be
            # applied, but we want to throw away the ACK. We do this by
            # inserting the data into a Settings frame and then passing it to
            # the state machine, but ignoring the return value.
            settings_header = base64.urlsafe_b64decode(settings_header)
            f = SettingsFrame(0)
            f.parse_body(memoryview(settings_header))
            self._receive_settings_frame(f)

        # Set up appropriate state. Stream 1 in a half-closed state:
        # half-closed(local) for clients, half-closed(remote) for servers.
        # Additionally, we need to set up the Connection state machine.
        connection_input = (
            ConnectionInputs.SEND_HEADERS if self.config.client_side
            else ConnectionInputs.RECV_HEADERS
        )
        self.config.logger.debug("Process input %s", connection_input)
        self.state_machine.process_input(connection_input)

        # Set up stream 1.
        self._begin_new_stream(stream_id=1, allowed_ids=AllowedStreamIDs.ODD)
        self.streams[1].upgrade(self.config.client_side)
        return frame_data

    def _get_or_create_stream(self, stream_id: int, allowed_ids: AllowedStreamIDs) -> H2Stream:
        """
        Gets a stream by its stream ID. Will create one if one does not already
        exist. Use allowed_ids to circumvent the usual stream ID rules for
        clients and servers.

        .. versionchanged:: 2.0.0
           Removed this function from the public API.
        """
        try:
            return self.streams[stream_id]
        except KeyError:
            return self._begin_new_stream(stream_id, allowed_ids)

    def _get_stream_by_id(self, stream_id: int | None) -> H2Stream:
        """
        Gets a stream by its stream ID. Raises NoSuchStreamError if the stream
        ID does not correspond to a known stream and is higher than the current
        maximum: raises if it is lower than the current maximum.

        .. versionchanged:: 2.0.0
           Removed this function from the public API.
        """
        if not stream_id:
            raise NoSuchStreamError(-1)  # pragma: no cover
        try:
            return self.streams[stream_id]
        except KeyError as e:
            outbound = self._stream_id_is_outbound(stream_id)
            highest_stream_id = (
                self.highest_outbound_stream_id if outbound else
                self.highest_inbound_stream_id
            )

            if stream_id > highest_stream_id:
                raise NoSuchStreamError(stream_id) from e
            raise StreamClosedError(stream_id) from e

    def get_next_available_stream_id(self) -> int:
        """
        Returns an integer suitable for use as the stream ID for the next
        stream created by this endpoint. For server endpoints, this stream ID
        will be even. For client endpoints, this stream ID will be odd. If no
        stream IDs are available, raises :class:`NoAvailableStreamIDError
        <h2.exceptions.NoAvailableStreamIDError>`.

        .. warning:: The return value from this function does not change until
                     the stream ID has actually been used by sending or pushing
                     headers on that stream. For that reason, it should be
                     called as close as possible to the actual use of the
                     stream ID.

        .. versionadded:: 2.0.0

        :raises: :class:`NoAvailableStreamIDError
            <h2.exceptions.NoAvailableStreamIDError>`
        :returns: The next free stream ID this peer can use to initiate a
            stream.
        :rtype: ``int``
        """
        # No streams have been opened yet, so return the lowest allowed stream
        # ID.
        if not self.highest_outbound_stream_id:
            next_stream_id = 1 if self.config.client_side else 2
        else:
            next_stream_id = self.highest_outbound_stream_id + 2
        self.config.logger.debug(
            "Next available stream ID %d", next_stream_id,
        )
        if next_stream_id > self.HIGHEST_ALLOWED_STREAM_ID:
            msg = "Exhausted allowed stream IDs"
            raise NoAvailableStreamIDError(msg)

        return next_stream_id

    def send_headers(self,
                     stream_id: int,
                     headers: Iterable[HeaderWeaklyTyped],
                     end_stream: bool = False,
                     priority_weight: int | None = None,
                     priority_depends_on: int | None = None,
                     priority_exclusive: bool | None = None) -> None:
        """
        Send headers on a given stream.

        This function can be used to send request or response headers: the kind
        that are sent depends on whether this connection has been opened as a
        client or server connection, and whether the stream was opened by the
        remote peer or not.

        If this is a client connection, calling ``send_headers`` will send the
        headers as a request. It will also implicitly open the stream being
        used. If this is a client connection and ``send_headers`` has *already*
        been called, this will send trailers instead.

        If this is a server connection, calling ``send_headers`` will send the
        headers as a response. It is a protocol error for a server to open a
        stream by sending headers. If this is a server connection and
        ``send_headers`` has *already* been called, this will send trailers
        instead.

        When acting as a server, you may call ``send_headers`` any number of
        times allowed by the following rules, in this order:

        - zero or more times with ``(':status', '1XX')`` (where ``1XX`` is a
          placeholder for any 100-level status code).
        - once with any other status header.
        - zero or one time for trailers.

        That is, you are allowed to send as many informational responses as you
        like, followed by one complete response and zero or one HTTP trailer
        blocks.

        Clients may send one or two header blocks: one request block, and
        optionally one trailer block.

        If it is important to send HPACK "never indexed" header fields (as
        defined in `RFC 7451 Section 7.1.3
        <https://tools.ietf.org/html/rfc7541#section-7.1.3>`_), the user may
        instead provide headers using the HPACK library's :class:`HeaderTuple
        <hpack:hpack.HeaderTuple>` and :class:`NeverIndexedHeaderTuple
        <hpack:hpack.NeverIndexedHeaderTuple>` objects.

        This method also allows users to prioritize the stream immediately,
        by sending priority information on the HEADERS frame directly. To do
        this, any one of ``priority_weight``, ``priority_depends_on``, or
        ``priority_exclusive`` must be set to a value that is not ``None``. For
        more information on the priority fields, see :meth:`prioritize
        <h2.connection.H2Connection.prioritize>`.

        .. warning:: In HTTP/2, it is mandatory that all the HTTP/2 special
            headers (that is, ones whose header keys begin with ``:``) appear
            at the start of the header block, before any normal headers.

        .. versionchanged:: 2.3.0
           Added support for using :class:`HeaderTuple
           <hpack:hpack.HeaderTuple>` objects to store headers.

        .. versionchanged:: 2.4.0
           Added the ability to provide priority keyword arguments:
           ``priority_weight``, ``priority_depends_on``, and
           ``priority_exclusive``.

        :param stream_id: The stream ID to send the headers on. If this stream
            does not currently exist, it will be created.
        :type stream_id: ``int``

        :param headers: The request/response headers to send.
        :type headers: An iterable of two tuples of bytestrings or
            :class:`HeaderTuple <hpack:hpack.HeaderTuple>` objects.

        :param end_stream: Whether this headers frame should end the stream
            immediately (that is, whether no more data will be sent after this
            frame). Defaults to ``False``.
        :type end_stream: ``bool``

        :param priority_weight: Sets the priority weight of the stream. See
            :meth:`prioritize <h2.connection.H2Connection.prioritize>` for more
            about how this field works. Defaults to ``None``, which means that
            no priority information will be sent.
        :type priority_weight: ``int`` or ``None``

        :param priority_depends_on: Sets which stream this one depends on for
            priority purposes. See :meth:`prioritize
            <h2.connection.H2Connection.prioritize>` for more about how this
            field works. Defaults to ``None``, which means that no priority
            information will be sent.
        :type priority_depends_on: ``int`` or ``None``

        :param priority_exclusive: Sets whether this stream exclusively depends
            on the stream given in ``priority_depends_on`` for priority
            purposes. See :meth:`prioritize
            <h2.connection.H2Connection.prioritize>` for more about how this
            field works. Defaults to ``None``, which means that no priority
            information will be sent.
        :type priority_depends_on: ``bool`` or ``None``

        :returns: Nothing
        """
        self.config.logger.debug(
            "Send headers on stream ID %d", stream_id,
        )

        # Check we can open the stream.
        if stream_id not in self.streams:
            max_open_streams = self.remote_settings.max_concurrent_streams
            value = self.open_outbound_streams # take a copy due to the property accessor having side affects
            if (value + 1) > max_open_streams:
                msg = f"Max outbound streams is {max_open_streams}, {value} open"
                raise TooManyStreamsError(msg)

        self.state_machine.process_input(ConnectionInputs.SEND_HEADERS)
        stream = self._get_or_create_stream(
            stream_id, AllowedStreamIDs(self.config.client_side),
        )

        frames: list[Frame] = []
        frames.extend(stream.send_headers(
            headers, self.encoder, end_stream,
        ))

        # We may need to send priority information.
        priority_present = (
            (priority_weight is not None) or
            (priority_depends_on is not None) or
            (priority_exclusive is not None)
        )

        if priority_present:
            if not self.config.client_side:
                msg = "Servers SHOULD NOT prioritize streams."
                raise RFC1122Error(msg)

            headers_frame = frames[0]
            assert isinstance(headers_frame, HeadersFrame)

            headers_frame.flags.add("PRIORITY")
            frames[0] = _add_frame_priority(
                headers_frame,
                priority_weight,
                priority_depends_on,
                priority_exclusive,
            )

        self._prepare_for_sending(frames)

    def send_data(self,
                  stream_id: int,
                  data: bytes | memoryview,
                  end_stream: bool = False,
                  pad_length: Any = None) -> None:
        """
        Send data on a given stream.

        This method does no breaking up of data: if the data is larger than the
        value returned by :meth:`local_flow_control_window
        <h2.connection.H2Connection.local_flow_control_window>` for this stream
        then a :class:`FlowControlError <h2.exceptions.FlowControlError>` will
        be raised. If the data is larger than :data:`max_outbound_frame_size
        <h2.connection.H2Connection.max_outbound_frame_size>` then a
        :class:`FrameTooLargeError <h2.exceptions.FrameTooLargeError>` will be
        raised.

        h2 does this to avoid buffering the data internally. If the user
        has more data to send than h2 will allow, consider breaking it up
        and buffering it externally.

        :param stream_id: The ID of the stream on which to send the data.
        :type stream_id: ``int``
        :param data: The data to send on the stream.
        :type data: ``bytes``
        :param end_stream: (optional) Whether this is the last data to be sent
            on the stream. Defaults to ``False``.
        :type end_stream: ``bool``
        :param pad_length: (optional) Length of the padding to apply to the
            data frame. Defaults to ``None`` for no use of padding. Note that
            a value of ``0`` results in padding of length ``0``
            (with the "padding" flag set on the frame).

            .. versionadded:: 2.6.0

        :type pad_length: ``int``
        :returns: Nothing
        """
        self.config.logger.debug(
            "Send data on stream ID %d with len %d", stream_id, len(data),
        )
        frame_size = len(data)
        if pad_length is not None:
            if not isinstance(pad_length, int):
                msg = "pad_length must be an int"
                raise TypeError(msg)
            if pad_length < 0 or pad_length > 255:
                msg = "pad_length must be within range: [0, 255]"
                raise ValueError(msg)
            # Account for padding bytes plus the 1-byte padding length field.
            frame_size += pad_length + 1
        self.config.logger.debug(
            "Frame size on stream ID %d is %d", stream_id, frame_size,
        )

        if frame_size > 0 and frame_size > self.local_flow_control_window(stream_id):
            msg = f"Cannot send {frame_size} bytes, flow control window is {self.local_flow_control_window(stream_id)}"
            raise FlowControlError(msg)
        if frame_size > self.max_outbound_frame_size:
            msg = f"Cannot send frame size {frame_size}, max frame size is {self.max_outbound_frame_size}"
            raise FrameTooLargeError(msg)

        self.state_machine.process_input(ConnectionInputs.SEND_DATA)
        frames = self.streams[stream_id].send_data(
            data, end_stream, pad_length=pad_length,
        )

        self._prepare_for_sending(frames)

        self.outbound_flow_control_window -= frame_size
        self.config.logger.debug(
            "Outbound flow control window size is %d",
            self.outbound_flow_control_window,
        )
        assert self.outbound_flow_control_window >= 0 or frame_size == 0

    def end_stream(self, stream_id: int) -> None:
        """
        Cleanly end a given stream.

        This method ends a stream by sending an empty DATA frame on that stream
        with the ``END_STREAM`` flag set.

        :param stream_id: The ID of the stream to end.
        :type stream_id: ``int``
        :returns: Nothing
        :raises NoSuchStreamError: If the stream ID does not correspond to a
            known stream and is higher than the current maximum stream ID.
        :raises StreamClosedError: If the stream ID corresponds to a stream
            that has been closed.
        """
        self.config.logger.debug("End stream ID %d", stream_id)
        self.state_machine.process_input(ConnectionInputs.SEND_DATA)
        frames = self._get_stream_by_id(stream_id).end_stream()
        self._prepare_for_sending(frames)

    def increment_flow_control_window(self, increment: int, stream_id: int | None = None) -> None:
        """
        Increment a flow control window, optionally for a single stream. Allows
        the remote peer to send more data.

        .. versionchanged:: 2.0.0
           Rejects attempts to increment the flow control window by out of
           range values with a ``ValueError``.

        :param increment: The amount to increment the flow control window by.
        :type increment: ``int``
        :param stream_id: (optional) The ID of the stream that should have its
            flow control window opened. If not present or ``None``, the
            connection flow control window will be opened instead.
        :type stream_id: ``int`` or ``None``
        :returns: Nothing
        :raises: ``ValueError``
        """
        if not (1 <= increment <= self.MAX_WINDOW_INCREMENT):
            msg = f"Flow control increment must be between 1 and {self.MAX_WINDOW_INCREMENT}"
            raise ValueError(msg)

        self.state_machine.process_input(ConnectionInputs.SEND_WINDOW_UPDATE)

        if stream_id is not None:
            stream = self.streams[stream_id]
            frames = stream.increase_flow_control_window(
                increment,
            )

            self.config.logger.debug(
                "Increase stream ID %d flow control window by %d",
                stream_id, increment,
            )
        else:
            self._inbound_flow_control_window_manager.window_opened(increment)
            f = WindowUpdateFrame(0)
            f.window_increment = increment
            frames = [f]

            self.config.logger.debug(
                "Increase connection flow control window by %d", increment,
            )

        self._prepare_for_sending(frames)

    def push_stream(self,
                    stream_id: int,
                    promised_stream_id: int,
                    request_headers: Iterable[HeaderWeaklyTyped]) -> None:
        """
        Push a response to the client by sending a PUSH_PROMISE frame.

        If it is important to send HPACK "never indexed" header fields (as
        defined in `RFC 7451 Section 7.1.3
        <https://tools.ietf.org/html/rfc7541#section-7.1.3>`_), the user may
        instead provide headers using the HPACK library's :class:`HeaderTuple
        <hpack:hpack.HeaderTuple>` and :class:`NeverIndexedHeaderTuple
        <hpack:hpack.NeverIndexedHeaderTuple>` objects.

        :param stream_id: The ID of the stream that this push is a response to.
        :type stream_id: ``int``
        :param promised_stream_id: The ID of the stream that the pushed
            response will be sent on.
        :type promised_stream_id: ``int``
        :param request_headers: The headers of the request that the pushed
            response will be responding to.
        :type request_headers: An iterable of two tuples of bytestrings or
            :class:`HeaderTuple <hpack:hpack.HeaderTuple>` objects.
        :returns: Nothing
        """
        self.config.logger.debug(
            "Send Push Promise frame on stream ID %d", stream_id,
        )

        if not self.remote_settings.enable_push:
            msg = "Remote peer has disabled stream push"
            raise ProtocolError(msg)

        self.state_machine.process_input(ConnectionInputs.SEND_PUSH_PROMISE)
        stream = self._get_stream_by_id(stream_id)

        # We need to prevent users pushing streams in response to streams that
        # they themselves have already pushed: see #163 and RFC 7540 § 6.6. The
        # easiest way to do that is to assert that the stream_id is not even:
        # this shortcut works because only servers can push and the state
        # machine will enforce this.
        if (stream_id % 2) == 0:
            msg = "Cannot recursively push streams."
            raise ProtocolError(msg)

        new_stream = self._begin_new_stream(
            promised_stream_id, AllowedStreamIDs.EVEN,
        )
        self.streams[promised_stream_id] = new_stream

        frames = stream.push_stream_in_band(
            promised_stream_id, request_headers, self.encoder,
        )
        new_frames = new_stream.locally_pushed()
        self._prepare_for_sending(frames + new_frames)

    def ping(self, opaque_data: bytes | str) -> None:
        """
        Send a PING frame.

        :param opaque_data: A bytestring of length 8 that will be sent in the
                            PING frame.
        :returns: Nothing
        """
        self.config.logger.debug("Send Ping frame")

        if not isinstance(opaque_data, bytes) or len(opaque_data) != 8:
            msg = f"Invalid value for ping data: {opaque_data!r}"
            raise ValueError(msg)

        self.state_machine.process_input(ConnectionInputs.SEND_PING)
        f = PingFrame(0)
        f.opaque_data = opaque_data
        self._prepare_for_sending([f])

    def reset_stream(self, stream_id: int, error_code: ErrorCodes | int = 0) -> None:
        """
        Reset a stream.

        This method forcibly closes a stream by sending a RST_STREAM frame for
        a given stream. This is not a graceful closure. To gracefully end a
        stream, try the :meth:`end_stream
        <h2.connection.H2Connection.end_stream>` method.

        :param stream_id: The ID of the stream to reset.
        :type stream_id: ``int``
        :param error_code: (optional) The error code to use to reset the
            stream. Defaults to :data:`ErrorCodes.NO_ERROR
            <h2.errors.ErrorCodes.NO_ERROR>`.
        :type error_code: ``int``
        :returns: Nothing
        """
        self.config.logger.debug("Reset stream ID %d", stream_id)
        self.state_machine.process_input(ConnectionInputs.SEND_RST_STREAM)
        stream = self._get_stream_by_id(stream_id)
        frames = stream.reset_stream(error_code)
        self._prepare_for_sending(frames)

    def close_connection(self,
                         error_code: ErrorCodes | int = 0,
                         additional_data: bytes | None = None,
                         last_stream_id: int | None = None) -> None:
        """
        Close a connection, emitting a GOAWAY frame.

        .. versionchanged:: 2.4.0
           Added ``additional_data`` and ``last_stream_id`` arguments.

        :param error_code: (optional) The error code to send in the GOAWAY
            frame.
        :param additional_data: (optional) Additional debug data indicating
            a reason for closing the connection. Must be a bytestring.
        :param last_stream_id: (optional) The last stream which was processed
            by the sender. Defaults to ``highest_inbound_stream_id``.
        :returns: Nothing
        """
        self.config.logger.debug("Close connection")
        self.state_machine.process_input(ConnectionInputs.SEND_GOAWAY)

        # Additional_data must be bytes
        if additional_data is not None:
            assert isinstance(additional_data, bytes)

        if last_stream_id is None:
            last_stream_id = self.highest_inbound_stream_id

        f = GoAwayFrame(
            stream_id=0,
            last_stream_id=last_stream_id,
            error_code=error_code,
            additional_data=(additional_data or b""),
        )
        self._prepare_for_sending([f])

    def update_settings(self, new_settings: dict[SettingCodes | int, int]) -> None:
        """
        Update the local settings. This will prepare and emit the appropriate
        SETTINGS frame.

        :param new_settings: A dictionary of {setting: new value}
        """
        self.config.logger.debug(
            "Update connection settings to %s", new_settings,
        )
        self.state_machine.process_input(ConnectionInputs.SEND_SETTINGS)
        self.local_settings.update(new_settings)
        s = SettingsFrame(0)
        s.settings = new_settings
        self._prepare_for_sending([s])

    def advertise_alternative_service(self,
                                      field_value: bytes | str,
                                      origin: bytes | None = None,
                                      stream_id: int | None = None) -> None:
        """
        Notify a client about an available Alternative Service.

        An Alternative Service is defined in `RFC 7838
        <https://tools.ietf.org/html/rfc7838>`_. An Alternative Service
        notification informs a client that a given origin is also available
        elsewhere.

        Alternative Services can be advertised in two ways. Firstly, they can
        be advertised explicitly: that is, a server can say "origin X is also
        available at Y". To advertise like this, set the ``origin`` argument
        and not the ``stream_id`` argument. Alternatively, they can be
        advertised implicitly: that is, a server can say "the origin you're
        contacting on stream X is also available at Y". To advertise like this,
        set the ``stream_id`` argument and not the ``origin`` argument.

        The explicit method of advertising can be done as long as the
        connection is active. The implicit method can only be done after the
        client has sent the request headers and before the server has sent the
        response headers: outside of those points, h2 will forbid sending
        the Alternative Service advertisement by raising a ProtocolError.

        The ``field_value`` parameter is specified in RFC 7838. h2 does
        not validate or introspect this argument: the user is required to
        ensure that it's well-formed. ``field_value`` corresponds to RFC 7838's
        "Alternative Service Field Value".

        .. note:: It is strongly preferred to use the explicit method of
                  advertising Alternative Services. The implicit method of
                  advertising Alternative Services has a number of subtleties
                  and can lead to inconsistencies between the server and
                  client. h2 allows both mechanisms, but caution is
                  strongly advised.

        .. versionadded:: 2.3.0

        :param field_value: The RFC 7838 Alternative Service Field Value. This
            argument is not introspected by h2: the user is responsible
            for ensuring that it is well-formed.
        :type field_value: ``bytes``

        :param origin: The origin/authority to which the Alternative Service
            being advertised applies. Must not be provided at the same time as
            ``stream_id``.
        :type origin: ``bytes`` or ``None``

        :param stream_id: The ID of the stream which was sent to the authority
            for which this Alternative Service advertisement applies. Must not
            be provided at the same time as ``origin``.
        :type stream_id: ``int`` or ``None``

        :returns: Nothing.
        """
        if not isinstance(field_value, bytes):
            msg = "Field must be bytestring."
            raise ValueError(msg)  # noqa: TRY004

        if origin is not None and stream_id is not None:
            msg = "Must not provide both origin and stream_id"
            raise ValueError(msg)

        self.state_machine.process_input(
            ConnectionInputs.SEND_ALTERNATIVE_SERVICE,
        )

        if origin is not None:
            # This ALTSVC is sent on stream zero.
            f = AltSvcFrame(stream_id=0)
            f.origin = origin
            f.field = field_value
            frames: list[Frame] = [f]
        else:
            stream = self._get_stream_by_id(stream_id)
            frames = stream.advertise_alternative_service(field_value)

        self._prepare_for_sending(frames)

    def prioritize(self,
                   stream_id: int,
                   weight: int | None = None,
                   depends_on: int | None = None,
                   exclusive: bool | None = None) -> None:
        """
        Notify a server about the priority of a stream.

        Stream priorities are a form of guidance to a remote server: they
        inform the server about how important a given response is, so that the
        server may allocate its resources (e.g. bandwidth, CPU time, etc.)
        accordingly. This exists to allow clients to ensure that the most
        important data arrives earlier, while less important data does not
        starve out the more important data.

        Stream priorities are explained in depth in `RFC 7540 Section 5.3
        <https://tools.ietf.org/html/rfc7540#section-5.3>`_.

        This method updates the priority information of a single stream. It may
        be called well before a stream is actively in use, or well after a
        stream is closed.

        .. warning:: RFC 7540 allows for servers to change the priority of
                     streams. However, h2 **does not** allow server
                     stacks to do this. This is because most clients do not
                     adequately know how to respond when provided conflicting
                     priority information, and relatively little utility is
                     provided by making that functionality available.

        .. note:: h2 **does not** maintain any information about the
                  RFC 7540 priority tree. That means that h2 does not
                  prevent incautious users from creating invalid priority
                  trees, particularly by creating priority loops. While some
                  basic error checking is provided by h2, users are
                  strongly recommended to understand their prioritisation
                  strategies before using the priority tools here.

        .. note:: Priority information is strictly advisory. Servers are
                  allowed to disregard it entirely. Avoid relying on the idea
                  that your priority signaling will definitely be obeyed.

        .. versionadded:: 2.4.0

        :param stream_id: The ID of the stream to prioritize.
        :type stream_id: ``int``

        :param weight: The weight to give the stream. Defaults to ``16``, the
             default weight of any stream. May be any value between ``1`` and
             ``256`` inclusive. The relative weight of a stream indicates what
             proportion of available resources will be allocated to that
             stream.
        :type weight: ``int``

        :param depends_on: The ID of the stream on which this stream depends.
             This stream will only be progressed if it is impossible to
             progress the parent stream (the one on which this one depends).
             Passing the value ``0`` means that this stream does not depend on
             any other. Defaults to ``0``.
        :type depends_on: ``int``

        :param exclusive: Whether this stream is an exclusive dependency of its
            "parent" stream (i.e. the stream given by ``depends_on``). If a
            stream is an exclusive dependency of another, that means that all
            previously-set children of the parent are moved to become children
            of the new exclusively-dependent stream. Defaults to ``False``.
        :type exclusive: ``bool``
        """
        if not self.config.client_side:
            msg = "Servers SHOULD NOT prioritize streams."
            raise RFC1122Error(msg)

        self.state_machine.process_input(
            ConnectionInputs.SEND_PRIORITY,
        )

        frame = PriorityFrame(stream_id)
        frame_prio = _add_frame_priority(frame, weight, depends_on, exclusive)

        self._prepare_for_sending([frame_prio])

    def local_flow_control_window(self, stream_id: int) -> int:
        """
        Returns the maximum amount of data that can be sent on stream
        ``stream_id``.

        This value will never be larger than the total data that can be sent on
        the connection: even if the given stream allows more data, the
        connection window provides a logical maximum to the amount of data that
        can be sent.

        The maximum data that can be sent in a single data frame on a stream
        is either this value, or the maximum frame size, whichever is
        *smaller*.

        :param stream_id: The ID of the stream whose flow control window is
            being queried.
        :type stream_id: ``int``
        :returns: The amount of data in bytes that can be sent on the stream
            before the flow control window is exhausted.
        :rtype: ``int``
        """
        stream = self._get_stream_by_id(stream_id)
        return min(
            self.outbound_flow_control_window,
            stream.outbound_flow_control_window,
        )

    def remote_flow_control_window(self, stream_id: int) -> int:
        """
        Returns the maximum amount of data the remote peer can send on stream
        ``stream_id``.

        This value will never be larger than the total data that can be sent on
        the connection: even if the given stream allows more data, the
        connection window provides a logical maximum to the amount of data that
        can be sent.

        The maximum data that can be sent in a single data frame on a stream
        is either this value, or the maximum frame size, whichever is
        *smaller*.

        :param stream_id: The ID of the stream whose flow control window is
            being queried.
        :type stream_id: ``int``
        :returns: The amount of data in bytes that can be received on the
            stream before the flow control window is exhausted.
        :rtype: ``int``
        """
        stream = self._get_stream_by_id(stream_id)
        return min(
            self.inbound_flow_control_window,
            stream.inbound_flow_control_window,
        )

    def acknowledge_received_data(self, acknowledged_size: int, stream_id: int) -> None:
        """
        Inform the :class:`H2Connection <h2.connection.H2Connection>` that a
        certain number of flow-controlled bytes have been processed, and that
        the space should be handed back to the remote peer at an opportune
        time.

        .. versionadded:: 2.5.0

        :param acknowledged_size: The total *flow-controlled size* of the data
            that has been processed. Note that this must include the amount of
            padding that was sent with that data.
        :type acknowledged_size: ``int``
        :param stream_id: The ID of the stream on which this data was received.
        :type stream_id: ``int``
        :returns: Nothing
        :rtype: ``None``
        """
        self.config.logger.debug(
            "Ack received data on stream ID %d with size %d",
            stream_id, acknowledged_size,
        )
        if stream_id <= 0:
            msg = f"Stream ID {stream_id} is not valid for acknowledge_received_data"
            raise ValueError(msg)
        if acknowledged_size < 0:
            msg = "Cannot acknowledge negative data"
            raise ValueError(msg)

        frames: list[Frame] = []

        conn_manager = self._inbound_flow_control_window_manager
        conn_increment = conn_manager.process_bytes(acknowledged_size)
        if conn_increment:
            f = WindowUpdateFrame(0)
            f.window_increment = conn_increment
            frames.append(f)

        try:
            stream = self._get_stream_by_id(stream_id)
        except StreamClosedError:
            # The stream is already gone. We're not worried about incrementing
            # the window in this case.
            pass
        else:
            # No point incrementing the windows of closed streams.
            if stream.open:
                frames.extend(
                    stream.acknowledge_received_data(acknowledged_size),
                )

        self._prepare_for_sending(frames)

    def data_to_send(self, amount: int | None = None) -> bytes:
        """
        Returns some data for sending out of the internal data buffer.

        This method is analogous to ``read`` on a file-like object, but it
        doesn't block. Instead, it returns as much data as the user asks for,
        or less if that much data is not available. It does not perform any
        I/O, and so uses a different name.

        :param amount: (optional) The maximum amount of data to return. If not
            set, or set to ``None``, will return as much data as possible.
        :type amount: ``int``
        :returns: A bytestring containing the data to send on the wire.
        :rtype: ``bytes``
        """
        if amount is None:
            data = bytes(self._data_to_send)
            self._data_to_send = bytearray()
            return data
        data = bytes(self._data_to_send[:amount])
        self._data_to_send = self._data_to_send[amount:]
        return data

    def clear_outbound_data_buffer(self) -> None:
        """
        Clears the outbound data buffer, such that if this call was immediately
        followed by a call to
        :meth:`data_to_send <h2.connection.H2Connection.data_to_send>`, that
        call would return no data.

        This method should not normally be used, but is made available to avoid
        exposing implementation details.
        """
        self._data_to_send = bytearray()

    def _acknowledge_settings(self) -> list[Frame]:
        """
        Acknowledge settings that have been received.

        .. versionchanged:: 2.0.0
           Removed from public API, removed useless ``event`` parameter, made
           automatic.

        :returns: Nothing
        """
        self.state_machine.process_input(ConnectionInputs.SEND_SETTINGS)

        changes = self.remote_settings.acknowledge()

        if SettingCodes.INITIAL_WINDOW_SIZE in changes:
            setting = changes[SettingCodes.INITIAL_WINDOW_SIZE]
            self._flow_control_change_from_settings(
                setting.original_value,
                setting.new_value,
            )

        # HEADER_TABLE_SIZE changes by the remote part affect our encoder: cf.
        # RFC 7540 Section 6.5.2.
        if SettingCodes.HEADER_TABLE_SIZE in changes:
            setting = changes[SettingCodes.HEADER_TABLE_SIZE]
            self.encoder.header_table_size = setting.new_value

        if SettingCodes.MAX_FRAME_SIZE in changes:
            setting = changes[SettingCodes.MAX_FRAME_SIZE]
            self.max_outbound_frame_size = setting.new_value
            for stream in self.streams.values():
                stream.max_outbound_frame_size = setting.new_value

        f = SettingsFrame(0)
        f.flags.add("ACK")
        return [f]

    def _flow_control_change_from_settings(self, old_value: int | None, new_value: int) -> None:
        """
        Update flow control windows in response to a change in the value of
        SETTINGS_INITIAL_WINDOW_SIZE.

        When this setting is changed, it automatically updates all flow control
        windows by the delta in the settings values. Note that it does not
        increment the *connection* flow control window, per section 6.9.2 of
        RFC 7540.
        """
        delta = new_value - (old_value or 0)

        for stream in self.streams.values():
            stream.outbound_flow_control_window = guard_increment_window(
                stream.outbound_flow_control_window,
                delta,
            )

    def _inbound_flow_control_change_from_settings(self, old_value: int | None, new_value: int) -> None:
        """
        Update remote flow control windows in response to a change in the value
        of SETTINGS_INITIAL_WINDOW_SIZE.

        When this setting is changed, it automatically updates all remote flow
        control windows by the delta in the settings values.
        """
        delta = new_value - (old_value or 0)

        for stream in self.streams.values():
            stream._inbound_flow_control_change_from_settings(delta)

    def receive_data(self, data: Buffer) -> list[Event]:
        """
        Pass some received HTTP/2 data to the connection for handling.

        :param data: The data received from the remote peer on the network.
        :type data: An object implementing the buffer protocol.
        :returns: A list of events that the remote peer triggered by sending
            this data.
        """
        self.config.logger.trace(
            "Process received data on connection. Received data: %r", data,
        )

        events: list[Event] = []
        self.incoming_buffer.add_data(data)
        self.incoming_buffer.max_frame_size = self.max_inbound_frame_size

        try:
            for frame in self.incoming_buffer:
                events.extend(self._receive_frame(frame))
        except InvalidPaddingError as e:
            self._terminate_connection(ErrorCodes.PROTOCOL_ERROR)
            msg = "Received frame with invalid padding."
            raise ProtocolError(msg) from e
        except ProtocolError as e:
            # For whatever reason, receiving the frame caused a protocol error.
            # We should prepare to emit a GoAway frame before throwing the
            # exception up further. No need for an event: the exception will
            # do fine.
            self._terminate_connection(e.error_code)
            raise

        return events

    def _receive_frame(self, frame: Frame) -> list[Event]:
        """
        Handle a frame received on the connection.

        .. versionchanged:: 2.0.0
           Removed from the public API.
        """
        events: list[Event]
        self.config.logger.trace("Received frame: %s", repr(frame))
        try:
            # I don't love using __class__ here, maybe reconsider it.
            frames, events = self._frame_dispatch_table[frame.__class__](frame)
        except StreamClosedError as e:
            # If the stream was closed by RST_STREAM, we just send a RST_STREAM
            # to the remote peer. Otherwise, this is a connection error, and so
            # we will re-raise to trigger one.
            if self._stream_is_closed_by_reset(e.stream_id):
                f = RstStreamFrame(e.stream_id)
                f.error_code = e.error_code
                self._prepare_for_sending([f])
                events = e._events
            else:
                raise
        except StreamIDTooLowError as e:
            # The stream ID seems invalid. This may happen when the closed
            # stream has been cleaned up, or when the remote peer has opened a
            # new stream with a higher stream ID than this one, forcing it
            # closed implicitly.
            #
            # Check how the stream was closed: depending on the mechanism, it
            # is either a stream error or a connection error.
            if self._stream_is_closed_by_reset(e.stream_id):
                # Closed by RST_STREAM is a stream error.
                f = RstStreamFrame(e.stream_id)
                f.error_code = ErrorCodes.STREAM_CLOSED
                self._prepare_for_sending([f])
                events = []
            elif self._stream_is_closed_by_end(e.stream_id):
                # Closed by END_STREAM is a connection error.
                raise StreamClosedError(e.stream_id) from e
            else:
                # Closed implicitly, also a connection error, but of type
                # PROTOCOL_ERROR.
                raise
        else:
            self._prepare_for_sending(frames)

        return events

    def _terminate_connection(self, error_code: ErrorCodes) -> None:
        """
        Terminate the connection early. Used in error handling blocks to send
        GOAWAY frames.
        """
        f = GoAwayFrame(0)
        f.last_stream_id = self.highest_inbound_stream_id
        f.error_code = error_code
        self.state_machine.process_input(ConnectionInputs.SEND_GOAWAY)
        self._prepare_for_sending([f])

    def _receive_headers_frame(self, frame: HeadersFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a headers frame on the connection.
        """
        # If necessary, check we can open the stream. Also validate that the
        # stream ID is valid.
        if frame.stream_id not in self.streams:
            max_open_streams = self.local_settings.max_concurrent_streams
            value = self.open_inbound_streams # take a copy due to the property accessor having side affects
            if (value + 1) > max_open_streams:
                msg = f"Max inbound streams is {max_open_streams}, {value} open"
                raise TooManyStreamsError(msg)

        # Let's decode the headers. We handle headers as bytes internally up
        # until we hang them off the event, at which point we may optionally
        # convert them to unicode.
        headers = _h2_connection_decode_headers(self.decoder, frame.data)

        events = self.state_machine.process_input(
            ConnectionInputs.RECV_HEADERS,
        )
        stream = self._get_or_create_stream(
            frame.stream_id, AllowedStreamIDs(not self.config.client_side),
        )
        frames, stream_events = stream.receive_headers(
            headers,
            "END_STREAM" in frame.flags,
            self.config.header_encoding,
        )

        if "PRIORITY" in frame.flags:
            p_frames, p_events = self._receive_priority_frame(frame)
            expected_frame_types = (RequestReceived, ResponseReceived, TrailersReceived, InformationalResponseReceived)
            assert isinstance(stream_events[0], expected_frame_types)
            assert isinstance(p_events[0], PriorityUpdated)
            stream_events[0].priority_updated = p_events[0]
            stream_events.extend(p_events)
            assert not p_frames

        return frames, events + stream_events

    def _receive_push_promise_frame(self, frame: PushPromiseFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a push-promise frame on the connection.
        """
        if not self.local_settings.enable_push:
            msg = "Received pushed stream"
            raise ProtocolError(msg)

        pushed_headers = _h2_connection_decode_headers(self.decoder, frame.data)

        events = self.state_machine.process_input(
            ConnectionInputs.RECV_PUSH_PROMISE,
        )

        try:
            stream = self._get_stream_by_id(frame.stream_id)
        except NoSuchStreamError as e:
            # We need to check if the parent stream was reset by us. If it was
            # then we presume that the PUSH_PROMISE was in flight when we reset
            # the parent stream. Rather than accept the new stream, just reset
            # it.
            #
            # If this was closed naturally, however, we should call this a
            # PROTOCOL_ERROR: pushing a stream on a naturally closed stream is
            # a real problem because it creates a brand new stream that the
            # remote peer now believes exists.
            if (self._stream_closed_by(frame.stream_id) ==
                    StreamClosedBy.SEND_RST_STREAM):
                f = RstStreamFrame(frame.promised_stream_id)
                f.error_code = ErrorCodes.REFUSED_STREAM
                return [f], events

            msg = "Attempted to push on closed stream."
            raise ProtocolError(msg) from e

        # We need to prevent peers pushing streams in response to streams that
        # they themselves have already pushed: see #163 and RFC 7540 § 6.6. The
        # easiest way to do that is to assert that the stream_id is not even:
        # this shortcut works because only servers can push and the state
        # machine will enforce this.
        if (frame.stream_id % 2) == 0:
            msg = "Cannot recursively push streams."
            raise ProtocolError(msg)

        try:
            frames, stream_events = stream.receive_push_promise_in_band(
                frame.promised_stream_id,
                pushed_headers,
                self.config.header_encoding,
            )
        except StreamClosedError:
            # The parent stream was reset by us, so we presume that
            # PUSH_PROMISE was in flight when we reset the parent stream.
            # So we just reset the new stream.
            f = RstStreamFrame(frame.promised_stream_id)
            f.error_code = ErrorCodes.REFUSED_STREAM
            return [f], events

        new_stream = self._begin_new_stream(
            frame.promised_stream_id, AllowedStreamIDs.EVEN,
        )
        self.streams[frame.promised_stream_id] = new_stream
        new_stream.remotely_pushed(pushed_headers)

        return frames, events + stream_events

    def _handle_data_on_closed_stream(self,
                                      events: list[Event],
                                      exc: StreamClosedError,
                                      frame: DataFrame) -> tuple[list[Frame], list[Event]]:
        # This stream is already closed - and yet we received a DATA frame.
        # The received DATA frame counts towards the connection flow window.
        # We need to manually to acknowledge the DATA frame to update the flow
        # window of the connection. Otherwise the whole connection stalls due
        # the inbound flow window being 0.
        frames: list[Frame] = []
        conn_manager = self._inbound_flow_control_window_manager
        conn_increment = conn_manager.process_bytes(
            frame.flow_controlled_length,
        )

        if conn_increment:
            window_update_frame = WindowUpdateFrame(0)
            window_update_frame.window_increment = conn_increment
            frames.append(window_update_frame)
            self.config.logger.debug(
                "Received DATA frame on closed stream %d - "
                "auto-emitted a WINDOW_UPDATE by %d",
                frame.stream_id, conn_increment,
            )

        rst_stream_frame = RstStreamFrame(exc.stream_id)
        rst_stream_frame.error_code = exc.error_code
        frames.append(rst_stream_frame)
        self.config.logger.debug(
            "Stream %s already CLOSED or cleaned up - auto-emitted a RST_FRAME",
            frame.stream_id,
        )
        return frames, events + exc._events

    def _receive_data_frame(self, frame: DataFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a data frame on the connection.
        """
        flow_controlled_length = frame.flow_controlled_length

        events = self.state_machine.process_input(
            ConnectionInputs.RECV_DATA,
        )
        self._inbound_flow_control_window_manager.window_consumed(
            flow_controlled_length,
        )

        try:
            stream = self._get_stream_by_id(frame.stream_id)
            frames, stream_events = stream.receive_data(
                frame.data,
                "END_STREAM" in frame.flags,
                flow_controlled_length,
            )
        except StreamClosedError as e:
            # This stream is either marked as CLOSED or already gone from our
            # internal state.
            return self._handle_data_on_closed_stream(events, e, frame)

        return frames, events + stream_events

    def _receive_settings_frame(self, frame: SettingsFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a SETTINGS frame on the connection.
        """
        events = self.state_machine.process_input(
            ConnectionInputs.RECV_SETTINGS,
        )

        # This is an ack of the local settings.
        if "ACK" in frame.flags:
            changed_settings = self._local_settings_acked()
            ack_event = SettingsAcknowledged()
            ack_event.changed_settings = changed_settings
            events.append(ack_event)
            return [], events

        # Add the new settings.
        for setting, value in frame.settings.items():
            self.remote_settings.validate_received_setting(setting, value)
        self.remote_settings.update(frame.settings)
        events.append(
            RemoteSettingsChanged.from_settings(
                self.remote_settings, frame.settings,
            ),
        )
        frames = self._acknowledge_settings()

        return frames, events

    def _receive_window_update_frame(self, frame: WindowUpdateFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a WINDOW_UPDATE frame on the connection.
        """
        # hyperframe will take care of validating the window_increment.
        # If we reach in here, we can assume a valid value.

        events = self.state_machine.process_input(
            ConnectionInputs.RECV_WINDOW_UPDATE,
        )

        if frame.stream_id:
            try:
                stream = self._get_stream_by_id(frame.stream_id)
                frames, stream_events = stream.receive_window_update(
                    frame.window_increment,
                )
            except StreamClosedError:
                return [], events
        else:
            # Increment our local flow control window.
            self.outbound_flow_control_window = guard_increment_window(
                self.outbound_flow_control_window,
                frame.window_increment,
            )

            # FIXME: Should we split this into one event per active stream?
            window_updated_event = WindowUpdated(stream_id=0, delta=frame.window_increment)
            stream_events = [window_updated_event]
            frames = []

        return frames, events + stream_events

    def _receive_ping_frame(self, frame: PingFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a PING frame on the connection.
        """
        events = self.state_machine.process_input(
            ConnectionInputs.RECV_PING,
        )
        frames: list[Frame] = []

        evt: PingReceived | PingAckReceived
        if "ACK" in frame.flags:
            evt = PingAckReceived(ping_data=frame.opaque_data)
        else:
            evt = PingReceived(ping_data=frame.opaque_data)

            # automatically ACK the PING with the same 'opaque data'
            f = PingFrame(0)
            f.flags.add("ACK")
            f.opaque_data = frame.opaque_data
            frames.append(f)

        events.append(evt)

        return frames, events

    def _receive_rst_stream_frame(self, frame: RstStreamFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a RST_STREAM frame on the connection.
        """
        events = self.state_machine.process_input(
            ConnectionInputs.RECV_RST_STREAM,
        )
        try:
            stream = self._get_stream_by_id(frame.stream_id)
        except NoSuchStreamError:
            # The stream is missing. That's ok, we just do nothing here.
            stream_frames: list[Frame] = []
            stream_events: list[Event] = []
        else:
            stream_frames, stream_events = stream.stream_reset(frame)

        return stream_frames, events + stream_events

    def _receive_priority_frame(self, frame: HeadersFrame | PriorityFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a PRIORITY frame on the connection.
        """
        events = self.state_machine.process_input(
            ConnectionInputs.RECV_PRIORITY,
        )

        event = PriorityUpdated()
        event.stream_id = frame.stream_id
        event.depends_on = frame.depends_on
        event.exclusive = frame.exclusive

        # Weight is an integer between 1 and 256, but the byte only allows
        # 0 to 255: add one.
        event.weight = frame.stream_weight + 1

        # A stream may not depend on itself.
        if event.depends_on == frame.stream_id:
            msg = f"Stream {frame.stream_id} may not depend on itself"
            raise ProtocolError(msg)
        events.append(event)

        return [], events

    def _receive_goaway_frame(self, frame: GoAwayFrame) -> tuple[list[Frame], list[Event]]:
        """
        Receive a GOAWAY frame on the connection.
        """
        events = self.state_machine.process_input(
            ConnectionInputs.RECV_GOAWAY,
        )

        # Clear the outbound data buffer: we cannot send further data now.
        self.clear_outbound_data_buffer()

        # Fire an appropriate ConnectionTerminated event.
        new_event = ConnectionTerminated()
        new_event.error_code = _error_code_from_int(frame.error_code)
        new_event.last_stream_id = frame.last_stream_id
        new_event.additional_data = frame.additional_data or None
        events.append(new_event)

        return [], events

    def _receive_naked_continuation(self, frame: ContinuationFrame) -> None:
        """
        A naked CONTINUATION frame has been received. This is always an error,
        but the type of error it is depends on the state of the stream and must
        transition the state of the stream, so we need to pass it to the
        appropriate stream.
        """
        stream = self._get_stream_by_id(frame.stream_id)
        stream.receive_continuation()
        msg = "Should not be reachable"  # pragma: no cover
        raise AssertionError(msg)  # pragma: no cover

    def _receive_alt_svc_frame(self, frame: AltSvcFrame) -> tuple[list[Frame], list[Event]]:
        """
        An ALTSVC frame has been received. This frame, specified in RFC 7838,
        is used to advertise alternative places where the same service can be
        reached.

        This frame can optionally be received either on a stream or on stream
        0, and its semantics are different in each case.
        """
        events = self.state_machine.process_input(
            ConnectionInputs.RECV_ALTERNATIVE_SERVICE,
        )
        frames = []

        if frame.stream_id:
            # Given that it makes no sense to receive ALTSVC on a stream
            # before that stream has been opened with a HEADERS frame, the
            # ALTSVC frame cannot create a stream. If the stream is not
            # present, we simply ignore the frame.
            try:
                stream = self._get_stream_by_id(frame.stream_id)
            except (NoSuchStreamError, StreamClosedError):
                pass
            else:
                stream_frames, stream_events = stream.receive_alt_svc(frame)
                frames.extend(stream_frames)
                events.extend(stream_events)
        else:
            # This frame is sent on stream 0. The origin field on the frame
            # must be present, though if it isn't it's not a ProtocolError
            # (annoyingly), we just need to ignore it.
            if not frame.origin:
                return frames, events

            # If we're a server, we want to ignore this (RFC 7838 says so).
            if not self.config.client_side:
                return frames, events

            event = AlternativeServiceAvailable()
            event.origin = frame.origin
            event.field_value = frame.field
            events.append(event)

        return frames, events

    def _receive_unknown_frame(self, frame: ExtensionFrame) -> tuple[list[Frame], list[Event]]:
        """
        We have received a frame that we do not understand. This is almost
        certainly an extension frame, though it's impossible to be entirely
        sure.

        RFC 7540 § 5.5 says that we MUST ignore unknown frame types: so we
        do. We do notify the user that we received one, however.
        """
        # All we do here is log.
        self.config.logger.debug(
            "Received unknown extension frame (ID %d)", frame.stream_id,
        )
        event = UnknownFrameReceived(frame=frame)
        return [], [event]

    def _local_settings_acked(self) -> dict[SettingCodes | int, ChangedSetting]:
        """
        Handle the local settings being ACKed, update internal state.
        """
        changes = self.local_settings.acknowledge()

        if SettingCodes.INITIAL_WINDOW_SIZE in changes:
            setting = changes[SettingCodes.INITIAL_WINDOW_SIZE]
            self._inbound_flow_control_change_from_settings(
                setting.original_value,
                setting.new_value,
            )

        if SettingCodes.MAX_HEADER_LIST_SIZE in changes:
            setting = changes[SettingCodes.MAX_HEADER_LIST_SIZE]
            self.decoder.max_header_list_size = setting.new_value

        if SettingCodes.MAX_FRAME_SIZE in changes:
            setting = changes[SettingCodes.MAX_FRAME_SIZE]
            self.max_inbound_frame_size = setting.new_value

        if SettingCodes.HEADER_TABLE_SIZE in changes:
            setting = changes[SettingCodes.HEADER_TABLE_SIZE]
            # This is safe across all hpack versions: some versions just won't
            # respect it.
            self.decoder.max_allowed_table_size = setting.new_value

        return changes

    def _stream_id_is_outbound(self, stream_id: int) -> bool:
        """
        Returns ``True`` if the stream ID corresponds to an outbound stream
        (one initiated by this peer), returns ``False`` otherwise.
        """
        return (stream_id % 2 == int(self.config.client_side))

    def _stream_closed_by(self, stream_id: int) -> StreamClosedBy | None:
        """
        Returns how the stream was closed.

        The return value will be either a member of
        ``h2.stream.StreamClosedBy`` or ``None``. If ``None``, the stream was
        closed implicitly by the peer opening a stream with a higher stream ID
        before opening this one.
        """
        if stream_id in self.streams:
            return self.streams[stream_id].closed_by
        if stream_id in self._closed_streams:
            return self._closed_streams[stream_id]
        return None

    def _stream_is_closed_by_reset(self, stream_id: int) -> bool:
        """
        Returns ``True`` if the stream was closed by sending or receiving a
        RST_STREAM frame. Returns ``False`` otherwise.
        """
        return self._stream_closed_by(stream_id) in (
            StreamClosedBy.RECV_RST_STREAM, StreamClosedBy.SEND_RST_STREAM,
        )

    def _stream_is_closed_by_end(self, stream_id: int) -> bool:
        """
        Returns ``True`` if the stream was closed by sending or receiving an
        END_STREAM flag in a HEADERS or DATA frame. Returns ``False``
        otherwise.
        """
        return self._stream_closed_by(stream_id) in (
            StreamClosedBy.RECV_END_STREAM, StreamClosedBy.SEND_END_STREAM,
        )


def _add_frame_priority(frame: PriorityFrame | HeadersFrame,
                        weight: int | None = None,
                        depends_on: int | None = None,
                        exclusive: bool | None = None) -> PriorityFrame | HeadersFrame:
    """
    Adds priority data to a given frame. Does not change any flags set on that
    frame: if the caller is adding priority information to a HEADERS frame they
    must set that themselves.

    This method also deliberately sets defaults for anything missing.

    This method validates the input values.
    """
    # A stream may not depend on itself.
    if depends_on == frame.stream_id:
        msg = f"Stream {frame.stream_id} may not depend on itself"
        raise ProtocolError(msg)

    # Weight must be between 1 and 256.
    if weight is not None:
        if weight > 256 or weight < 1:
            msg = f"Weight must be between 1 and 256, not {weight}"
            raise ProtocolError(msg)
        # Weight is an integer between 1 and 256, but the byte only allows
        # 0 to 255: subtract one.
        weight -= 1

    # Set defaults for anything not provided.
    weight = weight if weight is not None else 15
    depends_on = depends_on if depends_on is not None else 0
    exclusive = exclusive if exclusive is not None else False

    frame.stream_weight = weight
    frame.depends_on = depends_on
    frame.exclusive = exclusive

    return frame


def _h2_connection_decode_headers(decoder: Decoder, encoded_header_block: bytes) -> Iterable[Header]:
    """
    Decode a HPACK-encoded header block, translating HPACK exceptions into
    sensible h2 errors.

    This only ever returns bytestring headers: h2 may emit them as
    unicode later, but internally it processes them as bytestrings only.
    """
    try:
        return decoder.decode(encoded_header_block, raw=True)
    except OversizedHeaderListError as e:
        # This is a symptom of a HPACK bomb attack: the user has
        # disregarded our requirements on how large a header block we'll
        # accept.
        msg = f"Oversized header block: {e}"
        raise DenialOfServiceError(msg) from e
    except (HPACKError, IndexError, TypeError, UnicodeDecodeError) as e:
        # We should only need HPACKError here, but versions of HPACK older
        # than 2.1.0 throw all three others as well. For maximum
        # compatibility, catch all of them.
        msg = f"Error decoding header block: {e}"
        raise ProtocolError(msg) from e
