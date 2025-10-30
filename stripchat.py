import re
import time
import requests
import base64
import hashlib
import urllib.parse

from streamlink.plugin import Plugin, pluginmatcher
from streamlink.plugin.api import validate
from streamlink.stream import HLSStream

_post_schema = validate.Schema(
    {
        "cam": validate.Schema({
            "isCamAvailable": bool,
            "streamName": validate.any(str, None),
            "isCamActive": bool
        }),
        "user": validate.Schema({
            "user": validate.Schema({
                "status": str
            })
        })
    }
)

@pluginmatcher(re.compile(r"https?://(\w+\.)?stripchat\.com/(?P<username>[a-zA-Z0-9_-]+)"))
class Stripchat(Plugin):
    
    _static_data = None
    _main_js_data = None
    _doppio_js_data = None
    _mouflon_keys = {}
    _cached_keys = {}
    @classmethod
    def _populate_mouflon_keys_from_doppio(cls):
        """Extracts pkey:decode_key pairs from Doppio.js using a generic regex.
        This allows discovering dynamic pkeys without relying on hardcoded values."""
        try:
            if not cls._doppio_js_data:
                return
            pattern = r"\b[A-Za-z0-9]{12,}:[A-Za-z0-9]{12,}\b"
            matches = re.findall(pattern, cls._doppio_js_data)
            added = 0
            for m in matches:
                left, right = m.split(":", 1)
                if left and right and left not in cls._mouflon_keys:
                    cls._mouflon_keys[left] = right
                    added += 1
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_populate_mouflon_keys_from_doppio: pairs added={added} total={len(cls._mouflon_keys)}")
        except Exception as e:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_populate_mouflon_keys_from_doppio: error {e}")
    @classmethod
    def can_handle_url(cls, url):
        return cls._re_url.match(url) is not None
    
    @classmethod
    def _get_initial_data(cls):
        """Fetches static data and required JavaScript files"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Fetch static data
        r = requests.get('https://stripchat.com/api/front/v3/config/static', headers=headers)
        if r.status_code != 200:
            raise Exception("Failed to fetch static data from StripChat")
        cls._static_data = r.json().get('static')

        # Fetch JavaScript files
        mmp_origin = cls._static_data['features']['MMPExternalSourceOrigin']
        mmp_version = cls._static_data['featuresV2']['playerModuleExternalLoading']['mmpVersion']
        mmp_base = f"{mmp_origin}/v{mmp_version}"

        r = requests.get(f"{mmp_base}/main.js", headers=headers)
        if r.status_code != 200:
            raise Exception("Failed to fetch main.js from StripChat")
        cls._main_js_data = r.content.decode('utf-8')

        doppio_js_name = re.findall('require[(]"./(Doppio.*?[.]js)"[)]', cls._main_js_data)[0]

        r = requests.get(f"{mmp_base}/{doppio_js_name}", headers=headers)
        if r.status_code != 200:
            raise Exception("Failed to fetch doppio.js from StripChat")
        cls._doppio_js_data = r.content.decode('utf-8')
        # Populate Mouflon keys from Doppio.js
        cls._populate_mouflon_keys_from_doppio()
    
    @classmethod
    def _get_mouflon_from_m3u(cls, m3u8_doc):
        """Extracts Mouflon information from the M3U8 document"""
        try:
            # Find the latest Mouflon line (in case there's more than one)
            lines = [l.strip() for l in m3u8_doc.splitlines() if l.strip().startswith('#EXT-X-MOUFLON')]
            if not lines:
                return None, None

            line = lines[-1]

            psch = None
            pkey = None

            # Case 1: Format "#EXT-X-MOUFLON:PSCH:v1:XXXXXXXXX"
            if line.upper().startswith('#EXT-X-MOUFLON:PSCH'):
                try:
                    parts = line.split(':')
                    # parts = ['#EXT-X-MOUFLON', 'PSCH', psch, pkey, ...]
                    if len(parts) >= 4:
                        psch = parts[2].strip()
                        pkey = parts[3].strip()
                except Exception:
                    pass

            # Case 2: Explicit keys format: psch=..., pkey=...
            if not pkey:
                psch_m = re.search(r"psch(?:=|:)\s*([A-Za-z0-9._-]+)", line, flags=re.IGNORECASE)
                pkey_m = re.search(r"pkey(?:=|:)\s*([A-Za-z0-9._-]+)", line, flags=re.IGNORECASE)
                psch = psch or (psch_m.group(1) if psch_m else None)
                pkey = pkey or (pkey_m.group(1) if pkey_m else None)

            # Some masters don't include psch; assume 'v1' for compatibility
            if not psch and pkey:
                psch = 'v1'
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error("_get_mouflon_from_m3u: psch missing, using 'v1' by default")

            # Detailed log for debugging
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_get_mouflon_from_m3u: line='{line}' psch='{psch}' pkey='{pkey}'")

            return psch, pkey
        except Exception as e:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_get_mouflon_from_m3u: error parsing Mouflon: {e}")
            return None, None
    
    @classmethod
    def _get_mouflon_dec_key(cls, pkey):
        """Gets the Mouflon decryption key"""
        try:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_get_mouflon_dec_key: searching key for pkey={pkey}")
            
            # Check if the key is already cached
            if pkey in cls._mouflon_keys:
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"Cached key for {pkey}: {cls._mouflon_keys[pkey][:8]}...")
                return cls._mouflon_keys[pkey]
            
            # Method 1: Search in Doppio.js with multiple robust patterns
            if cls._doppio_js_data:
                # Ensure we have extracted the complete map if not yet
                if not cls._mouflon_keys:
                    cls._populate_mouflon_keys_from_doppio()
                # If the pair already exists in the populated map, return it directly
                if pkey in cls._mouflon_keys:
                    key = cls._mouflon_keys[pkey]
                    if hasattr(Stripchat, 'logger') and Stripchat.logger:
                        Stripchat.logger.error(f"Key found in Doppio map for {pkey}: {key[:10]}...")
                    return key
                patterns = [
                    rf'\b["\']{re.escape(pkey)}["\']\s*:\s*["\']([^"\']+)["\']',  # quoted key and value
                    rf'\b{re.escape(pkey)}\s*:\s*["\']([^"\']+)["\']',               # unquoted key, quoted value
                    rf'\b{re.escape(pkey)}\s*:\s*([A-Za-z0-9._-]+)',                      # unquoted value
                ]
                matches = []
                for pat in patterns:
                    try:
                        found = re.findall(pat, cls._doppio_js_data)
                        if found:
                            matches.extend(found)
                    except Exception:
                        continue
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"Doppio.js: patterns tried={len(patterns)} total matches={len(matches)}")
                if matches:
                    key = matches[0]
                    cls._mouflon_keys[pkey] = key
                    if hasattr(Stripchat, 'logger') and Stripchat.logger:
                        Stripchat.logger.error(f"Key found in Doppio.js for {pkey}: {key[:10]}...")
                    return key
            
            # Method 2: Obtain the key from the homepage
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error("Attempting to get key from homepage...")
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0',
            }
            
            try:
                r = requests.get('https://stripchat.com/', headers=headers)
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"GET https://stripchat.com/ -> status={r.status_code}")
                
                if r.status_code == 200:
                    html_content = r.text
                    
                    # Search for scripts containing the Mouflon key
                    script_pattern = r'<script[^>]*>(.*?)</script>'
                    scripts = re.findall(script_pattern, html_content, re.DOTALL)
                    
                    for script in scripts:
                        # Search for Mouflon key patterns within the script
                        key_patterns = [
                            f'"{pkey}:(.*?)"',
                            f"'{pkey}:(.*?)'",
                            f'mouflon.*?{pkey}.*?["\'](.+?)["\']',
                            f'pkey.*?{pkey}.*?["\'](.+?)["\']'
                        ]
                        
                        for pattern in key_patterns:
                            matches = re.findall(pattern, script)
                            if matches:
                                key = matches[0]
                                cls._mouflon_keys[pkey] = key
                                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                                    Stripchat.logger.error(f"Key found in HTML for {pkey}: {key[:10]}...")
                                return key
                    
                    # Search in the full HTML if not found in scripts
                    for pattern in key_patterns:
                        matches = re.findall(pattern, html_content)
                        if matches:
                            key = matches[0]
                            cls._mouflon_keys[pkey] = key
                            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                                Stripchat.logger.error(f"Key found in full HTML for {pkey}: {key[:10]}...")
                            return key
            
            except Exception as e:
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"Error fetching homepage: {e}")
            # No hardcoded keys: if the key is not found in Doppio.js or HTML,
            # return empty to avoid incorrect decodings.
                
        except Exception as e:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"Error in _get_mouflon_dec_key: {e}")
        
        if hasattr(Stripchat, 'logger') and Stripchat.logger:
            Stripchat.logger.error(f"Could not find key for {pkey}")
        return ""
    
    @classmethod
    def _decode_mouflon(cls, encrypted_b64, key):
        """Decodes content encrypted with Mouflon"""
        try:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_decode_mouflon: start, key={key[:8] if key else 'EMPTY'}")
            
            # Verify that we have a valid key
            if not key:
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error("_decode_mouflon: empty key, returning placeholder")
                return "media.mp4"
            
            # Generate and cache the key hash if it doesn't exist
            if key not in cls._cached_keys:
                cls._cached_keys[key] = hashlib.sha256(key.encode("utf-8")).digest()
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error("_decode_mouflon: hash generated and cached")
            
            hash_bytes = cls._cached_keys[key]
            hash_len = len(hash_bytes)
            
            # Ensure base64 has the correct length
            padding = len(encrypted_b64) % 4
            if padding:
                encrypted_b64 += "=" * (4 - padding)
            
            try:
                # Attempt to decode base64
                encrypted_data = base64.b64decode(encrypted_b64)
            except Exception as e:
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"_decode_mouflon: error in base64 decode: {e}")
                    Stripchat.logger.error(f"_decode_mouflon: trying with additional padding")
                try:
                    # Try with additional padding
                    encrypted_data = base64.b64decode(encrypted_b64 + "==")
                except Exception as e2:
                    if hasattr(Stripchat, 'logger') and Stripchat.logger:
                        Stripchat.logger.error(f"_decode_mouflon: error on second attempt of base64 decode: {e2}")
                    return "media.mp4"
            
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_decode_mouflon: encrypted data len={len(encrypted_data)}")
            
            # Decode using XOR
            decrypted_bytes = bytearray()
            for i, cipher_byte in enumerate(encrypted_data):
                key_byte = hash_bytes[i % hash_len]
                decrypted_byte = cipher_byte ^ key_byte
                decrypted_bytes.append(decrypted_byte)
            
            # Try decoding as UTF-8
            try:
                result = decrypted_bytes.decode("utf-8")
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"_decode_mouflon: result len={len(result)}")
                return result
            except UnicodeDecodeError as e:
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error(f"_decode_mouflon: error in UTF-8 decode: {e}")
                
                # Try different encodings
                for encoding in ['latin-1', 'iso-8859-1', 'windows-1252']:
                    try:
                        result = decrypted_bytes.decode(encoding)
                        if hasattr(Stripchat, 'logger') and Stripchat.logger:
                            Stripchat.logger.error(f"_decode_mouflon: decoded with {encoding}, len={len(result)}")
                        return result
                    except Exception:
                        pass
                
                # If everything fails, return a default value
                if hasattr(Stripchat, 'logger') and Stripchat.logger:
                    Stripchat.logger.error("_decode_mouflon: could not decode, returning placeholder")
                return "media.mp4"
                
        except Exception as e:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_decode_mouflon: general error: {e}")
            return "media.mp4"
    
    @classmethod
    def _decode_m3u8(cls, content, psch_override=None, pkey_override=None):
        """Decodes M3U8 playlist with Mouflon encryption.
        Allows using known psch/pkey if the playlist doesn't include them explicitly."""
        psch, pkey = cls._get_mouflon_from_m3u(content)
        psch = psch or psch_override
        pkey = pkey or pkey_override
        if not pkey:
            return content

        def _append_params(url: str) -> str:
            try:
                p = urllib.parse.urlsplit(url)
                if not ('doppiocdn.com' in p.netloc or 'doppiocdn.net' in p.netloc):
                    return url
                q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
                changed = False
                if psch and 'psch' not in q:
                    q['psch'] = [psch]
                    changed = True
                if 'pkey' not in q:
                    q['pkey'] = [pkey]
                    changed = True
                if not changed:
                    return url
                new_q = urllib.parse.urlencode({k: v[0] for k, v in q.items()})
                return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, new_q, p.fragment))
            except Exception:
                return url

        decoded = []
        lines = content.splitlines()
        replaced_count = 0
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("#EXT-X-MOUFLON:FILE:"):
                dec = cls._decode_mouflon(line[20:], cls._get_mouflon_dec_key(pkey))
                # Replace the next line that contains the segment URL
                if i + 1 < len(lines):
                    next_line = lines[i + 1]
                    replaced = next_line.replace("media.mp4", dec)
                    decoded.append(_append_params(replaced))
                    if replaced != next_line:
                        replaced_count += 1
                    i += 2
                    continue
                else:
                    i += 1
                    continue
            elif line.startswith("#EXT-X-MAP:"):
                # Add psch/pkey to the init segment URI
                m = re.search(r'URI="([^"]+)"', line)
                if m:
                    new_uri = _append_params(m.group(1))
                    line = re.sub(r'URI="([^"]+)"', f'URI="{new_uri}"', line)
                decoded.append(line)
            elif line.startswith("#EXT-X-PART:"):
                # Add psch/pkey to the PART URI
                m = re.search(r'URI="([^"]+)"', line)
                if m:
                    new_uri = _append_params(m.group(1))
                    line = re.sub(r'URI="([^"]+)"', f'URI="{new_uri}"', line)
                decoded.append(line)
            elif line.startswith("#EXT-X-MOUFLON:"):
                # Skip Mouflon metadata
                i += 1
                continue
            else:
                # If it's a segment/playlist URL, append parameters
                if line.startswith('http://') or line.startswith('https://'):
                    decoded.append(_append_params(line))
                else:
                    decoded.append(line)
            i += 1
        out = "\n".join(decoded)
        try:
            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                Stripchat.logger.error(f"_decode_m3u8: Mouflon replacements performed={replaced_count}")
        except Exception:
            pass
        return out

    def _get_streams(self):
        # Initialize static data if necessary
        if self._static_data is None:
            try:
                self._get_initial_data()
            except Exception as e:
                self.logger.error(f"Failed to initialize StripChat data: {e}")
                return
        
        username = self.match.group("username")
        api_call = f"https://stripchat.com/api/front/v2/models/username/{username}/cam"
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'es',
            'Cache-Control': 'max-age=0',
            'DNT': '1',
            'Priority': 'u=0, i',
            'Sec-CH-UA': '"Chromium";v="140", "Not=A?Brand";v="24", "Microsoft Edge";v="140"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Upgrade-Insecure-Requests': '1',
            "Referer": self.url,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
        }

        res = self.session.http.get(api_call, headers=headers)
        try:
            data = self.session.http.json(res, schema=_post_schema)
        except Exception as e:
            self.logger.error(f"Failed to parse API response: {e}")
            return

        # Verify if the stream is available
        if not (data["user"]["user"]["status"] == "public" and 
                data["cam"]["isCamAvailable"] and 
                data["cam"]["isCamActive"]):
            #self.logger.info(f"Stream not available. Status: {data['user']['user']['status']}")
            return

        stream_name = data["cam"]["streamName"]
        if not stream_name:
            self.logger.error("No stream name found")
            return

        # Build master playlist URL
        master_url = f"https://edge-hls.doppiocdn.com/hls/{stream_name}/master/{stream_name}_auto.m3u8"
        
        try:
            # Strengthen session headers for all subsequent requests
            try:
                self.session.http.headers.update({
                    'Referer': self.url,
                    'Origin': 'https://stripchat.com',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0',
                    'Accept': '*/*',
                    'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Keep-Alive': 'timeout=30, max=1000',
                    'DNT': '1',
                })
            except Exception:
                pass

            # Fetch the master playlist
            master_res = self.session.http.get(master_url, headers={'Referer': self.url})
            master_content = master_res.text
            
            # Extract Mouflon parameters from the master; it may not include them
            psch, pkey = self._get_mouflon_from_m3u(master_content)
            if not psch:
                psch = 'v1'
            # If the master does not declare pkey, choose one detected from Doppio.js
            if not pkey:
                try:
                    candidates = list(self._mouflon_keys.keys()) if self._mouflon_keys else []
                    chosen = None
                    # Preferir el que parezca el conocido si existe, si no, el primero
                    for c in candidates:
                        if c.lower().startswith('zokee'):
                            chosen = c
                            break
                    if not chosen and candidates:
                        chosen = candidates[0]
                    pkey = chosen
                    if hasattr(self, 'logger') and self.logger:
                        self.logger.error(f"pkey not declared in master, using detected from Doppio: {pkey}")
                except Exception:
                    pkey = None
            if hasattr(self, 'logger') and self.logger:
                self.logger.error(f"Effective Mouflon: psch={psch} pkey={pkey}")
            
            # Parse playlist variants
            streams = HLSStream.parse_variant_playlist(
                self.session, 
                master_url, 
                headers={'Referer': self.url, 'Origin': 'https://stripchat.com'}
            )
            
            # If parameters are defined, create custom streams
            if psch and pkey:
                # Build new HLSStream with parameterized URLs without mutating internal properties
                try:
                    new_streams = {}
                    for quality, stream in streams.items():
                        url = getattr(stream, 'url', None)
                        if url:
                            parsed = urllib.parse.urlparse(url)
                            if 'doppiocdn.com' in parsed.netloc or 'doppiocdn.net' in parsed.netloc:
                                q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
                                if 'psch' not in q and psch:
                                    q['psch'] = psch
                                if 'pkey' not in q and pkey:
                                    q['pkey'] = pkey
                                new_query = urllib.parse.urlencode(q)
                                url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                        new_streams[quality] = HLSStream(self.session, url, headers={'Referer': self.url, 'Origin': 'https://stripchat.com'})
                    streams = new_streams
                except Exception as e:
                    if hasattr(self, 'logger') and self.logger:
                        self.logger.error(f"Error building parameterized HLSStream: {e}")

                # Create custom HTTP adapter to intercept requests
                from requests.adapters import HTTPAdapter
                from requests import Response
                import io
                
                class MouflonHTTPAdapter(HTTPAdapter):
                    def __init__(self, stripchat_instance, psch, pkey):
                        super().__init__()
                        self.stripchat = stripchat_instance
                        self.psch = psch
                        self.pkey = pkey
                    
                    def send(self, request, **kwargs):
                        # Add Mouflon parameters and headers to all requests to doppiocdn.com
                        try:
                            parsed = urllib.parse.urlparse(request.url)
                            if ('doppiocdn.com' in parsed.netloc) or ('doppiocdn.net' in parsed.netloc):
                                # Update critical headers
                                request.headers.setdefault('Referer', self.stripchat.url)
                                request.headers.setdefault('Origin', 'https://stripchat.com')
                                request.headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0')
                                request.headers.setdefault('Accept', '*/*')

                                # Merge existing parameters with missing psch/pkey
                                q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
                                changed = False
                                if 'psch' not in q:
                                    q['psch'] = self.psch
                                    changed = True
                                if 'pkey' not in q:
                                    q['pkey'] = self.pkey
                                    changed = True
                                if changed:
                                    new_query = urllib.parse.urlencode(q)
                                    new_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
                                    request.url = new_url
                                    if hasattr(Stripchat, 'logger') and Stripchat.logger:
                                        Stripchat.logger.error(f"MouflonHTTPAdapter: parameterized URL -> {request.url}")
                        except Exception as e:
                            if hasattr(Stripchat, 'logger') and Stripchat.logger:
                                Stripchat.logger.error(f"MouflonHTTPAdapter: error parameterizing URL: {e}")
                        
                        response = super().send(request, **kwargs)
                        
                        # Decode content if it's an M3U8 playlist with Mouflon
                        if (response.headers.get('content-type', '').lower().startswith('application/vnd.apple.mpegurl') or
                            request.url.endswith('.m3u8')) and '#EXT-X-MOUFLON:' in response.text:
                            
                            decoded_content = self.stripchat._decode_m3u8(response.text, self.psch, self.pkey)

                            # Log init URI if present
                            try:
                                m = re.search(r'#EXT-X-MAP:URI="([^"]+)"', decoded_content)
                                if m and hasattr(Stripchat, 'logger') and Stripchat.logger:
                                    Stripchat.logger.error(f"MouflonHTTPAdapter: INIT URI after decoding -> {m.group(1)}")
                            except Exception:
                                pass
                            
                            # Create a new response with decoded content
                            new_response = Response()
                            new_response.status_code = response.status_code
                            new_response.headers = response.headers
                            new_response.url = response.url
                            new_response.encoding = response.encoding
                            new_response._content = decoded_content.encode('utf-8')
                            
                            return new_response
                        
                        return response
                
                # Install the adapter in the session
                adapter = MouflonHTTPAdapter(self, psch, pkey)
                self.session.http.mount('https://media-hls.doppiocdn.com/', adapter)
                self.session.http.mount('https://edge-hls.doppiocdn.com/', adapter)
                self.session.http.mount('https://doppiocdn.com/', adapter)
                # Also cover .net domains
                self.session.http.mount('https://media-hls.doppiocdn.net/', adapter)
                self.session.http.mount('https://edge-hls.doppiocdn.net/', adapter)
                self.session.http.mount('https://doppiocdn.net/', adapter)
                
                # Create normal streams - the HTTP adapter will handle decoding
                for quality, stream in streams.items():
                    yield quality, stream
            else:
                # Unencrypted streams
                for quality, stream in streams.items():
                    yield quality, stream
                    
        except Exception as e:
            self.logger.error(f"Failed to get streams: {e}")
            return

__plugin__ = Stripchat