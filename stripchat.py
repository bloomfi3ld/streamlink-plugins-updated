import re
import requests
import base64
import hashlib
import itertools
import random
from requests.adapters import HTTPAdapter
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
    _pkey = None
    _mouflon_keys = {"Zeechoej4aleeshi": "ubahjae7goPoodi6"}
    _cached_keys = {}
    @classmethod
    def can_handle_url(cls, url):
        return cls._re_url.match(url) is not None
    
    @classmethod
    def _get_initial_data(cls):
        """Fetch static configuration and required JavaScript assets"""
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
        }

        r = requests.get('https://stripchat.com/api/front/v3/config/static', headers=headers)
        if r.status_code != 200:
            raise Exception("Failed to fetch static data from StripChat")
        cls._static_data = r.json().get('static')

        mmp_origin = cls._static_data['features']['MMPExternalSourceOrigin']
        mmp_version = cls._static_data['featuresV2']['playerModuleExternalLoading']['mmpVersion']
        mmp_base = f"{mmp_origin}/{mmp_version}"

        r = requests.get(f"{mmp_base}/main.js", headers=headers)
        if r.status_code != 200:
            raise Exception("Failed to fetch main.js from StripChat")
        cls._main_js_data = r.content.decode('utf-8')

        doppio_idx_match = re.findall('([0-9]+):"Doppio"', cls._main_js_data)
        if not doppio_idx_match:
            raise Exception("Failed to locate Doppio index in main.js")
        doppio_idx = doppio_idx_match[0]
        doppio_hash_match = re.findall(f'{doppio_idx}:\\"([a-zA-Z0-9]{{20}})\\"', cls._main_js_data)
        if not doppio_hash_match:
            raise Exception("Failed to locate Doppio chunk hash in main.js")
        doppio_hash = doppio_hash_match[0]

        r = requests.get(f"{mmp_base}/chunk-Doppio-{doppio_hash}.js", headers=headers)
        if r.status_code != 200:
            raise Exception("Failed to fetch doppio.js from StripChat")
        cls._doppio_js_data = r.content.decode('utf-8')
    
    @classmethod
    def _get_mouflon_from_m3u(cls, m3u8_doc):
        _start = 0
        _needle = '#EXT-X-MOUFLON:'
        while _needle in (doc := m3u8_doc[_start:]):
            mouflon_start = doc.find(_needle)
            if mouflon_start > 0:
                line_start = _start + mouflon_start
                line_end = m3u8_doc.find('\n', line_start)
                if line_end == -1:
                    line_end = len(m3u8_doc)
                parts = m3u8_doc[line_start:line_end].strip().split(':')
                if len(parts) >= 4:
                    psch = parts[2]
                    pkey = parts[3]
                    pdkey = cls._get_mouflon_dec_key(pkey)
                    if pdkey:
                        return psch, pkey, pdkey
            _start += mouflon_start + len(_needle)
        return None, None, None
    
    @classmethod
    def _get_mouflon_dec_key(cls, pkey):
        if pkey in cls._mouflon_keys:
            return cls._mouflon_keys[pkey]

        patterns = [
            f'"{re.escape(pkey)}:(.*?)"',
            f'{re.escape(pkey)}:"(.*?)"',
            f'"{re.escape(pkey)}":"(.*?)"',
            f'{re.escape(pkey)}:(\\w+)',
        ]
        for pat in patterns:
            keys = re.findall(pat, cls._doppio_js_data)
            if keys:
                cls._mouflon_keys[pkey] = keys[0]
                return keys[0]
        return None
    
    @classmethod
    def _decode_mouflon(cls, encrypted_b64, key):
        """Decode content encrypted with Mouflon"""
        if key not in cls._cached_keys:
            cls._cached_keys[key] = hashlib.sha256(key.encode("utf-8")).digest()
        hash_bytes = cls._cached_keys[key]

        encrypted_data = base64.b64decode(encrypted_b64 + "==")
        return bytes(a ^ b for (a, b) in zip(encrypted_data, itertools.cycle(hash_bytes))).decode("utf-8")
    
    @classmethod
    def _decode_m3u8(cls, content):
        _mouflon_file_attr = "#EXT-X-MOUFLON:FILE:"
        _mouflon_filename = "media.mp4"

        psch, pkey, pdkey = cls._get_mouflon_from_m3u(content)
        if not pkey or not pdkey:
            return content

        decoded_lines = []
        lines = content.splitlines()
        last_decoded_file = None

        for line in lines:
            if line.startswith(_mouflon_file_attr) and pdkey:
                # Decode the real segment filename
                last_decoded_file = cls._decode_mouflon(line[len(_mouflon_file_attr):], pdkey)
            elif line.endswith(_mouflon_filename) and last_decoded_file:
                # Replace the generic filename with the real one and reset state
                decoded_lines.append(line.replace(_mouflon_filename, last_decoded_file))
                last_decoded_file = None
            else:
                decoded_lines.append(line)
        return "\n".join(decoded_lines)

    @staticmethod
    def uniq(length=16):
        """Generate a random value to avoid API caching"""
        chars = ''.join(chr(i) for i in range(ord('a'), ord('z')+1))
        chars += ''.join(chr(i) for i in range(ord('0'), ord('9')+1))
        return ''.join(random.choice(chars) for _ in range(length))

    def _get_streams(self):
        # Initialize static data if needed
        if self._static_data is None:
            try:
                self._get_initial_data()
            except Exception as e:
                self.logger.error(f"Failed to initialize StripChat data: {e}")
                return
        
        username = self.match.group("username")
        api_call = f"https://stripchat.com/api/front/v2/models/username/{username}/cam?uniq={Stripchat.uniq()}"
        headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Encoding': 'gzip, deflate, br, zstd',
            'Accept-Language': 'en-US,en;q=0.9',
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

        # Verify stream availability
        if not (data["user"]["user"]["status"] == "public" and 
                data["cam"]["isCamAvailable"] and 
                data["cam"]["isCamActive"]):
            #self.logger.info(f"Stream not available. Status: {data['user']['user']['status']}")
            return

        stream_name = data["cam"]["streamName"]
        if not stream_name:
            self.logger.error("No stream name found")
            return

        # Build master playlist URL using random doppiocdn TLD and without static pkey
        host = 'doppiocdn.' + random.choice(['org', 'com', 'net'])
        master_url = f"https://edge-hls.{host}/hls/{stream_name}/master/{stream_name}_auto.m3u8"
        
        try:
            # Fetch the master playlist
            master_res = self.session.http.get(master_url, headers={'Referer': self.url})
            master_content = master_res.text
            
            psch, pkey, pdkey = self._get_mouflon_from_m3u(master_content)
            
            # Parse variant playlist
            streams = HLSStream.parse_variant_playlist(
                self.session, 
                master_url, 
                headers={'Referer': self.url}
            )
            
            if psch and pkey:
                class MouflonHTTPAdapter(HTTPAdapter):
                    def __init__(self, stripchat_instance, psch, pkey):
                        super().__init__()
                        self.stripchat = stripchat_instance
                        self.psch = psch
                        self.pkey = pkey

                    def send(self, request, **kwargs):
                        if 'doppiocdn.' in request.url and 'psch=' not in request.url:
                            separator = "&" if "?" in request.url else "?"
                            request.url = f"{request.url}{separator}psch={self.psch}&pkey={self.pkey}"
                        if 'doppiocdn.' in request.url:
                            request.headers.setdefault('Referer', self.stripchat.url)
                            request.headers.setdefault('Origin', 'https://stripchat.com')
                            request.headers.setdefault('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0')
                            request.headers.setdefault('Accept', 'application/x-mpegURL,application/vnd.apple.mpegurl;q=0.9,*/*;q=0.8')
                            request.headers.setdefault('Accept-Language', 'en-US,en;q=0.9')

                        response = super().send(request, **kwargs)

                        content_type = (response.headers.get('content-type', '') or '').lower()
                        is_m3u8 = (
                            content_type.startswith('application/vnd.apple.mpegurl')
                            or content_type.startswith('application/x-mpegurl')
                            or request.url.endswith('.m3u8')
                        )
                        if is_m3u8 and '#EXT-X-MOUFLON:' in response.text:
                            decoded_content = self.stripchat._decode_m3u8(response.text)
                            response._content = decoded_content.encode('utf-8')
                            if 'Content-Length' in response.headers:
                                response.headers['Content-Length'] = str(len(response._content))
                            return response

                        return response

                adapter = MouflonHTTPAdapter(self, psch, pkey)
                # Mount on various origins used by StripChat
                self.session.http.mount('https://edge-hls.doppiocdn.com/', adapter)
                self.session.http.mount('https://media-hls.doppiocdn.com/', adapter)
                self.session.http.mount('https://doppiocdn.com/', adapter)
                # Also mount TLD variants
                self.session.http.mount('https://edge-hls.doppiocdn.org/', adapter)
                self.session.http.mount('https://edge-hls.doppiocdn.net/', adapter)
                self.session.http.mount('https://media-hls.doppiocdn.org/', adapter)
                self.session.http.mount('https://media-hls.doppiocdn.net/', adapter)
                
                # Create regular streams — the HTTP adapter will handle decoding
                for quality, stream in streams.items():
                    yield quality, stream
            else:
                # Streams without encryption
                for quality, stream in streams.items():
                    yield quality, stream
                    
        except Exception as e:
            self.logger.error(f"Failed to get streams: {e}")
            return

__plugin__ = Stripchat
