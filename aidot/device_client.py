# device_client.py for python-aidot

"""The aidot integration."""

import ctypes
import json
import logging
import random
import socket
import struct
import time
import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, List, Optional

from .exceptions import AidotNotLogin
from .aes_utils import aes_encrypt, aes_decrypt
from .const import (
CONF_AES_KEY,
CONF_ASCNUMBER,
CONF_ATTR,
CONF_CCT,
CONF_HARDWARE_VERSION,
CONF_ID,
CONF_IDENTITY,
CONF_MAC,
CONF_MAXVALUE,
CONF_MINVALUE,
CONF_MODEL_ID,
CONF_NAME,
CONF_ON_OFF,
CONF_DIMMING,
CONF_PASSWORD,
CONF_PAYLOAD,
CONF_PRODUCT,
CONF_PROPERTIES,
CONF_RGBW,
CONF_SERVICE_MODULES,
CONF_ACK,
CONF_CODE,
Identity,
)

_LOGGER = logging.getLogger(**name**)

# ── Camera / Leedarson smarthome API constants ────────────────────────────────

# AppKey from LDSAppOpenSDK CocoaPods docs (kLDSAppOpenSDKKey = "appa070")

_LEEDARSON_APP_KEY = "appa070"

# Camera-specific backend.  Region prefix mirrors AidotClient._base_url pattern.

# e.g. "us" → "https://us-smarthome.arnoo.com:443"

_SMARTHOME_URL_TEMPLATE = "https://{region}-smarthome.arnoo.com:443"

# ── Playback TCP binary framing constants ─────────────────────────────────────

# 

# Wire layout (all big-endian) -- derived from RecordVideoEncoder.java and

# verified against INettyClientInitializer.java Netty decoder parameters:

# lengthFieldOffset=14, lengthFieldLength=4, lengthAdjustment=19

# 

# version(H2) seq(i4) cmd(H2) subcmd(H2) cmdParam(i4)   ← 14 bytes before payloadLen

# payloadLen(i4)                                          ← at offset 14, 4 bytes

# timestamp(q8) context(i4) encodeType(b1) result(h2) reserve(i4)  ← 19-byte suffix

# <payload bytes>

# Total header = 37 bytes

# Full header pack format (big-endian)

_HDR_FMT         = ">HiHHiiqibhi"
_HDR_SIZE        = struct.calcsize(_HDR_FMT)          # 37

# First 18 bytes: all fields up to and including payloadLen

_HDR_PREFIX_FMT  = ">HiHHii"
_HDR_PREFIX_SIZE = struct.calcsize(_HDR_PREFIX_FMT)   # 18

# Next 19 bytes: suffix after payloadLen, before payload data

_HDR_SUFFIX_FMT  = ">qibhi"
_HDR_SUFFIX_SIZE = struct.calcsize(_HDR_SUFFIX_FMT)   # 19

assert _HDR_SIZE        == 37, _HDR_SIZE
assert _HDR_PREFIX_SIZE == 18, _HDR_PREFIX_SIZE
assert _HDR_SUFFIX_SIZE == 19, _HDR_SUFFIX_SIZE

# Fixed header field values used in all outbound request frames

_HDR_VERSION  = 256   # 0x0100
_HDR_CONTEXT  = 1005
_HDR_ENC_TYPE = 1
_HDR_RESULT   = 4     # ignored by server in requests
_HDR_RESERVE  = 2

# TCP command codes -- from AppCmd.java

_CMD_LOGIN_REQ  = 0x0101   # open task channel / authenticate
_CMD_LOGIN_RES  = 0x0102
_CMD_HB_REQ     = 0x0105   # heartbeat ping
_CMD_HB_RES     = 0x0106
_CMD_STREAM_REQ = 0x0107   # request next frame batch
_CMD_STREAM_RES = 0x0108
_CMD_SUBCMD     = 0x0001
_CMD_PARAM      = 0x00000002

# Video sub-frame header size -- from LDSPlayer.decodeStream()

# padding(2) + frameType(1) + audioCodec(1) + timestamp(8) + encType(1) + payloadLen(4)

_SF_HDR_SIZE = 17

# ── Video frame types (from LDSPlayer.decodeStream) ──────────────────────────

_FRAME_TYPE_P_FRAME  = 2
_FRAME_TYPE_B_FRAME  = 3
_FRAME_TYPE_I_FRAME  = 4   # keyframe
_FRAME_TYPE_AUDIO    = 5

# Audio codec byte values (when frame_type == 5)

_AUDIO_CODEC_G711A   = 1

# ─────────────────────────────────────────────────────────────────────────────

# Existing device-state classes (unchanged)

# ─────────────────────────────────────────────────────────────────────────────

class DeviceStatusData:
online: bool = False
on: bool = False
rgdb: int = None
rgbw: tuple[int, int, int, int] = None
cct: int = None
dimming: int = None

```
def update(self, attr: dict[str, Any]) -> None:
    if attr is None:
        return
    if attr.get(CONF_ON_OFF) is not None:
        self.on = attr.get(CONF_ON_OFF)
    if attr.get(CONF_DIMMING) is not None:
        self.dimming = int(attr.get(CONF_DIMMING) * 255 / 100)
    if attr.get(CONF_RGBW) is not None:
        self.rgdb = attr.get(CONF_RGBW)
        rgbw = ctypes.c_uint32(self.rgdb).value
        r = (rgbw >> 24) & 0xFF
        g = (rgbw >> 16) & 0xFF
        b = (rgbw >> 8) & 0xFF
        w = rgbw & 0xFF
        self.rgbw = (r, g, b, w)
    if attr.get(CONF_CCT) is not None:
        self.cct = attr.get(CONF_CCT)
```

class DeviceInformation:
enable_rgbw: bool = False
enable_dimming: bool = True
enable_cct: bool = False
cct_min: int
cct_max: int
dev_id: str
mac: str
model_id: str
name: str
hw_version: str

```
def __init__(self, device: dict[str, Any]) -> None:
    self.dev_id = device.get(CONF_ID)
    self.mac = device.get(CONF_MAC) if device.get(CONF_MAC) is not None else ""
    self.model_id = device.get(CONF_MODEL_ID)
    self.name = device.get(CONF_NAME)
    self.hw_version = device.get(CONF_HARDWARE_VERSION)
    if CONF_PRODUCT in device and CONF_SERVICE_MODULES in device[CONF_PRODUCT]:
        for service in device[CONF_PRODUCT][CONF_SERVICE_MODULES]:
            if service[CONF_IDENTITY] == Identity.RGBW:
                self.enable_rgbw = True
                self.enable_cct = True
            elif service[CONF_IDENTITY] == Identity.CCT:
                self.cct_min = int(service[CONF_PROPERTIES][0][CONF_MINVALUE])
                self.cct_max = int(service[CONF_PROPERTIES][0][CONF_MAXVALUE])
                self.enable_cct = True
```

# ─────────────────────────────────────────────────────────────────────────────

# Camera data types

# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VideoFrame:
"""One decoded video or audio sub-frame from a cloud-playback stream.

```
Attributes:
    frame_type:   2=P-frame, 3=B-frame, 4=I-frame (keyframe), 5=audio.
    audio_codec:  0=N/A, 1=G.711A  (only meaningful when frame_type==5).
    timestamp:    Server-side PTS in milliseconds (big-endian int64).
    is_encrypted: True if the sub-frame encryption byte was non-zero.
                  The ``data`` field will be empty in that case.
    data:         Raw H.264 NAL bytes (video) or G.711A bytes (audio).
"""

frame_type:   int
audio_codec:  int
timestamp:    int
is_encrypted: bool
data:         bytes

@property
def is_video(self) -> bool:
    """True for I/P/B video frames."""
    return self.frame_type in (_FRAME_TYPE_P_FRAME,
                               _FRAME_TYPE_B_FRAME,
                               _FRAME_TYPE_I_FRAME)

@property
def is_keyframe(self) -> bool:
    """True for I-frames; a decoder can cleanly sync on these."""
    return self.frame_type == _FRAME_TYPE_I_FRAME

@property
def is_audio(self) -> bool:
    """True for G.711A audio frames."""
    return self.frame_type == _FRAME_TYPE_AUDIO
```

# ─────────────────────────────────────────────────────────────────────────────

# TCP binary framing helpers

# ─────────────────────────────────────────────────────────────────────────────

def _pack_frame(cmd: int, payload: bytes, sequence: Optional[int] = None) -> bytes:
"""Build one outbound wire frame for the Leedarson playback TCP protocol.

```
Args:
    cmd:      One of the _CMD_* constants.
    payload:  UTF-8 JSON body bytes.
    sequence: Sequence number; random signed 32-bit int if omitted.

Returns:
    37-byte header followed by payload, ready to write to the socket.
"""
if sequence is None:
    sequence = random.randint(-(2 ** 31), 2 ** 31 - 1)
ts = int(time.time() * 1000)
header = struct.pack(
    _HDR_FMT,
    _HDR_VERSION,
    sequence,
    cmd,
    _CMD_SUBCMD,
    _CMD_PARAM,
    len(payload),
    ts,
    _HDR_CONTEXT,
    _HDR_ENC_TYPE,
    _HDR_RESULT,
    _HDR_RESERVE,
)
return header + payload
```

async def _read_frame(reader: asyncio.StreamReader) -> tuple[dict, bytes]:
"""Read one complete framed response from the playback TCP server.

```
Mirrors the Netty LengthFieldBasedFrameDecoder logic:
  - Read first 18 bytes (prefix + payloadLen field)
  - Read next 19 + payloadLen bytes (suffix + payload data)

Returns:
    (header_dict, payload_bytes) where header_dict has keys
    ``cmd``, ``seq``, ``result``, ``timestamp``.

Raises:
    asyncio.IncompleteReadError: connection closed mid-frame.
    OSError: underlying socket error.
"""
# Read version…cmdParam + payloadLen (18 bytes total)
prefix_raw = await reader.readexactly(_HDR_PREFIX_SIZE)
_version, seq, cmd, _subcmd, _cmd_param, payload_len = struct.unpack(
    _HDR_PREFIX_FMT, prefix_raw
)

# Guard against obviously corrupt frames before allocating memory
if payload_len < 0 or payload_len > 4 * 1024 * 1024:
    raise ValueError(f"Implausible payloadLen={payload_len} in TCP frame")

# Read timestamp…reserve (19 bytes) + payload
rest = await reader.readexactly(_HDR_SUFFIX_SIZE + payload_len)
timestamp, _context, _enc_type, result, _reserve = struct.unpack(
    _HDR_SUFFIX_FMT, rest[:_HDR_SUFFIX_SIZE]
)
payload = rest[_HDR_SUFFIX_SIZE:]

return (
    {"cmd": cmd, "seq": seq, "result": result, "timestamp": timestamp},
    payload,
)
```

def _parse_video_payload(data: bytes) -> List[VideoFrame]:
"""Parse a STREAM_RES TCP payload into a list of VideoFrame objects.

```
Sub-frame wire layout (17-byte header, all big-endian):
  padding(2) | frameType(1) | audioCodec(1) | timestamp(8)
  | encType(1) | payloadLen(4) | <payloadLen bytes>

Source: LDSPlayer.decodeStream() in the Leedarson Android SDK.
"""
frames: List[VideoFrame] = []
offset = 0

while len(data) - offset >= _SF_HDR_SIZE:
    frame_type  = data[offset + 2]
    audio_codec = data[offset + 3]
    # timestamp is a signed big-endian 64-bit int at offset+4
    (timestamp,) = struct.unpack_from(">q", data, offset + 4)
    enc_type     = data[offset + 12]
    (payload_len,) = struct.unpack_from(">i", data, offset + 13)

    if payload_len < 0:
        break   # corrupt frame

    end = offset + _SF_HDR_SIZE + payload_len
    if end > len(data):
        break   # truncated

    if enc_type != 0:
        # Encrypted -- payload is unreadable; surface the frame so
        # callers know data was received but skipped.
        frames.append(VideoFrame(frame_type, audio_codec, timestamp, True, b""))
    else:
        frames.append(VideoFrame(
            frame_type,
            audio_codec,
            timestamp,
            False,
            data[offset + _SF_HDR_SIZE: end],
        ))

    offset = end

return frames
```

# ─────────────────────────────────────────────────────────────────────────────

# MQTT helper -- playback server discovery

# ─────────────────────────────────────────────────────────────────────────────

async def _mqtt_get_playback_server_info(
mqtt_url: str,
user_id: str,
mqtt_password: str,
dev_id: str,
client_id: str,
timeout: float = 15.0,
) -> Optional[dict]:
"""Send a Leedarson MQTT `getPlaybackServerInfoReq` and return the payload.

```
The Leedarson cloud uses MQTT-over-WebSocket (WSS).  We connect with
paho-mqtt, publish the request on the server topic, subscribe to our
client topic, and return the first matching response.

Args:
    mqtt_url:      Full WSS URL from ``/commonController/getServerUrlConfig``,
                   e.g. ``"wss://mqtt.arnoo.com:443/mqtt"``.
    user_id:       User account ID (``login_info["id"]``).
    mqtt_password: MQTT password from login response (``mqqtPwd`` / ``mqttPwd``).
    dev_id:        Target camera device ID.
    client_id:     MQTT client identifier, conventionally ``"app-{user_id}"``.
    timeout:       Seconds to wait for a matching response.

Returns:
    The ``payload`` dict from the MQTT response, e.g.::

        {"serverIP": "1.2.3.4", "serverPort": 9000, "heartbeat": 15}

    or ``None`` if the request timed out or the broker was unreachable.

Requires:
    ``paho-mqtt``  (``pip install paho-mqtt``)
"""
try:
    import paho.mqtt.client as mqtt  # type: ignore[import]
except ImportError as exc:
    raise ImportError(
        "paho-mqtt is required for cloud playback. "
        "Install it with:  pip install paho-mqtt"
    ) from exc

import ssl
import threading
import urllib.parse

seq       = str(random.randint(100_000, 999_999))
pub_topic = f"iot/v1/s/{user_id}/IPCAM/getPlaybackServerInfoReq"
sub_topic = f"iot/v1/c/{user_id}/#"

request_body = json.dumps({
    "service": "IPCAM",
    "method":  "getPlaybackServerInfoReq",
    "seq":     seq,
    "srcAddr": f"0.{user_id}",
    "payload": {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "deviceId":  dev_id,
        "clientId":  client_id,
    },
})

result_event: threading.Event = threading.Event()
result_box: List[Optional[dict]] = [None]

parsed    = urllib.parse.urlparse(mqtt_url)
host      = parsed.hostname or mqtt_url
port      = parsed.port or (443 if parsed.scheme in ("wss", "mqtts") else 1883)
path      = parsed.path or "/mqtt"
use_tls   = parsed.scheme in ("wss", "mqtts")
transport = "websockets" if parsed.scheme in ("wss", "ws") else "tcp"

def on_connect(client: "mqtt.Client", userdata, flags, rc: int) -> None:
    if rc != 0:
        _LOGGER.warning("MQTT broker rejected connection rc=%d", rc)
        result_event.set()
        return
    client.subscribe(sub_topic, qos=1)
    client.publish(pub_topic, request_body, qos=1)

def on_message(client: "mqtt.Client", userdata, msg: "mqtt.MQTTMessage") -> None:
    try:
        body = json.loads(msg.payload.decode("utf-8"))
        if str(body.get("seq")) == seq:
            pld = body.get("payload")
            if pld and pld.get("serverIP"):
                result_box[0] = pld
                result_event.set()
    except Exception:
        pass

def _run_mqtt() -> None:
    mqttc = mqtt.Client(client_id=client_id, transport=transport)
    if use_tls:
        mqttc.tls_set(cert_reqs=ssl.CERT_REQUIRED)
    if transport == "websockets":
        mqttc.ws_set_options(path=path)
    mqttc.username_pw_set(user_id, mqtt_password)
    mqttc.on_connect = on_connect
    mqttc.on_message = on_message
    try:
        mqttc.connect(host, port, keepalive=30)
        mqttc.loop_start()
        result_event.wait(timeout=timeout)
    finally:
        mqttc.loop_stop()
        try:
            mqttc.disconnect()
        except Exception:
            pass

await asyncio.get_event_loop().run_in_executor(None, _run_mqtt)
return result_box[0]
```

# ─────────────────────────────────────────────────────────────────────────────

# CloudPlaybackSession

# ─────────────────────────────────────────────────────────────────────────────

class CloudPlaybackSession:
"""Manages a single cloud-playback TCP session for a Leedarson/AiDot camera.

```
Do not instantiate directly; use
:meth:`DeviceClient.async_open_cloud_playback` instead, which performs the
full three-step handshake and returns a running session.

The session:
    - Connects to the Leedarson TCP playback server.
    - Authenticates with a ``taskId`` from the cloud REST API.
    - Requests frame batches and calls *on_frame* for each decoded sub-frame.
    - Sends heartbeats to prevent server-side timeout.
    - Supports :meth:`pause`, :meth:`resume`, and :meth:`stop`.
"""

def __init__(
    self,
    server_ip: str,
    server_port: int,
    heartbeat_interval: int,
    task_id: int,
    client_id: str,
    start_ts_s: int,
    on_frame: Callable[[VideoFrame], None],
) -> None:
    self._server_ip   = server_ip
    self._server_port = server_port
    self._hb_interval = heartbeat_interval
    self._task_id     = task_id
    self._client_id   = client_id
    self._start_ts    = start_ts_s   # in seconds (converted from ms by caller)
    self._on_frame    = on_frame

    self._reader: Optional[asyncio.StreamReader] = None
    self._writer: Optional[asyncio.StreamWriter] = None
    self._running  = False
    self._paused   = False
    self._hb_task: Optional[asyncio.Task] = None
    self._rx_task: Optional[asyncio.Task] = None

# ── Internal ──────────────────────────────────────────────────────────────

async def _connect_and_login(self) -> bool:
    """Open TCP connection and perform the login handshake.

    Sends LOGIN_REQ (cmd=0x0101) with JSON body::

        {"clientId": <userId>, "heartbeat": <hb>, "taskId": <taskId>}

    Returns True if the server responds with code 200.
    """
    try:
        self._reader, self._writer = await asyncio.open_connection(
            self._server_ip, self._server_port
        )
    except OSError as exc:
        _LOGGER.error(
            "Cloud playback: TCP connect to %s:%d failed: %s",
            self._server_ip, self._server_port, exc,
        )
        return False

    login_body = json.dumps({
        "clientId":  self._client_id,
        "heartbeat": self._hb_interval,
        "taskId":    self._task_id,
    }).encode("utf-8")

    seq = random.randint(-(2 ** 31), 2 ** 31 - 1)
    self._writer.write(_pack_frame(_CMD_LOGIN_REQ, login_body, seq))
    await self._writer.drain()

    try:
        hdr, resp_payload = await asyncio.wait_for(
            _read_frame(self._reader), timeout=10.0
        )
    except asyncio.TimeoutError:
        _LOGGER.error("Cloud playback: login response timed out")
        return False
    except Exception as exc:
        _LOGGER.error("Cloud playback: login read error: %s", exc)
        return False

    if hdr["cmd"] != _CMD_LOGIN_RES:
        _LOGGER.error(
            "Cloud playback: unexpected login response cmd=0x%04x", hdr["cmd"]
        )
        return False

    try:
        body_obj = json.loads(resp_payload)
        if body_obj.get("code") != 200:
            _LOGGER.error(
                "Cloud playback: login rejected (code=%s body=%s)",
                body_obj.get("code"), body_obj,
            )
            return False
    except (json.JSONDecodeError, ValueError):
        # Some firmware revisions send no JSON body -- treat as success
        pass

    _LOGGER.debug(
        "Cloud playback: login OK (task=%d server=%s:%d)",
        self._task_id, self._server_ip, self._server_port,
    )
    return True

async def _request_stream_batch(self) -> None:
    """Send STREAM_REQ (cmd=0x0107) to fetch the next batch of frames.

    JSON body::

        {"begin": <unix_seconds>, "type": 1, "framenums": 10, "speed": 1}
    """
    if self._writer is None:
        return
    body = json.dumps({
        "begin":     self._start_ts,
        "type":      1,
        "framenums": 10,
        "speed":     1,
    }).encode("utf-8")
    self._writer.write(_pack_frame(_CMD_STREAM_REQ, body))
    await self._writer.drain()

async def _heartbeat_loop(self) -> None:
    """Send HB_REQ (cmd=0x0105) every *heartbeat_interval* seconds."""
    while self._running:
        await asyncio.sleep(self._hb_interval)
        if not self._running or self._writer is None:
            break
        try:
            self._writer.write(_pack_frame(_CMD_HB_REQ, b"{}"))
            await self._writer.drain()
        except Exception as exc:
            _LOGGER.warning("Cloud playback: heartbeat write failed: %s", exc)
            break

async def _receive_loop(self) -> None:
    """Receive STREAM_RES frames and dispatch decoded sub-frames to on_frame.

    A result code of 200 means data is present; -15528 (0xFFFFC3F8) signals
    end-of-stream per the Leedarson SDK (LDSOpenSDK.java receiveDataTask).
    """
    while self._running:
        if self._paused:
            await asyncio.sleep(0.2)
            continue

        try:
            hdr, payload = await asyncio.wait_for(
                _read_frame(self._reader),  # type: ignore[arg-type]
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            _LOGGER.warning("Cloud playback: receive timeout -- server may have dropped connection")
            break
        except asyncio.IncompleteReadError:
            if self._running:
                _LOGGER.info("Cloud playback: server closed TCP connection")
            break
        except Exception as exc:
            if self._running:
                _LOGGER.warning("Cloud playback: receive error: %s", exc)
            break

        if hdr["cmd"] == _CMD_HB_RES:
            continue   # heartbeat ACK -- nothing to do

        if hdr["cmd"] != _CMD_STREAM_RES:
            _LOGGER.debug(
                "Cloud playback: ignoring unexpected cmd=0x%04x", hdr["cmd"]
            )
            continue

        result = hdr["result"]

        if result == 200:
            for frame in _parse_video_payload(payload):
                try:
                    self._on_frame(frame)
                except Exception:
                    _LOGGER.exception("Cloud playback: exception in on_frame callback")
            if self._running and not self._paused:
                await self._request_stream_batch()

        elif result == -15528:
            # End of recorded stream (Leedarson magic sentinel)
            _LOGGER.info("Cloud playback: end of stream reached")
            break

        else:
            _LOGGER.warning("Cloud playback: unexpected stream result=%d", result)

# ── Public API ────────────────────────────────────────────────────────────

async def start(self) -> bool:
    """Connect, authenticate, and begin streaming.

    Returns:
        True if the TCP login handshake succeeded and streaming has begun.
    """
    self._running = True

    if not await self._connect_and_login():
        self._running = False
        return False

    await self._request_stream_batch()

    self._hb_task = asyncio.create_task(
        self._heartbeat_loop(), name="aidot-cloud-hb"
    )
    self._rx_task = asyncio.create_task(
        self._receive_loop(), name="aidot-cloud-rx"
    )
    return True

async def pause(self) -> None:
    """Suspend frame delivery without closing the TCP connection."""
    self._paused = True

async def resume(self) -> None:
    """Resume frame delivery after :meth:`pause`.

    Re-sends a STREAM_REQ so the server resumes sending data.
    """
    self._paused = False
    if self._running and self._writer is not None:
        await self._request_stream_batch()

async def stop(self) -> None:
    """Stop playback and close the TCP connection.

    Safe to call multiple times or before :meth:`start` has been called.
    """
    self._running = False
    self._paused  = False

    for task in (self._hb_task, self._rx_task):
        if task and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    self._hb_task = None
    self._rx_task = None

    if self._writer is not None:
        try:
            self._writer.close()
            await self._writer.wait_closed()
        except Exception:
            pass
        self._writer = None
        self._reader = None
```

# ─────────────────────────────────────────────────────────────────────────────

# DeviceClient

# ─────────────────────────────────────────────────────────────────────────────

class DeviceClient(object):
status: DeviceStatusData
info: DeviceInformation
_login_uuid = 0
_connect_and_login: bool = False
_connecting: bool = False
_simpleVersion: str = ""
_ip_address: str = None
device_id: str
_is_close: bool = False
_status_fresh_cb: Any = None

```
@property
def connect_and_login(self) -> bool:
    return self._connect_and_login

@property
def connecting(self) -> bool:
    return self._connecting

def __init__(self, device: dict[str, Any], user_info: dict[str, Any]) -> None:
    self.ping_count = 0
    self.status = DeviceStatusData()
    self.info = DeviceInformation(device)
    self.user_id = user_info.get(CONF_ID)

    # Store full user_info for camera API calls (access token, region, etc.)
    self._user_info: dict[str, Any] = user_info

    # Derive the smarthome API base URL from the user's region.
    # Region is stored by AidotClient as login_info["region"] (e.g. "us").
    self._region: str = user_info.get("region", "us")

    # Cache slot for the MQTT broker URL (fetched lazily on first playback)
    self._mqtt_url: Optional[str] = None

    if CONF_AES_KEY in device:
        key_string = device[CONF_AES_KEY][0]
        if key_string is not None:
            self.aes_key = bytearray(16)
            key_bytes = key_string.encode()
            self.aes_key[: len(key_bytes)] = key_bytes

    self.password = device.get(CONF_PASSWORD)
    self.device_id = device.get(CONF_ID)
    self._simpleVersion = device.get("simpleVersion")

# ── Camera helpers ────────────────────────────────────────────────────────

@property
def _smarthome_base(self) -> str:
    """Base URL for Leedarson camera/smarthome API endpoints."""
    return _SMARTHOME_URL_TEMPLATE.format(region=self._region)

def _leedarson_headers(self) -> dict:
    """HTTP headers required by the Leedarson smarthome API.

    Mirrors the header construction in LDSOpenSDK.java::

        {"terminal": "thirdPlatFormUser", "active-language": "zh_CN",
         "access-token": <token>, "token": <token>, "appKey": <appKey>}
    """
    token = (
        self._user_info.get("accessToken")
        or self._user_info.get("access_token")
        or ""
    )
    return {
        "terminal":        "thirdPlatFormUser",
        "active-language": "zh_CN",
        "access-token":    token,
        "token":           token,
        "appKey":          _LEEDARSON_APP_KEY,
        "Content-Type":    "application/json",
    }

async def _async_get_mqtt_url(self) -> Optional[str]:
    """Return the WSS MQTT broker URL, fetching and caching it if needed.

    Calls GET ``/commonController/getServerUrlConfig`` on the smarthome API
    and prepends ``"wss://"`` to the returned ``mqttServerUrl`` value.

    Source: LDSOpenSDK.getServerConfig() in the Leedarson Android SDK.
    """
    if self._mqtt_url:
        return self._mqtt_url

    import aiohttp

    url = f"{self._smarthome_base}/commonController/getServerUrlConfig"
    # Strip Content-Type from GET request headers
    headers = {
        k: v for k, v in self._leedarson_headers().items()
        if k != "Content-Type"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=headers,
                params={"version": "1.0.1", "clientId": f"app-{self.user_id}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                body = await resp.json(content_type=None)

        mqtt_host = (body.get("data") or {}).get("mqttServerUrl") or ""
        if not mqtt_host:
            _LOGGER.error("getServerUrlConfig returned no mqttServerUrl: %s", body)
            return None

        self._mqtt_url = (
            mqtt_host
            if mqtt_host.startswith(("wss://", "ws://"))
            else f"wss://{mqtt_host}"
        )
        _LOGGER.debug("MQTT URL cached: %s", self._mqtt_url)
        return self._mqtt_url

    except Exception as exc:
        _LOGGER.error("_async_get_mqtt_url failed: %s", exc)
        return None

# ── Camera public methods ─────────────────────────────────────────────────

async def async_get_p2p_uid(self) -> Optional[str]:
    """Fetch the TUTK P2P UID for this camera from the AiDot cloud.

    The returned UID is passed directly to ``TutkSession`` (in ``tutk.py``)
    to establish a live P2P stream.

    Calls::

        POST /deviceController/getP2pId
        Form body: deviceId=<device_id>

    Returns:
        A UID string such as ``"ABCD-123456-XXXXX"`` on success, or
        ``None`` if the request fails or returns an empty value.
    """
    import aiohttp

    headers = {
        k: v for k, v in self._leedarson_headers().items()
        if k != "Content-Type"
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._smarthome_base}/deviceController/getP2pId",
                data={"deviceId": self.device_id},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                body = await resp.json(content_type=None)

        uid = body.get("data") or body.get("uid")
        if uid:
            return str(uid)

        _LOGGER.warning(
            "async_get_p2p_uid: empty UID in response for %s: %s",
            self.device_id, body,
        )
    except Exception as exc:
        _LOGGER.error("async_get_p2p_uid failed for %s: %s", self.device_id, exc)

    return None

async def async_get_cloud_recordings(
    self,
    start_ts: int,
    end_ts: int,
    *,
    page: int = 1,
    page_size: int = 100,
) -> List[dict]:
    """List cloud-recorded time slots for this camera device.

    Calls::

        POST /api/ipc/playbackController/getRecordTimeSlot

    Args:
        start_ts:  Query window start, Unix timestamp in **milliseconds**.
        end_ts:    Query window end, Unix timestamp in **milliseconds**.
        page:      1-based result page (default 1).
        page_size: Results per page, max 100 (default 100).

    Returns:
        A list of dicts with keys ``"sta"`` and ``"end"`` (both in
        milliseconds), or an empty list on error / no recordings.

    Example::

        recordings = await device_client.async_get_cloud_recordings(
            start_ts=1_700_000_000_000,
            end_ts=1_700_086_400_000,
        )
        for r in recordings:
            print(r["sta"], "→", r["end"])
    """
    import aiohttp

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._smarthome_base}"
                "/api/ipc/playbackController/getRecordTimeSlot",
                json={
                    "deviceId":      self.device_id,
                    "recordStaTime": start_ts,
                    "recordEndTime": end_ts,
                    "pageNum":       page,
                    "pageSize":      page_size,
                    "timeout":       20_000,
                },
                headers=self._leedarson_headers(),
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                body = await resp.json(content_type=None)

        if body.get("code") != 200:
            _LOGGER.warning(
                "getRecordTimeSlot returned code=%s for %s",
                body.get("code"), self.device_id,
            )
            return []

        items = (body.get("data") or {}).get("list") or []
        return [{"sta": int(it["sta"]), "end": int(it["end"])} for it in items]

    except Exception as exc:
        _LOGGER.error(
            "async_get_cloud_recordings failed for %s: %s",
            self.device_id, exc,
        )
        return []

async def async_open_cloud_playback(
    self,
    start_ts: int,
    end_ts: int,
    on_frame: Callable[[VideoFrame], None],
) -> Optional[CloudPlaybackSession]:
    """Open a cloud-playback session and begin streaming video frames.

    Performs the full three-step Leedarson cloud-playback handshake
    derived from ``LDSOpenSDK.playCloudRecord()`` in the Android SDK:

    **Step 1 -- MQTT** ``getPlaybackServerInfoReq``
        Sends a request to the camera via the Leedarson MQTT broker
        (WSS) and receives the TCP playback server address
        (``serverIP``, ``serverPort``, ``heartbeat``).

    **Step 2 -- HTTPS** ``POST /api/ipc/playbackController/playRecord``
        Registers the playback request with the cloud REST API and
        obtains a ``taskId`` that authorises the TCP session.

    **Step 3 -- TCP** binary framing
        Connects to the playback server, logs in with the ``taskId``,
        and begins requesting and delivering frames.

    Requires ``paho-mqtt`` (``pip install paho-mqtt``) for Step 1.

    Args:
        start_ts:  Start position, Unix timestamp in **milliseconds**.
        end_ts:    End of clip, Unix timestamp in **milliseconds**.
        on_frame:  Callback invoked (in the asyncio event loop) for each
                   :class:`VideoFrame`.  Must not block the event loop;
                   use ``asyncio.get_event_loop().run_in_executor(…)``
                   for any CPU-intensive decoding work.

    Returns:
        A running :class:`CloudPlaybackSession`, or ``None`` if any
        step of the handshake fails.

    Example::

        def handle_frame(frame: VideoFrame) -> None:
            if frame.is_keyframe:
                print("keyframe", len(frame.data), "bytes")

        session = await device_client.async_open_cloud_playback(
            start_ts=1_700_000_000_000,
            end_ts=1_700_003_600_000,
            on_frame=handle_frame,
        )
        if session:
            await asyncio.sleep(60)
            await session.stop()
    """
    import aiohttp

    # MQTT password -- the Leedarson SDK stores it as "mqqtPwd" (typo in SDK)
    mqtt_pwd = (
        self._user_info.get("mqqtPwd")
        or self._user_info.get("mqttPwd")
        or self._user_info.get("mqtt_pwd")
        or ""
    )
    client_id = f"app-{self.user_id}"

    # ── Step 1: MQTT → playback TCP server coordinates ────────────────────
    mqtt_url = await self._async_get_mqtt_url()
    if not mqtt_url:
        _LOGGER.error(
            "async_open_cloud_playback: cannot determine MQTT URL for %s",
            self.device_id,
        )
        return None

    _LOGGER.debug(
        "Cloud playback step 1: MQTT getPlaybackServerInfoReq for %s",
        self.device_id,
    )
    srv_info = await _mqtt_get_playback_server_info(
        mqtt_url,
        str(self.user_id),
        mqtt_pwd,
        self.device_id,
        client_id,
    )
    if not srv_info:
        _LOGGER.error(
            "async_open_cloud_playback: MQTT response empty for %s -- "
            "check that the camera is online and MQTT credentials are correct",
            self.device_id,
        )
        return None

    server_ip   = srv_info.get("serverIP")
    server_port = srv_info.get("serverPort")
    heartbeat   = int(srv_info.get("heartbeat") or 15)

    if not server_ip or not server_port:
        _LOGGER.error(
            "async_open_cloud_playback: incomplete server info for %s: %s",
            self.device_id, srv_info,
        )
        return None

    # ── Step 2: HTTP → task ID ────────────────────────────────────────────
    _LOGGER.debug(
        "Cloud playback step 2: playRecord HTTP request for %s", self.device_id
    )
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self._smarthome_base}"
                "/api/ipc/playbackController/playRecord",
                json={
                    "deviceId":      self.device_id,
                    "recordStaTime": start_ts,
                    "recordEndTime": end_ts,
                },
                headers=self._leedarson_headers(),
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                play_body = await resp.json(content_type=None)

        if play_body.get("code") != 200:
            _LOGGER.error(
                "playRecord returned code=%s for %s: %s",
                play_body.get("code"), self.device_id, play_body,
            )
            return None

        task_id = (play_body.get("data") or {}).get("taskId")
        if task_id is None:
            _LOGGER.error(
                "playRecord: no taskId in response for %s: %s",
                self.device_id, play_body,
            )
            return None

    except Exception as exc:
        _LOGGER.error(
            "async_open_cloud_playback: playRecord request failed for %s: %s",
            self.device_id, exc,
        )
        return None

    # ── Step 3: TCP → connect, login, stream ──────────────────────────────
    _LOGGER.debug(
        "Cloud playback step 3: TCP to %s:%d (task=%d heartbeat=%ds)",
        server_ip, server_port, task_id, heartbeat,
    )
    pb_session = CloudPlaybackSession(
        server_ip=server_ip,
        server_port=int(server_port),
        heartbeat_interval=heartbeat,
        task_id=int(task_id),
        client_id=str(self.user_id),   # server expects raw userId, not "app-" prefix
        start_ts_s=start_ts // 1000,
        on_frame=on_frame,
    )
    if not await pb_session.start():
        return None

    _LOGGER.info(
        "Cloud playback session open for %s (task=%d start=%d)",
        self.device_id, task_id, start_ts // 1000,
    )
    return pb_session

# ── Existing methods (unchanged) ──────────────────────────────────────────

async def connect(self, ip_address) -> None:
    _LOGGER.info(f"connect device : {ip_address}")
    self.reader = self.writer = None
    self._connecting = True
    try:
        self.reader, self.writer = await asyncio.open_connection(ip_address, 10000)
        sock: socket.socket = self.writer.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.seq_num = 1
        await self.login()
        self._connect_and_login = True
    except Exception as e:
        self._connect_and_login = False
    finally:
        self._connecting = False

def update_ip_address(self, ip: str) -> None:
    if ip is None:
        return
    self._ip_address = ip
    if self._connecting is not True and self._connect_and_login is not True:
        asyncio.get_running_loop().create_task(self.async_login())

async def async_login(self) -> None:
    if self._ip_address is None:
        return
    if self._connecting is not True and self._connect_and_login is not True:
        await self.connect(self._ip_address)

def get_send_packet(self, message, msgtype):
    magic = struct.pack(">H", 0x1EED)
    _msgtype = struct.pack(">h", msgtype)

    if self.aes_key is not None:
        send_data = aes_encrypt(message, self.aes_key)
    else:
        send_data = message

    bodysize = struct.pack(">i", len(send_data))
    packet = magic + _msgtype + bodysize + send_data

    return packet

async def login(self) -> None:
    login_seq = str(int(time.time() * 1000) + self._login_uuid)[-9:]
    self._login_uuid += 1
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    message = {
        "service": "device",
        "method": "loginReq",
        "seq": login_seq,
        "srcAddr": self.user_id,
        "deviceId": self.device_id,
        "payload": {
            "userId": self.user_id,
            "password": self.password,
            "timestamp": timestamp,
            "ascNumber": 1,
        },
    }
    try:
        self.writer.write(self.get_send_packet(json.dumps(message).encode(), 1))
        await self.writer.drain()
        data = await self.reader.read(1024)
    except (BrokenPipeError, ConnectionResetError) as e:
        _LOGGER.error(f"{self.device_id} login read status error {e}")
    except Exception as e:
        _LOGGER.error(f"recv data error {e}")

    data_len = len(data)
    if data_len <= 0:
        return

    try:
        magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
        encrypted_data = data[8:]
        if self.aes_key is not None:
            decrypted_data = aes_decrypt(encrypted_data, self.aes_key)
        else:
            decrypted_data = encrypted_data

        json_data = json.loads(decrypted_data)
        code = json_data[CONF_ACK][CONF_CODE]
        if code != 200:
            _LOGGER.error(f"{self.device_id} login error, code: {code}")
            await self.reset()
            return

        self.ascNumber = json_data[CONF_PAYLOAD][CONF_ASCNUMBER]
        self.ascNumber += 1
        self.status.online = True
        asyncio.get_running_loop().create_task(self.reveive_data())
        _LOGGER.info(f"connect device success: {self._ip_address}")
        await self.send_action({}, "getDevAttrReq")
    except Exception as e:
        _LOGGER.error(f"connect device error : {e}")
        return

async def reveive_data(self) -> None:
    while True:
        try:
            data = await self.reader.read(1024)
        except (BrokenPipeError, ConnectionResetError) as e:
            _LOGGER.error(f"{self.device_id} read status error {e}")
            await self.reset()
            self.status.online = False
            return
        except Exception as e:
            _LOGGER.error(f"recv data error {e}")
            return
        data_len = len(data)
        if data_len <= 0:
            _LOGGER.error("recv data error len, exit socket")
            await self.reset()
            self.status.online = False
            return
        try:
            magic, msgtype, bodysize = struct.unpack(">HHI", data[:8])
            decrypted_data = aes_decrypt(data[8:], self.aes_key)
            json_data = json.loads(decrypted_data)
        except Exception as e:
            _LOGGER.error(f"recv json error : {e}")
            continue

        if "service" in json_data:
            if "test" == json_data["service"]:
                self.ping_count = 0
                continue

        payload = json_data.get(CONF_PAYLOAD)
        if payload is not None:
            self.ascNumber = payload.get(CONF_ASCNUMBER)
            self.status.update(payload.get(CONF_ATTR))
            if self._status_fresh_cb:
                self._status_fresh_cb(self.status)

def set_status_fresh_cb(self, callback) -> None:
    self._status_fresh_cb = callback

async def read_status(self) -> DeviceStatusData:
    return self.status

async def ping_task(self) -> None:
    while True:
        if self._is_close:
            return
        await asyncio.sleep(5)
        await self.send_ping_action()
        await asyncio.sleep(5)

async def send_dev_attr(self, dev_attr) -> None:
    if not self._connect_and_login:
        raise ConnectionError('Device offline')
    await self.send_action(dev_attr, "setDevAttrReq")

async def async_turn_off(self) -> None:
    await self.send_dev_attr({CONF_ON_OFF: 0})

async def async_turn_on(self) -> None:
    await self.send_dev_attr({CONF_ON_OFF: 1})

async def async_set_brightness(self, brightness: int) -> None:
    final_dimming = int(brightness * 100 / 255)
    await self.send_dev_attr({CONF_DIMMING: final_dimming})

async def async_set_rgbw(self, rgbw: tuple[int, int, int, int]) -> None:
    final_rgbw = (rgbw[0] << 24) | (rgbw[1] << 16) | (rgbw[2] << 8) | rgbw[3]
    await self.send_dev_attr({CONF_RGBW: ctypes.c_int32(final_rgbw).value})

async def async_set_cct(self, cct: int) -> None:
    await self.send_dev_attr({CONF_CCT: cct})

async def send_action(self, attr, method) -> None:
    current_timestamp_milliseconds = int(time.time() * 1000)
    self.seq_num += 1
    seq = "ha93" + str(self.seq_num).zfill(5)
    if not self.status.on and not CONF_ON_OFF in attr:
        self.status.on = True
        attr[CONF_ON_OFF] = 1

    if self._simpleVersion is not None:
        action = {
            "method": method,
            "service": "device",
            "clientId": "ha-" + self.user_id,
            "srcAddr": "0." + self.user_id,
            "seq": "" + seq,
            "payload": {
                "devId": self.device_id,
                "parentId": self.device_id,
                "userId": self.user_id,
                "password": self.password,
                "attr": attr,
                "channel": "tcp",
                "ascNumber": self.ascNumber,
            },
            "tst": current_timestamp_milliseconds,
            "deviceId": self.device_id,
        }
    else:
        action = {
            "method": method,
            "service": "device",
            "seq": "" + seq,
            "srcAddr": "0." + self.user_id,
            "payload": {
                "attr": attr,
                "ascNumber": self.ascNumber,
            },
            "tst": current_timestamp_milliseconds,
            "deviceId": self.device_id,
        }

    try:
        self.writer.write(self.get_send_packet(json.dumps(action).encode(), 1))
        await self.writer.drain()
    except (BrokenPipeError, ConnectionResetError) as e:
        _LOGGER.error(f"{self.device_id} send action error {e}")
        await self.reset()
    except Exception as e:
        _LOGGER.error(f"{self.device_id} send action error {e}")

async def send_ping_action(self) -> int:
    ping = {
        "service": "test",
        "method": "pingreq",
        "seq": "123456",
        "srcAddr": "x.xxxxxxx",
        CONF_PAYLOAD: {},
    }
    try:
        if self.ping_count >= 2:
            _LOGGER.error(
                f"Last ping did not return within 20 seconds. device id:{self.device_id}"
            )
            await self.reset()
            return -1
        if self._connect_and_login is False:
            return -1
        self.writer.write(self.get_send_packet(json.dumps(ping).encode(), 2))
        await self.writer.drain()
        self.ping_count += 1
        return 1
    except Exception as e:
        _LOGGER.error(f"{self.device_id} ping error {e}")
        await self.reset()
        return -1

async def reset(self) -> None:
    try:
        if self.writer:
            self.writer.close()
            await self.writer.wait_closed()
    except Exception as e:
        _LOGGER.error(f"{self.device_id} writer close error {e}")
    self._connect_and_login = False
    self.status.online = False
    self.ping_count = 0

async def close(self) -> None:
    self._is_close = True
    await self.reset()
    _LOGGER.info(f"{self.device_id} connect close by user")
```
