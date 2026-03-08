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

_LOGGER = logging.getLogger(__name__)

# --------------------------------------------------------------------------- #
# Camera / Leedarson smarthome API constants
# --------------------------------------------------------------------------- #

# AppKey from LDSAppOpenSDK CocoaPods docs (kLDSAppOpenSDKKey = "appa070")
_LEEDARSON_APP_KEY = "appa070"

# Camera-specific backend; region prefix mirrors AidotClient._base_url pattern.
# e.g. "us" -> "https://us-smarthome.arnoo.com:443"
_SMARTHOME_URL_TEMPLATE = "https://{region}-smarthome.arnoo.com:443"

# --------------------------------------------------------------------------- #
# Playback TCP binary framing constants
#
# Wire layout (all big-endian) from RecordVideoEncoder.java, verified against
# INettyClientInitializer.java Netty params:
#   lengthFieldOffset=14, lengthFieldLength=4, lengthAdjustment=19
#
# version(H2) seq(i4) cmd(H2) subcmd(H2) cmdParam(i4)  <- 14 bytes
# payloadLen(i4)                                         <- offset 14
# timestamp(q8) context(i4) encodeType(b1) result(h2) reserve(i4)  <- 19 bytes
# <payload bytes>
# Total header = 37 bytes
# --------------------------------------------------------------------------- #

_HDR_FMT         = ">HiHHiiqibhi"
_HDR_SIZE        = struct.calcsize(_HDR_FMT)           # 37
_HDR_PREFIX_FMT  = ">HiHHii"
_HDR_PREFIX_SIZE = struct.calcsize(_HDR_PREFIX_FMT)    # 18
_HDR_SUFFIX_FMT  = ">qibhi"
_HDR_SUFFIX_SIZE = struct.calcsize(_HDR_SUFFIX_FMT)    # 19

assert _HDR_SIZE        == 37
assert _HDR_PREFIX_SIZE == 18
assert _HDR_SUFFIX_SIZE == 19

# Fixed values for all outbound request frames
_HDR_VERSION  = 256   # 0x0100
_HDR_CONTEXT  = 1005
_HDR_ENC_TYPE = 1
_HDR_RESULT   = 4
_HDR_RESERVE  = 2

# TCP command codes from AppCmd.java
_CMD_LOGIN_REQ  = 0x0101
_CMD_LOGIN_RES  = 0x0102
_CMD_HB_REQ     = 0x0105
_CMD_HB_RES     = 0x0106
_CMD_STREAM_REQ = 0x0107
_CMD_STREAM_RES = 0x0108
_CMD_SUBCMD     = 0x0001
_CMD_PARAM      = 0x00000002

# Video sub-frame header size from LDSPlayer.decodeStream():
# padding(2) frameType(1) audioCodec(1) timestamp(8) encType(1) payloadLen(4)
_SF_HDR_SIZE = 17

# Frame type values
_FRAME_TYPE_P_FRAME = 2
_FRAME_TYPE_B_FRAME = 3
_FRAME_TYPE_I_FRAME = 4   # keyframe
_FRAME_TYPE_AUDIO   = 5

_AUDIO_CODEC_G711A = 1

# --------------------------------------------------------------------------- #
# Existing device-state classes (unchanged from original library)
# --------------------------------------------------------------------------- #

class DeviceStatusData:
    online: bool = False
    on: bool = False
    rgdb: int = None
    rgbw: tuple[int, int, int, int] = None
    cct: int = None
    dimming: int = None

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

# --------------------------------------------------------------------------- #
# Camera data types
# --------------------------------------------------------------------------- #

@dataclass
class VideoFrame:
    # frame_type: 2=P-frame  3=B-frame  4=I-frame/keyframe  5=audio
    # audio_codec: 0=N/A  1=G.711A  (meaningful only when frame_type==5)
    # timestamp: server-side PTS in milliseconds
    # is_encrypted: True when sub-frame encryption byte was non-zero
    # data: raw H.264 NAL bytes (video) or G.711A bytes (audio)
    frame_type:   int
    audio_codec:  int
    timestamp:    int
    is_encrypted: bool
    data:         bytes

    @property
    def is_video(self) -> bool:
        return self.frame_type in (_FRAME_TYPE_P_FRAME,
                                   _FRAME_TYPE_B_FRAME,
                                   _FRAME_TYPE_I_FRAME)

    @property
    def is_keyframe(self) -> bool:
        return self.frame_type == _FRAME_TYPE_I_FRAME

    @property
    def is_audio(self) -> bool:
        return self.frame_type == _FRAME_TYPE_AUDIO

# --------------------------------------------------------------------------- #
# TCP binary framing helpers
# --------------------------------------------------------------------------- #

def _pack_frame(cmd: int, payload: bytes, sequence: Optional[int] = None) -> bytes:
    # Build one outbound wire frame: 37-byte header + payload.
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


async def _read_frame(reader: asyncio.StreamReader) -> tuple:
    # Read one complete framed response from the playback TCP server.
    # Returns (header_dict, payload_bytes).
    # header_dict keys: cmd, seq, result, timestamp.
    prefix_raw = await reader.readexactly(_HDR_PREFIX_SIZE)
    _version, seq, cmd, _subcmd, _cmd_param, payload_len = struct.unpack(
        _HDR_PREFIX_FMT, prefix_raw
    )
    if payload_len < 0 or payload_len > 4 * 1024 * 1024:
        raise ValueError(f"Implausible payloadLen={payload_len} in TCP frame")
    rest = await reader.readexactly(_HDR_SUFFIX_SIZE + payload_len)
    timestamp, _context, _enc_type, result, _reserve = struct.unpack(
        _HDR_SUFFIX_FMT, rest[:_HDR_SUFFIX_SIZE]
    )
    payload = rest[_HDR_SUFFIX_SIZE:]
    return {"cmd": cmd, "seq": seq, "result": result, "timestamp": timestamp}, payload


def _parse_video_payload(data: bytes) -> List[VideoFrame]:
    # Parse a STREAM_RES payload into VideoFrame objects.
    # Sub-frame layout (17-byte header, big-endian):
    #   padding(2) frameType(1) audioCodec(1) timestamp(8) encType(1) payloadLen(4)
    # Source: LDSPlayer.decodeStream() in the Leedarson Android SDK.
    frames: List[VideoFrame] = []
    offset = 0
    while len(data) - offset >= _SF_HDR_SIZE:
        frame_type    = data[offset + 2]
        audio_codec   = data[offset + 3]
        (timestamp,)  = struct.unpack_from(">q", data, offset + 4)
        enc_type      = data[offset + 12]
        (payload_len,) = struct.unpack_from(">i", data, offset + 13)
        if payload_len < 0:
            break
        end = offset + _SF_HDR_SIZE + payload_len
        if end > len(data):
            break
        if enc_type != 0:
            frames.append(VideoFrame(frame_type, audio_codec, timestamp, True, b""))
        else:
            frames.append(VideoFrame(
                frame_type, audio_codec, timestamp, False,
                data[offset + _SF_HDR_SIZE:end],
            ))
        offset = end
    return frames

# --------------------------------------------------------------------------- #
# MQTT helper - playback server discovery
# --------------------------------------------------------------------------- #

async def _mqtt_get_playback_server_info(
    mqtt_url: str,
    user_id: str,
    mqtt_password: str,
    dev_id: str,
    client_id: str,
    timeout: float = 15.0,
) -> Optional[dict]:
    # Publish getPlaybackServerInfoReq over MQTT-over-WSS and return the
    # response payload dict, or None on timeout/error.
    # Requires: pip install paho-mqtt
    try:
        import paho.mqtt.client as mqtt
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

    result_event = threading.Event()
    result_box: List[Optional[dict]] = [None]

    parsed    = urllib.parse.urlparse(mqtt_url)
    host      = parsed.hostname or mqtt_url
    port      = parsed.port or (443 if parsed.scheme in ("wss", "mqtts") else 1883)
    path      = parsed.path or "/mqtt"
    use_tls   = parsed.scheme in ("wss", "mqtts")
    transport = "websockets" if parsed.scheme in ("wss", "ws") else "tcp"

    def on_connect(client, userdata, flags, rc):
        if rc != 0:
            _LOGGER.warning("MQTT broker rejected connection rc=%d", rc)
            result_event.set()
            return
        client.subscribe(sub_topic, qos=1)
        client.publish(pub_topic, request_body, qos=1)

    def on_message(client, userdata, msg):
        try:
            body = json.loads(msg.payload.decode("utf-8"))
            if str(body.get("seq")) == seq:
                pld = body.get("payload")
                if pld and pld.get("serverIP"):
                    result_box[0] = pld
                    result_event.set()
        except Exception:
            pass

    def _run_mqtt():
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

# --------------------------------------------------------------------------- #
# AES helpers (live stream)
#
# Source: AESUtils.java in Leedarson Android SDK.
# Algorithm: AES/ECB/PKCS7Padding, key zero-padded to 32 bytes.
# --------------------------------------------------------------------------- #

def _aes_pad_key(key_str: str) -> bytes:
    # Replicate AESUtils.get32Key(): take UTF-8 bytes of key, zero-pad to 32.
    raw = key_str.encode("utf-8")
    return raw[:32].ljust(32, b"\x00")


def _aes_ecb_decrypt(key_str: str, data: bytes) -> bytes:
    # AES-256/ECB/PKCS7 decrypt. Used to decrypt live-stream TCP frame payloads.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for live-stream decryption. "
            "Install it with:  pip install cryptography"
        ) from exc
    key = _aes_pad_key(key_str)
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    dec = cipher.decryptor()
    padded = dec.update(data) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _aes_ecb_encrypt(key_str: str, data: bytes) -> bytes:
    # AES-256/ECB/PKCS7 encrypt. Used to encrypt outbound live-stream payloads.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
    except ImportError as exc:
        raise ImportError(
            "The 'cryptography' package is required for live-stream encryption. "
            "Install it with:  pip install cryptography"
        ) from exc
    key = _aes_pad_key(key_str)
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(padded) + enc.finalize()


# --------------------------------------------------------------------------- #
# MQTT helper - live stream server discovery (connectipc)
#
# Source: iOS LDSXplayer -startRealPlay, LDSTCPManager, TCP_API in the
# Leedarson iOS SDK binary.  The request mirrors _mqtt_get_playback_server_info
# but uses method="connectipc" and receives AES/session credentials in return.
# --------------------------------------------------------------------------- #

async def _mqtt_get_live_server_info(
    mqtt_url: str,
    user_id: str,
    mqtt_password: str,
    dev_id: str,
    client_id: str,
    timeout: float = 15.0,
) -> Optional[dict]:
    # Publish connectipc over MQTT-over-WSS and return the response payload dict,
    # or None on timeout/error.
    # Expected response payload fields:
    #   serverIP, serverPort, sessionId, aesKey, heartbeat, tls
    # Requires: pip install paho-mqtt
    try:
        import paho.mqtt.client as mqtt
    except ImportError as exc:
        raise ImportError(
            "paho-mqtt is required for live streaming. "
            "Install it with:  pip install paho-mqtt"
        ) from exc

    import ssl
    import threading
    import urllib.parse

    seq       = str(random.randint(100_000, 999_999))
    pub_topic = f"iot/v1/s/{user_id}/IPCAM/connectipc"
    sub_topic = f"iot/v1/c/{user_id}/#"

    request_body = json.dumps({
        "service": "IPCAM",
        "method":  "connectipc",
        "seq":     seq,
        "srcAddr": f"0.{user_id}",
        "payload": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "deviceId":  dev_id,
            "clientId":  client_id,
        },
    })

    result_event = threading.Event()
    result_box: List[Optional[dict]] = [None]

    parsed    = urllib.parse.urlparse(mqtt_url)
    host      = parsed.hostname or mqtt_url
    port      = parsed.port or (443 if parsed.scheme in ("wss", "mqtts") else 1883)
    path      = parsed.path or "/mqtt"
    use_tls   = parsed.scheme in ("wss", "mqtts")
    transport = "websockets" if parsed.scheme in ("wss", "ws") else "tcp"

    def on_connect(client, userdata, flags, rc):
        if rc != 0:
            _LOGGER.warning("MQTT (connectipc) broker rejected connection rc=%d", rc)
            result_event.set()
            return
        client.subscribe(sub_topic, qos=1)
        client.publish(pub_topic, request_body, qos=1)

    def on_message(client, userdata, msg):
        try:
            body = json.loads(msg.payload.decode("utf-8"))
            if str(body.get("seq")) == seq:
                pld = body.get("payload")
                if pld and pld.get("serverIP"):
                    result_box[0] = pld
                    result_event.set()
        except Exception:
            pass

    def _run_mqtt():
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


# --------------------------------------------------------------------------- #
# CloudPlaybackSession
# --------------------------------------------------------------------------- #

class CloudPlaybackSession:
    # Manages a single cloud-playback TCP session for a Leedarson/AiDot camera.
    # Use DeviceClient.async_open_cloud_playback() to obtain an instance.

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
        self._start_ts    = start_ts_s
        self._on_frame    = on_frame
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._running  = False
        self._paused   = False
        self._hb_task: Optional[asyncio.Task] = None
        self._rx_task: Optional[asyncio.Task] = None

    async def _connect_and_login(self) -> bool:
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
                    "Cloud playback: login rejected code=%s body=%s",
                    body_obj.get("code"), body_obj,
                )
                return False
        except (json.JSONDecodeError, ValueError):
            pass  # some firmware sends no JSON body - treat as success

        _LOGGER.debug(
            "Cloud playback: login OK task=%d server=%s:%d",
            self._task_id, self._server_ip, self._server_port,
        )
        return True

    async def _request_stream_batch(self) -> None:
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
        while self._running:
            if self._paused:
                await asyncio.sleep(0.2)
                continue
            try:
                hdr, payload = await asyncio.wait_for(
                    _read_frame(self._reader),
                    timeout=30.0,
                )
            except asyncio.TimeoutError:
                _LOGGER.warning("Cloud playback: receive timeout")
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
                continue

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
                # End-of-stream sentinel from LDSOpenSDK.java receiveDataTask
                _LOGGER.info("Cloud playback: end of stream reached")
                break
            else:
                _LOGGER.warning("Cloud playback: unexpected stream result=%d", result)

    async def start(self) -> bool:
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
        self._paused = True

    async def resume(self) -> None:
        self._paused = False
        if self._running and self._writer is not None:
            await self._request_stream_batch()

    async def stop(self) -> None:
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

# --------------------------------------------------------------------------- #
# LiveStreamSession
#
# Manages a single live-stream TCP session for a Leedarson/AiDot camera.
# Use DeviceClient.async_open_live_stream() to obtain an instance.
#
# Protocol source: iOS LDSXplayer startRealPlay → LDSTCPManager
#   connectHost:port:sessionId:aesKey:heartbeat:msg:cmd:subCmd:cmdParam:tls:
#
# Wire format: same 37-byte header + payload as CloudPlaybackSession, but:
#   - TLS socket (server cert not verified -- IoT device)
#   - AES-256/ECB/PKCS7 encrypts outbound payloads; decrypts inbound payloads
#   - LOGIN payload carries sessionId from the MQTT connectipc response
#   - STREAM_REQ starts the live video feed (no taskId needed)
# --------------------------------------------------------------------------- #

class LiveStreamSession:

    def __init__(
        self,
        server_ip: str,
        server_port: int,
        session_id: str,
        aes_key: str,
        heartbeat_interval: int,
        use_tls: bool,
        on_frame: Callable[["VideoFrame"], None],
    ) -> None:
        self._server_ip         = server_ip
        self._server_port       = int(server_port)
        self._session_id        = session_id
        self._aes_key           = aes_key
        self._heartbeat_secs    = max(1, int(heartbeat_interval))
        self._use_tls           = use_tls
        self._on_frame          = on_frame
        self._reader: Optional[asyncio.StreamReader]  = None
        self._writer: Optional[asyncio.StreamWriter]  = None
        self._task:   Optional[asyncio.Task]          = None
        self._closed  = False

    # -- Public interface ---------------------------------------------------- #

    async def start(self) -> bool:
        # Open the TLS (or plain) TCP connection and perform the login handshake.
        # Returns True on success, False on failure.
        import ssl

        try:
            if self._use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode    = ssl.CERT_NONE
            else:
                ssl_ctx = None

            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self._server_ip, self._server_port, ssl=ssl_ctx
                ),
                timeout=10,
            )
        except Exception as exc:
            _LOGGER.error(
                "LiveStreamSession: TCP connect to %s:%d failed: %s",
                self._server_ip, self._server_port, exc,
            )
            return False

        # LOGIN -- carry sessionId as credential, AES-encrypt the JSON payload.
        try:
            login_body_raw = json.dumps({
                "sessionId": self._session_id,
                "clientId":  "live-stream",
            }).encode("utf-8")
            login_enc = _aes_ecb_encrypt(self._aes_key, login_body_raw)
            self._writer.write(_pack_frame(_CMD_LOGIN_REQ, login_enc))
            await self._writer.drain()

            hdr, payload = await asyncio.wait_for(_read_frame(self._reader), timeout=10)
            if hdr["cmd"] != _CMD_LOGIN_RES:
                _LOGGER.error(
                    "LiveStreamSession: expected LOGIN_RES (0x%04x), got 0x%04x",
                    _CMD_LOGIN_RES, hdr["cmd"],
                )
                await self._cleanup()
                return False

            # Decrypt and log the login response (best-effort -- ignore on error)
            try:
                resp_plain = _aes_ecb_decrypt(self._aes_key, payload)
                _LOGGER.debug("LiveStreamSession: LOGIN_RES: %s", resp_plain[:200])
            except Exception:
                _LOGGER.debug("LiveStreamSession: LOGIN_RES payload not AES-encrypted")

        except Exception as exc:
            _LOGGER.error("LiveStreamSession: login handshake failed: %s", exc)
            await self._cleanup()
            return False

        # STREAM_REQ -- request the live feed.
        # No taskId needed; the sessionId from MQTT already identifies the stream.
        try:
            stream_body_raw = json.dumps({"sessionId": self._session_id}).encode("utf-8")
            stream_enc = _aes_ecb_encrypt(self._aes_key, stream_body_raw)
            self._writer.write(_pack_frame(_CMD_STREAM_REQ, stream_enc))
            await self._writer.drain()
        except Exception as exc:
            _LOGGER.error("LiveStreamSession: STREAM_REQ failed: %s", exc)
            await self._cleanup()
            return False

        # Start background receive/heartbeat task.
        self._task = asyncio.get_event_loop().create_task(self._receive_loop())
        return True

    async def stop(self) -> None:
        # Gracefully stop the session.
        self._closed = True
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        await self._cleanup()

    # -- Internals ----------------------------------------------------------- #

    async def _receive_loop(self) -> None:
        assert self._reader is not None
        assert self._writer is not None

        hb_interval = self._heartbeat_secs
        last_hb     = time.monotonic()

        try:
            while not self._closed:
                # Send heartbeat if due.
                if time.monotonic() - last_hb >= hb_interval:
                    try:
                        hb_enc = _aes_ecb_encrypt(self._aes_key, b"{}")
                        self._writer.write(_pack_frame(_CMD_HB_REQ, hb_enc))
                        await self._writer.drain()
                        last_hb = time.monotonic()
                    except Exception as exc:
                        _LOGGER.warning("LiveStreamSession: heartbeat error: %s", exc)
                        break

                # Read next frame with a deadline matching the heartbeat interval.
                try:
                    hdr, payload = await asyncio.wait_for(
                        _read_frame(self._reader),
                        timeout=hb_interval * 2,
                    )
                except asyncio.TimeoutError:
                    _LOGGER.warning("LiveStreamSession: receive timeout -- reconnect?")
                    break

                if hdr["cmd"] == _CMD_HB_RES:
                    continue

                if hdr["cmd"] != _CMD_STREAM_RES:
                    _LOGGER.debug(
                        "LiveStreamSession: unexpected cmd=0x%04x", hdr["cmd"]
                    )
                    continue

                # End-of-stream sentinel (result == -15528 from LDSOpenSDK.java)
                if hdr.get("result") == -15528:
                    _LOGGER.info("LiveStreamSession: end-of-stream sentinel received")
                    break

                # AES-decrypt the payload, then parse video sub-frames.
                try:
                    plain = _aes_ecb_decrypt(self._aes_key, payload)
                except Exception:
                    # Some servers send unencrypted frames; fall back gracefully.
                    plain = payload

                for frame in _parse_video_payload(plain):
                    try:
                        self._on_frame(frame)
                    except Exception as exc:
                        _LOGGER.warning(
                            "LiveStreamSession: on_frame callback raised: %s", exc
                        )

        except asyncio.CancelledError:
            pass
        except Exception as exc:
            if not self._closed:
                _LOGGER.error("LiveStreamSession: receive loop error: %s", exc)
        finally:
            await self._cleanup()

    async def _cleanup(self) -> None:
        if self._writer:
            try:
                self._writer.close()
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None


# --------------------------------------------------------------------------- #
# DeviceClient
# --------------------------------------------------------------------------- #

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

        # Store full user_info for camera API calls
        self._user_info: dict[str, Any] = user_info

        # Region written to login_info by AidotClient.async_post_login()
        self._region: str = user_info.get("region", "us")

        # Cache slot for MQTT broker URL, fetched lazily on first playback call
        self._mqtt_url: Optional[str] = None

        # Cache slot for Leedarson smarthome auth (mqttUser, mqttPassword, userId)
        # Fetched lazily via _async_get_smarthome_auth()
        self._smarthome_auth: Optional[dict] = None

        if CONF_AES_KEY in device:
            key_string = device[CONF_AES_KEY][0]
            if key_string is not None:
                self.aes_key = bytearray(16)
                key_bytes = key_string.encode()
                self.aes_key[: len(key_bytes)] = key_bytes

        self.password = device.get(CONF_PASSWORD)
        self.device_id = device.get(CONF_ID)
        self._simpleVersion = device.get("simpleVersion")

    # -- Camera helpers ------------------------------------------------------ #

    @property
    def _smarthome_base(self) -> str:
        return _SMARTHOME_URL_TEMPLATE.format(region=self._region)

    def _leedarson_headers(self) -> dict:
        # HTTP headers required by the Leedarson smarthome API.
        # Mirrors header construction in LDSOpenSDK.java.
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
        # Fetch and cache the WSS MQTT broker URL (and MQTT credentials) from
        # getServerUrlConfig.  The full response is stored in self._smarthome_auth
        # so mqttUser / mqttPassword are captured in the same call.
        if self._mqtt_url:
            return self._mqtt_url

        import aiohttp

        headers = {k: v for k, v in self._leedarson_headers().items()
                   if k != "Content-Type"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self._smarthome_base}/commonController/getServerUrlConfig",
                    headers=headers,
                    params={"version": "1.0.1", "clientId": f"app-{self.user_id}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json(content_type=None)

            data = body.get("data") or {}
            _LOGGER.warning("getServerUrlConfig full response data keys=%s  body=%s", list(data.keys()), body)

            mqtt_host = data.get("mqttServerUrl") or ""
            if not mqtt_host:
                _LOGGER.error("getServerUrlConfig returned no mqttServerUrl: %s", body)
                return None

            self._mqtt_url = (
                mqtt_host
                if mqtt_host.startswith(("wss://", "ws://"))
                else f"wss://{mqtt_host}"
            )

            # Capture mqttUser + mqttPassword from this same response if present.
            # iOS SDK binary strings confirm these fields cluster with mqttServerUrl.
            if not self._smarthome_auth:
                self._smarthome_auth = {
                    "mqttUrl":      self._mqtt_url,
                    "mqttUser":     (data.get("mqttUser") or data.get("userId")
                                     or str(self.user_id)),
                    "mqttPassword": (data.get("mqttPassword") or data.get("mqqtPwd")
                                     or ""),
                    "raw":          data,
                }
                _LOGGER.debug(
                    "Server config cached: url=%s mqttUser=%s hasPwd=%s  all_keys=%s",
                    self._mqtt_url,
                    self._smarthome_auth["mqttUser"],
                    bool(self._smarthome_auth["mqttPassword"]),
                    list(data.keys()),
                )
                _LOGGER.warning("getServerUrlConfig data=%s", data)

            return self._mqtt_url

        except Exception as exc:
            _LOGGER.error("_async_get_mqtt_url failed: %s", exc)
            return None

    async def _async_get_smarthome_auth(self) -> Optional[dict]:
        """Fetch MQTT credentials (mqttUser + mqttPassword) for the Arnoo broker.

        Strategy order — stops at first success:
          0. Already cached
          1. mqttPassword already in AiDot login_info (unlikely but cheap to check)
          2. GET /user/getUser  <- THE DOCUMENTED STEP 3 from LDSAppOpenSDK CocoaPods README
             The SDK calls reqUserAuthInfoWithCallback which hits /user/getUser?desc=...
             and returns LDSAuthInfo {userId, mqttUser, mqttPassword, ...}
          3. getServerUrlConfig response (fallback — may not include mqtt creds)
          4. POST /user/login form-encoded with multiple appId/pwd variants (last resort)
        """
        if self._smarthome_auth and self._smarthome_auth.get("mqttPassword"):
            return self._smarthome_auth

        import aiohttp

        # Smarthome userId — 'id' in AiDot login_info is the Leedarson userId
        _mqtt_id = (
            self._user_info.get("id")
            or self._user_info.get("userId")
            or str(self.user_id)
        )

        # --- Strategy 1: mqttPassword already in AiDot login_info ---
        for key in ("mqttPassword", "mqqtPwd", "mqttPwd", "mqtt_pwd",
                    "mqttPass", "mqtttoken", "mqttToken", "MQTTPassword"):
            val = self._user_info.get(key)
            if val:
                _LOGGER.warning("_async_get_smarthome_auth: found %r in login_info", key)
                self._smarthome_auth = {
                    "mqttUser":     _mqtt_id,
                    "mqttPassword": val,
                    "userId":       _mqtt_id,
                    "raw":          {"source": f"login_info.{key}"},
                }
                return self._smarthome_auth

        # --- Strategy 2: GET /user/getUser  (reqUserAuthInfoWithCallback in SDK) ---
        # CocoaPods README documents the 3-step auth flow:
        #   1. loginWithUserName -> accessToken
        #   2. setHeader (set token on SDK)
        #   3. reqUserAuthInfoWithCallback -> LDSAuthInfo {mqttUser, mqttPassword}
        token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        if token:
            headers = self._leedarson_headers()
            for desc_val in (_mqtt_id, "", None):
                params = {"desc": desc_val} if desc_val is not None else {}
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(
                            f"{self._smarthome_base}/user/getUser",
                            headers=headers,
                            params=params,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            body = await resp.json(content_type=None)

                    code = body.get("code")
                    data = body.get("data") or {}
                    _LOGGER.warning(
                        "_async_get_smarthome_auth GET /user/getUser desc=%r -> "
                        "code=%s  data_keys=%s  body=%s",
                        desc_val, code,
                        list(data.keys()) if isinstance(data, dict) else data,
                        body,
                    )
                    print(f"    [getUser] desc={desc_val!r} code={code} "
                          f"data_keys={list(data.keys()) if isinstance(data, dict) else data!r} "
                          f"body={body!r}")

                    if isinstance(data, dict):
                        auth = data.get("authInfo") or data
                        mqtt_user = (
                            auth.get("mqttUser")
                            or auth.get("userId")
                            or auth.get("associatedAccount")
                            or _mqtt_id
                        )
                        mqtt_pwd = (
                            auth.get("mqttPassword")
                            or auth.get("mqqtPwd")
                            or auth.get("mqttPwd")
                            or ""
                        )
                        if mqtt_pwd:
                            self._smarthome_auth = {
                                "mqttUser":     mqtt_user,
                                "mqttPassword": mqtt_pwd,
                                "userId":       auth.get("userId") or mqtt_user,
                                "raw":          auth,
                            }
                            _LOGGER.warning(
                                "_async_get_smarthome_auth OK via /user/getUser: "
                                "mqttUser=%s desc=%r", mqtt_user, desc_val,
                            )
                            return self._smarthome_auth

                    if code not in (200, 0, None):
                        break  # hard error, don't retry other desc values

                except Exception as exc:
                    _LOGGER.debug("_async_get_smarthome_auth /user/getUser exc: %s", exc)
                    print(f"    [getUser] EXCEPTION: {exc}")
                    break

        # --- Strategy 3: getServerUrlConfig ---
        if not self._mqtt_url:
            await self._async_get_mqtt_url()
        if self._smarthome_auth and self._smarthome_auth.get("mqttPassword"):
            _LOGGER.warning("_async_get_smarthome_auth: mqttPassword from getServerUrlConfig")
            return self._smarthome_auth

        # --- Strategy 4: POST /user/login (form-encoded, multiple appId+pwd variants) ---
        import hashlib

        username = (
            self._user_info.get("username")
            or self._user_info.get("userName")
            or ""
        )
        password = (
            self._user_info.get("password")
            or self._user_info.get("passWord")
            or ""
        )
        if not username or not password:
            _LOGGER.error(
                "_async_get_smarthome_auth: username/password missing — cannot try /user/login"
            )
            return None

        rsa_pwd: Optional[str] = None
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import padding as _apad
            from cryptography.hazmat.backends import default_backend
            import base64 as _b64
            _PUBLIC_KEY_PEM = (
                b"-----BEGIN PUBLIC KEY-----\n"
                b"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtQAnPCi8ksPnS1Du6z96PsKfN\n"
                b"p2Gp/f/bHwlrAdplbX3p7/TnGpnbJGkLq8uRxf6cw+vOthTsZjkPCF7CatRvRnTj\n"
                b"c9fcy7yE0oXa5TloYyXD6GkxgftBbN/movkJJGQCc7gFavuYoAdTRBOyQoXBtm0m\n"
                b"kXMSjXOldI/290b9BQIDAQAB\n"
                b"-----END PUBLIC KEY-----"
            )
            pub_key = serialization.load_pem_public_key(
                _PUBLIC_KEY_PEM, backend=default_backend()
            )
            rsa_pwd = _b64.b64encode(
                pub_key.encrypt(password.encode("utf-8"), _apad.PKCS1v15())
            ).decode("utf-8")
        except Exception as exc:
            _LOGGER.debug("RSA encrypt unavailable: %s", exc)

        md5_pwd = hashlib.md5(password.encode("utf-8")).hexdigest().upper()
        _AIDOT_APP_ID = "1383974540041977857"
        pwd_variants = []
        if rsa_pwd:
            pwd_variants.append(("rsa", rsa_pwd))
        pwd_variants.append(("plain", password))
        pwd_variants.append(("md5", md5_pwd))

        login_headers = {
            "terminal":        "thirdPlatFormUser",
            "active-language": "en_US",
            "appKey":          _LEEDARSON_APP_KEY,
        }
        last_body: dict = {}
        async with aiohttp.ClientSession() as session:
            for app_id in (_LEEDARSON_APP_KEY, _AIDOT_APP_ID):
                for pwd_type, pwd_val in pwd_variants:
                    _tenant_id = (
                        self._user_info.get("tid")
                        or self._user_info.get("tenantId")
                        or ""
                    )
                    _phone_id = (
                        self._user_info.get("terminalIndex")
                        or self._user_info.get("phoneId")
                        or ""
                    )
                    form_data = {
                        "userName":     username,
                        "passWord":     pwd_val,
                        "os":           "ios",
                        "terminalMark": "thirdPlatFormUser",
                        "appId":        app_id,
                        "tenantId":     _tenant_id,
                        "phoneId":      _phone_id,
                        "locationId":   self._region or "us",
                    }
                    try:
                        async with session.post(
                            f"{self._smarthome_base}/user/login",
                            data=form_data,
                            headers=login_headers,
                            params={"appId": app_id},
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            last_body = await resp.json(content_type=None)

                        code = last_body.get("code")
                        _LOGGER.warning(
                            "_async_get_smarthome_auth /user/login appId=%s pwd=%s "
                            "-> code=%s: %s",
                            app_id, pwd_type, code, last_body.get("desc"),
                        )
                        print(f"    [/user/login] appId={app_id} pwd={pwd_type} "
                              f"tenantId={_tenant_id!r} -> code={code} desc={last_body.get('desc')!r}")
                        if code not in (200, 0):
                            continue

                        data = last_body.get("data") or {}
                        if isinstance(data, str):
                            import json as _json
                            try:
                                data = _json.loads(data)
                            except Exception:
                                data = {}

                        auth = (data.get("authInfo") if isinstance(data, dict) else None) or data
                        mqtt_user = (
                            (auth.get("mqttUser")             if isinstance(auth, dict) else None)
                            or (auth.get("userId")            if isinstance(auth, dict) else None)
                            or (auth.get("associatedAccount") if isinstance(auth, dict) else None)
                            or _mqtt_id
                        )
                        mqtt_pwd = (
                            (auth.get("mqttPassword") if isinstance(auth, dict) else None)
                            or (auth.get("mqqtPwd")   if isinstance(auth, dict) else None)
                            or (auth.get("mqttPwd")   if isinstance(auth, dict) else None)
                            or ""
                        )
                        if mqtt_pwd:
                            self._smarthome_auth = {
                                "mqttUser":     mqtt_user,
                                "mqttPassword": mqtt_pwd,
                                "userId":       (auth.get("userId") if isinstance(auth, dict) else None) or mqtt_user,
                                "raw":          auth,
                            }
                            _LOGGER.warning(
                                "_async_get_smarthome_auth OK via /user/login: "
                                "mqttUser=%s appId=%s pwd=%s", mqtt_user, app_id, pwd_type,
                            )
                            return self._smarthome_auth

                        _LOGGER.warning(
                            "_async_get_smarthome_auth /user/login code=200 but no "
                            "mqttPassword. data_keys=%s  auth_keys=%s",
                            list(data.keys()) if isinstance(data, dict) else data,
                            list(auth.keys()) if isinstance(auth, dict) else auth,
                        )

                    except Exception as exc:
                        _LOGGER.debug(
                            "_async_get_smarthome_auth /user/login appId=%s pwd=%s: %s",
                            app_id, pwd_type, exc,
                        )
                        continue

        # --- Strategy 5: accessToken as MQTT password (common Arnoo pattern) ---
        # The Arnoo broker frequently accepts (userId, accessToken) as credentials.
        # This is always available and is the first candidate --diag-mqtt tries.
        # Use it as a guaranteed non-empty fallback rather than returning None.
        access_token = (
            self._user_info.get("accessToken")
            or self._user_info.get("access_token")
            or ""
        )
        if access_token:
            _LOGGER.warning(
                "_async_get_smarthome_auth: all HTTP strategies failed; "
                "falling back to userId+accessToken for MQTT (common Arnoo pattern). "
                "last_body=%s", last_body,
            )
            self._smarthome_auth = {
                "mqttUser":     _mqtt_id,
                "mqttPassword": access_token,
                "userId":       _mqtt_id,
                "raw":          {"source": "accessToken_fallback"},
            }
            return self._smarthome_auth

        _LOGGER.error(
            "_async_get_smarthome_auth: all strategies failed (no accessToken either). "
            "last_body=%s  login_info_keys=%s",
            last_body,
            list(self._user_info.keys()),
        )
        return None

    # -- Camera public methods ----------------------------------------------- #

    async def async_get_p2p_uid(self) -> Optional[str]:
        # Fetch the TUTK P2P UID for this camera from the AiDot cloud.
        # POST /deviceController/getP2pId  body: deviceId=<device_id>
        import aiohttp

        headers = {k: v for k, v in self._leedarson_headers().items()
                   if k != "Content-Type"}
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
                "async_get_p2p_uid: empty UID for %s: %s", self.device_id, body
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
        # List cloud-recorded time slots for this camera.
        # start_ts / end_ts: Unix timestamps in milliseconds.
        # Returns list of {"sta": <ms>, "end": <ms>} dicts.
        # POST /api/ipc/playbackController/getRecordTimeSlot
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
                "async_get_cloud_recordings failed for %s: %s", self.device_id, exc
            )
            return []

    async def async_open_cloud_playback(
        self,
        start_ts: int,
        end_ts: int,
        on_frame: Callable[[VideoFrame], None],
    ) -> Optional[CloudPlaybackSession]:
        # Open a cloud-playback session and begin streaming VideoFrame objects.
        # start_ts / end_ts: Unix timestamps in milliseconds.
        # on_frame: called in the asyncio event loop for each decoded frame.
        # Returns a running CloudPlaybackSession, or None if handshake fails.
        #
        # Three-step handshake from LDSOpenSDK.playCloudRecord():
        #   1. MQTT getPlaybackServerInfoReq -> serverIP, serverPort, heartbeat
        #   2. HTTP POST playRecord          -> taskId
        #   3. TCP binary login + stream
        import aiohttp

        # Fetch MQTT credentials from the Leedarson smarthome /user/login endpoint.
        # The AiDot platform login does NOT return mqttUser/mqttPassword.
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = f"app-{mqtt_user}"

        # Step 1 - MQTT
        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.error(
                "async_open_cloud_playback: cannot determine MQTT URL for %s",
                self.device_id,
            )
            return None

        _LOGGER.debug("Cloud playback step 1: MQTT for %s", self.device_id)
        srv_info = await _mqtt_get_playback_server_info(
            mqtt_url, mqtt_user, mqtt_pwd, self.device_id, client_id,
        )
        if not srv_info:
            _LOGGER.error(
                "async_open_cloud_playback: MQTT response empty for %s",
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

        # Step 2 - HTTP playRecord
        _LOGGER.debug("Cloud playback step 2: HTTP playRecord for %s", self.device_id)
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
                "async_open_cloud_playback: playRecord failed for %s: %s",
                self.device_id, exc,
            )
            return None

        # Step 3 - TCP
        _LOGGER.debug(
            "Cloud playback step 3: TCP to %s:%d task=%d heartbeat=%ds",
            server_ip, server_port, task_id, heartbeat,
        )
        pb_session = CloudPlaybackSession(
            server_ip=server_ip,
            server_port=int(server_port),
            heartbeat_interval=heartbeat,
            task_id=int(task_id),
            client_id=str(self.user_id),
            start_ts_s=start_ts // 1000,
            on_frame=on_frame,
        )
        if not await pb_session.start():
            return None

        _LOGGER.info(
            "Cloud playback session open for %s task=%d start=%d",
            self.device_id, task_id, start_ts // 1000,
        )
        return pb_session

    async def async_open_live_stream(
        self,
        on_frame: Callable[[VideoFrame], None],
        timeout: float = 15.0,
    ) -> Optional[LiveStreamSession]:
        # Open a live-stream session and begin delivering VideoFrame objects.
        # on_frame: called in the asyncio event loop for each decoded frame.
        # Returns a running LiveStreamSession, or None if the handshake fails.
        #
        # Two-step handshake from iOS LDSXplayer -startRealPlay:
        #   1. MQTT connectipc  -> serverIP, serverPort, sessionId, aesKey, heartbeat, tls
        #   2. TLS TCP LOGIN + STREAM_REQ (AES-256/ECB/PKCS7 on all payloads)

        # Fetch MQTT credentials from the Leedarson smarthome /user/login endpoint.
        # The AiDot platform login does NOT return mqttUser/mqttPassword.
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        client_id = f"app-{mqtt_user}"

        # Step 1 -- MQTT connectipc
        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.error(
                "async_open_live_stream: cannot determine MQTT URL for %s",
                self.device_id,
            )
            return None

        _LOGGER.debug("Live stream step 1: MQTT connectipc for %s", self.device_id)
        srv_info = await _mqtt_get_live_server_info(
            mqtt_url, mqtt_user, mqtt_pwd,
            self.device_id, client_id, timeout=timeout,
        )
        if not srv_info:
            _LOGGER.error(
                "async_open_live_stream: MQTT connectipc response empty for %s. "
                "Camera may be offline or may not support this streaming path.",
                self.device_id,
            )
            return None

        server_ip   = srv_info.get("serverIP")
        server_port = srv_info.get("serverPort")
        session_id  = srv_info.get("sessionId") or ""
        aes_key     = srv_info.get("aesKey") or ""
        heartbeat   = int(srv_info.get("heartbeat") or 15)
        use_tls     = bool(srv_info.get("tls", True))

        if not server_ip or not server_port:
            _LOGGER.error(
                "async_open_live_stream: incomplete server info for %s: %s",
                self.device_id, srv_info,
            )
            return None

        if not aes_key:
            _LOGGER.warning(
                "async_open_live_stream: no aesKey in response for %s -- "
                "AES encryption disabled",
                self.device_id,
            )

        # Step 2 -- TLS TCP
        _LOGGER.debug(
            "Live stream step 2: TCP to %s:%d tls=%s heartbeat=%ds for %s",
            server_ip, server_port, use_tls, heartbeat, self.device_id,
        )
        session = LiveStreamSession(
            server_ip=server_ip,
            server_port=int(server_port),
            session_id=session_id,
            aes_key=aes_key,
            heartbeat_interval=heartbeat,
            use_tls=use_tls,
            on_frame=on_frame,
        )
        if not await session.start():
            return None

        _LOGGER.info(
            "Live stream session open for %s -> %s:%d",
            self.device_id, server_ip, server_port,
        )
        return session

    # -- Existing methods (unchanged) ---------------------------------------- #

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
        if not self.status.on and CONF_ON_OFF not in attr:
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
