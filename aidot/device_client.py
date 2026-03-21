"""The aidot integration."""

import ctypes
import json
import logging
import random
import socket
import struct
import threading
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
# TutkStreamSession
#
# TUTK IOTC P2P live-stream session for Leedarson/AiDot cameras.
# Use DeviceClient.async_open_live_stream() to obtain an instance.
#
# Protocol source: classes.jar.decompiled.zip / TutkManager.java
#   IOTC_Connect_ByUID_Parallel(uid, sid) → nSID
#   avClientStart2(nSID, "admin", "admin123", ...) → avIndex
#   avSendIOCtrl(avIndex, 511, ...) → start video (IOTYPE_USER_IPCAM_START)
#   avRecvFrameData2(avIndex, ...) → frame data loop
#
# Requires: libIOTCAPIs.so + libAVAPIs.so from the TUTK SDK.
# Obtain them from the TUTK SDK distribution or an extracted AiDot APK.
# --------------------------------------------------------------------------- #

class TutkStreamSession:
    """TUTK IOTC P2P live-stream session."""

    _IOTYPE_INNER_SND_DATA_DELAY = 255   # TutkManager.java: sent before START
    _IOTYPE_USER_IPCAM_START     = 511   # AVIOCTRLDEFs: IOTYPE_USER_IPCAM_START
    _IOTYPE_USER_IPCAM_STOP      = 767   # AVIOCTRLDEFs: IOTYPE_USER_IPCAM_STOP
    _IOTYPE_USER_IPCAM_AUDIOSTART = 768  # AVIOCTRLDEFs: IOTYPE_USER_IPCAM_AUDIOSTART

    def __init__(
        self,
        uid: str,
        on_frame: Callable[["VideoFrame"], None],
        iotc_lib_path: str = "libIOTCAPIs.so",
        av_lib_path: str = "libAVAPIs.so",
    ) -> None:
        self._uid           = uid
        self._on_frame      = on_frame
        self._iotc_lib_path = iotc_lib_path
        self._av_lib_path   = av_lib_path
        self._thread: Optional[threading.Thread] = None
        self._stop_event    = threading.Event()
        self._sid           = -1
        self._av_index      = -1

    async def start(self) -> bool:
        """Load native libs, connect P2P, and start the frame-receive thread."""
        return await asyncio.get_event_loop().run_in_executor(
            None, self._start_sync)

    def _start_sync(self) -> bool:
        import ctypes

        try:
            iotc = ctypes.CDLL(self._iotc_lib_path)
            av   = ctypes.CDLL(self._av_lib_path)
        except OSError as exc:
            _LOGGER.error(
                "TutkStreamSession: cannot load TUTK native libraries "
                "(%s, %s): %s. "
                "Obtain them from the TUTK SDK or an extracted AiDot APK.",
                self._iotc_lib_path, self._av_lib_path, exc,
            )
            return False

        # --- Declare function signatures ------------------------------------ #
        iotc.IOTC_Initialize2.restype  = ctypes.c_int
        iotc.IOTC_Initialize2.argtypes = [ctypes.c_int]

        iotc.IOTC_Get_SessionID.restype  = ctypes.c_int
        iotc.IOTC_Get_SessionID.argtypes = []

        iotc.IOTC_Set_Max_Session_Number.restype  = None
        iotc.IOTC_Set_Max_Session_Number.argtypes = [ctypes.c_int]

        iotc.IOTC_Connect_ByUID_Parallel.restype  = ctypes.c_int
        iotc.IOTC_Connect_ByUID_Parallel.argtypes = [ctypes.c_char_p, ctypes.c_int]

        iotc.IOTC_Session_Close.restype  = None
        iotc.IOTC_Session_Close.argtypes = [ctypes.c_int]

        # TutkManager.java: AVAPIs.avInitialize(32)
        av.avInitialize.restype  = ctypes.c_int
        av.avInitialize.argtypes = [ctypes.c_int]

        av.avClientStart2.restype  = ctypes.c_int
        av.avClientStart2.argtypes = [
            ctypes.c_int,                        # nSID
            ctypes.c_char_p,                     # account
            ctypes.c_char_p,                     # password
            ctypes.c_int,                        # timeout_ms
            ctypes.POINTER(ctypes.c_int),        # srvType[] (out)
            ctypes.c_int,                        # reserved=0
            ctypes.POINTER(ctypes.c_int),        # nSend[] (out)
        ]

        av.avClientStop.restype  = ctypes.c_int
        av.avClientStop.argtypes = [ctypes.c_int]

        av.avSendIOCtrl.restype  = ctypes.c_int
        av.avSendIOCtrl.argtypes = [
            ctypes.c_int,    # nAVIndex
            ctypes.c_uint,   # nIOCtrlType
            ctypes.c_char_p, # cabIOCtrlData
            ctypes.c_int,    # nIOCtrlDataSize
        ]

        # FRAMEINFO_t — TUTK SDK v3.x layout (codec_id, flags, onlineNum,
        # frameSize, frameNo, timestamp). Adjust if your SDK version differs.
        class FrameInfo(ctypes.Structure):
            _fields_ = [
                ("codec_id",   ctypes.c_uint),
                ("flags",      ctypes.c_uint),
                ("onlineNum",  ctypes.c_uint),
                ("frameSize",  ctypes.c_uint),
                ("frameNo",    ctypes.c_uint),
                ("timestamp",  ctypes.c_uint),
            ]

        av.avRecvFrameData2.restype  = ctypes.c_int
        av.avRecvFrameData2.argtypes = [
            ctypes.c_int,                        # nAVIndex
            ctypes.c_char_p,                     # abFrameData
            ctypes.c_int,                        # nFrameDataMaxSize (by value)
            ctypes.POINTER(ctypes.c_int),        # pnActualFrameSize (out)
            ctypes.POINTER(ctypes.c_int),        # pnExpectedFrameSize (out)
            ctypes.c_char_p,                     # pFrameInfo (byte buffer)
            ctypes.c_int,                        # nFrameInfoBufSize (by value)
            ctypes.POINTER(ctypes.c_int),        # pnActualFrameInfoSize (out)
            ctypes.POINTER(ctypes.c_int),        # pnFrameIndex (out)
        ]

        # --- Initialize IOTC (idempotent) ----------------------------------- #
        # TutkManager.java: IOTC_Initialize2(0) then IOTC_Set_Max_Session_Number(10)
        # then avInitialize(32)
        ret = iotc.IOTC_Initialize2(0)
        if ret < 0:
            _LOGGER.debug("IOTC_Initialize2 returned %d (may already be initialized)", ret)
        else:
            iotc.IOTC_Set_Max_Session_Number(10)

        ret = av.avInitialize(32)
        if ret < 0:
            _LOGGER.debug("avInitialize returned %d (may already be initialized)", ret)

        # --- Connect P2P ---------------------------------------------------- #
        sid = iotc.IOTC_Get_SessionID()
        if sid < 0:
            _LOGGER.error("TUTK: IOTC_Get_SessionID failed: %d", sid)
            return False

        _LOGGER.debug("TUTK: connecting to uid=%s (sid=%d)", self._uid, sid)
        ret = iotc.IOTC_Connect_ByUID_Parallel(self._uid.encode(), sid)
        if ret < 0:
            _LOGGER.error(
                "TUTK: IOTC_Connect_ByUID_Parallel(%s) failed: %d",
                self._uid, ret,
            )
            return False
        self._sid = ret

        # --- Start AV client ------------------------------------------------ #
        # TutkManager.java: avClientStart2(nSID, account, pwd, 2000, srvType, 0, nSend)
        # Credentials: "admin" / "admin123" (hardcoded in TutkManager.java)
        srv_type = ctypes.c_int(0)
        n_send   = ctypes.c_int(0)
        av_index = av.avClientStart2(
            self._sid, b"admin", b"admin123", 2000,
            ctypes.byref(srv_type), 0, ctypes.byref(n_send))
        if av_index < 0:
            _LOGGER.error("TUTK: avClientStart2 failed: %d", av_index)
            iotc.IOTC_Session_Close(self._sid)
            self._sid = -1
            return False
        self._av_index = av_index

        # --- Send IOCtrl commands per TutkManager.java ---------------------- #
        # 1. IOTYPE_INNER_SND_DATA_DELAY (255) — 2-byte body
        av.avSendIOCtrl(self._av_index, self._IOTYPE_INNER_SND_DATA_DELAY,
                        (ctypes.c_uint8 * 2)(), 2)
        # 2. IOTYPE_USER_IPCAM_START (511) — 8-byte body (all zeros = default stream)
        av.avSendIOCtrl(self._av_index, self._IOTYPE_USER_IPCAM_START,
                        (ctypes.c_uint8 * 8)(), 8)
        # 3. IOTYPE_USER_IPCAM_AUDIOSTART (768) — 8-byte body
        av.avSendIOCtrl(self._av_index, self._IOTYPE_USER_IPCAM_AUDIOSTART,
                        (ctypes.c_uint8 * 8)(), 8)

        # --- Launch frame-receive thread ------------------------------------ #
        self._thread = threading.Thread(
            target=self._recv_loop,
            args=(av, iotc, FrameInfo),
            daemon=True,
            name=f"tutk-recv-{self._uid[:8]}",
        )
        self._thread.start()
        return True

    def _recv_loop(self, av, iotc, FrameInfo) -> None:
        import ctypes

        # avRecvFrameData2 signature (from AVAPIs.java / TUTK SDK):
        #   (nAVIndex, abFrameData, nFrameDataMaxSize,
        #    *pnActualFrameSize, *pnExpectedFrameSize,
        #    pFrameInfo, nFrameInfoBufSize,
        #    *pnActualFrameInfoSize, *pnFrameIndex)
        BUF_SIZE     = 131072   # 128 KB — matches TutkManager.VIDEO_BUF_SIZE (100000)
        frame_buf    = ctypes.create_string_buffer(BUF_SIZE)
        info_buf     = ctypes.create_string_buffer(ctypes.sizeof(FrameInfo))
        actual_sz    = ctypes.c_int(0)
        expected_sz  = ctypes.c_int(0)
        actual_info  = ctypes.c_int(0)
        frame_idx    = ctypes.c_int(0)

        _LOGGER.debug("TUTK: recv loop started (avIndex=%d)", self._av_index)

        while not self._stop_event.is_set():
            ret = av.avRecvFrameData2(
                self._av_index,
                frame_buf,
                BUF_SIZE,
                ctypes.byref(actual_sz),
                ctypes.byref(expected_sz),
                info_buf,
                ctypes.sizeof(FrameInfo),
                ctypes.byref(actual_info),
                ctypes.byref(frame_idx),
            )
            if ret == -20012:
                # AV_ER_DATA_NOREADY — no frame yet; brief sleep per TutkManager (2ms)
                time.sleep(0.002)
                continue
            if ret < 0:
                _LOGGER.error("TUTK: avRecvFrameData2 returned %d — stopping", ret)
                break

            raw      = bytes(frame_buf.raw[: actual_sz.value])
            fi       = FrameInfo.from_buffer_copy(info_buf)
            vf  = VideoFrame(
                frame_type   = fi.codec_id,
                audio_codec  = 0,
                timestamp    = fi.timestamp,
                is_key_frame = bool(fi.flags & 0x1),
                data         = raw,
            )
            try:
                self._on_frame(vf)
            except Exception as exc:
                _LOGGER.error("TUTK: on_frame callback raised: %s", exc)

        # Teardown
        if self._av_index >= 0:
            try:
                av.avClientStop(self._av_index)
            except Exception:
                pass
        if self._sid >= 0:
            try:
                iotc.IOTC_Session_Close(self._sid)
            except Exception:
                pass
        _LOGGER.debug("TUTK: recv loop exited")

    async def stop(self) -> None:
        """Signal the receive thread to stop and wait for it."""
        self._stop_event.set()
        if self._thread is not None:
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: self._thread.join(timeout=5.0)
            )


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
# WebRTCSession
#
# Manages a live WebRTC stream opened by DeviceClient.async_open_webrtc_stream.
# Call await session.stop() to tear down the peer connection and MQTT session.
# --------------------------------------------------------------------------- #

class WebRTCSession:
    """Active WebRTC live-stream session for a liveType=2 AiDot camera.

    Obtain via ``await DeviceClient.async_open_webrtc_stream(...)``.
    Call ``await session.stop()`` when done.
    """

    def __init__(
        self,
        *,
        pc: Any,
        outgoing_q: Any,
        mqtt_fut: Any,
        recorder: Any,
        track_tasks: list,
    ) -> None:
        self._pc          = pc
        self._outgoing_q  = outgoing_q
        self._mqtt_fut    = mqtt_fut
        self._recorder    = recorder
        self._track_tasks = track_tasks

    async def stop(self) -> None:
        """Tear down the stream: close peer connection and MQTT session."""
        for task in self._track_tasks:
            task.cancel()
        if self._recorder is not None:
            try:
                await self._recorder.stop()
            except Exception:
                pass
        # Send None sentinel to stop the MQTT session in its thread
        self._outgoing_q.put_nowait(None)
        await self._pc.close()
        try:
            await asyncio.wait_for(self._mqtt_fut, timeout=5.0)
        except Exception:
            pass


class SdesSession:
    """Active SDES-SRTP stream session managed by an ffmpeg subprocess.

    Obtain via ``await DeviceClient.async_open_webrtc_stream(...)`` when the
    camera uses SDES-SRTP (``isDTLS == '0'``).
    Call ``await session.stop()`` when done.
    """

    def __init__(
        self,
        *,
        proc,
        sdp_path: str,
        outgoing_q,
        mqtt_fut,
        audio_sock=None,
        video_sock=None,
    ) -> None:
        self._proc       = proc
        self._sdp_path   = sdp_path
        self._outgoing_q = outgoing_q
        self._mqtt_fut   = mqtt_fut
        self._audio_sock = audio_sock
        self._video_sock = video_sock

    async def stop(self) -> None:
        """Tear down the stream: terminate ffmpeg and stop MQTT."""
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except Exception:
            self._proc.kill()
        import os
        try:
            os.unlink(self._sdp_path)
        except Exception:
            pass
        for _sock in (self._audio_sock, self._video_sock):
            if _sock is not None:
                try:
                    _sock.close()
                except Exception:
                    pass
        self._outgoing_q.put_nowait(None)
        try:
            await asyncio.wait_for(self._mqtt_fut, timeout=5.0)
        except Exception:
            pass


async def _webrtc_consume_video(track: Any, on_frame: Callable) -> None:
    """Receive video frames from an aiortc VideoStreamTrack and call on_frame."""
    while True:
        try:
            frame = await track.recv()
            try:
                on_frame(frame)
            except Exception:
                pass
        except Exception:
            break


# --------------------------------------------------------------------------- #
# MQTT helpers (playback provisioning + live-stream discovery)
#
# Uses paho-mqtt with WebSocket transport.  The synchronous paho loop runs in
# a thread-pool executor so it never blocks the asyncio event loop.
# Threading primitives (threading.Event, queue.Queue) replace the complex
# asyncio Future/call_soon_threadsafe bridge that had VERSION2 ReasonCode
# compatibility issues.
# --------------------------------------------------------------------------- #

def _mqtt_session_sync(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    subscribe_topics: list,
    publish_items: list,
    duration: float,
    on_message=None,
    ws_path: str = "/mqtt",
    on_ready=None,
    outgoing_queue=None,
) -> tuple:
    """Synchronous paho MQTT session (runs in a thread executor).

    Returns (messages, status_dict) where:
      messages    = list of (topic, payload_str) tuples received
      status_dict = {"connected": bool, "rc": int, "rc_str": str,
                     "error": str|None, "log": [str, ...]}

    ws_path overrides the WebSocket endpoint path (default "/mqtt").
    Pass "" or "/" to try the root path.

    on_ready(status) — optional callback called after all subscribe/publish
    operations complete but before the receive loop starts.  If it blocks
    (e.g. waiting for user input) the paho background thread continues to
    buffer incoming messages.  The ``duration`` countdown starts only after
    on_ready returns, so use this hook to implement a "wait for ENTER before
    starting the capture window" pattern.
    """
    import paho.mqtt.client as _paho
    import ssl as _ssl
    import threading
    import queue as _queue
    from urllib.parse import urlparse

    parsed   = urlparse(mqtt_url)
    hostname = parsed.hostname or mqtt_url
    port     = parsed.port or (8443 if parsed.scheme in ("wss", "https") else 1883)
    tls      = parsed.scheme in ("wss", "https", "mqtts")
    # ws_path parameter takes priority; fall back to URL path then "/mqtt"
    path     = ws_path if ws_path is not None else (parsed.path or "/mqtt")
    if path == "":
        path = "/"

    msg_q   = _queue.Queue()
    conn_ev = threading.Event()
    status  = {"connected": False, "rc": None, "rc_str": "", "error": None, "log": []}

    # Build client — handle paho ≥2.0 (VERSION2) and <2.0
    try:
        client = _paho.Client(
            callback_api_version=_paho.CallbackAPIVersion.VERSION2,
            client_id=client_id,
            transport="websockets",
        )
    except AttributeError:
        client = _paho.Client(client_id=client_id, transport="websockets")

    client.ws_set_options(path=path)
    if mqtt_user:
        client.username_pw_set(mqtt_user, mqtt_pwd or "")
    if tls:
        ctx = _ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = _ssl.CERT_NONE
        client.tls_set_context(ctx)

    def _on_connect(c, ud, flags, reason_code, props=None):
        # paho ≥2 passes ReasonCode; paho <2 passes int
        try:
            rc = int(reason_code)
        except (TypeError, ValueError):
            rc = -1
        status["connected"] = (rc == 0)
        status["rc"]        = rc
        status["rc_str"]    = str(reason_code)
        conn_ev.set()

    def _on_message(c, ud, msg):
        payload = (msg.payload.decode("utf-8", errors="replace")
                   if isinstance(msg.payload, (bytes, bytearray))
                   else str(msg.payload))
        msg_q.put((msg.topic, payload))

    def _on_disconnect(c, ud, disconnect_flags=None, reason_code=None, props=None):
        # If _on_connect was never fired (WebSocket upgrade failed, auth refused
        # at TCP level, etc.) signal conn_ev now so the caller doesn't time out.
        if not conn_ev.is_set():
            status["connected"] = False
            status["rc_str"]    = f"disconnect-before-connect rc={reason_code}"
            conn_ev.set()
        msg_q.put(None)   # sentinel to unblock the receive loop

    def _on_log(c, ud, level, buf):
        status["log"].append(buf)
        _LOGGER.debug("paho: %s", buf)

    client.on_connect    = _on_connect
    client.on_message    = _on_message
    client.on_disconnect = _on_disconnect
    client.on_log        = _on_log

    import time as _time

    try:
        client.connect(hostname, port, keepalive=60)
    except Exception as exc:
        status["error"] = str(exc)
        _LOGGER.warning("_mqtt_session: connect() raised: %s", exc)
        return [], status

    client.loop_start()

    if not conn_ev.wait(timeout=15):
        status["error"] = f"connect timeout to {hostname}:{port}"
        _LOGGER.warning("_mqtt_session: %s", status["error"])
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
        return [], status

    if not status["connected"]:
        _LOGGER.warning(
            "_mqtt_session: broker refused rc=%s (%s) for %s:%d",
            status["rc"], status["rc_str"], hostname, port,
        )
        client.loop_stop()
        try:
            client.disconnect()
        except Exception:
            pass
        return [], status

    _LOGGER.info("_mqtt_session: connected to %s:%d clientId=%s", hostname, port, client_id)

    for topic in subscribe_topics:
        client.subscribe(topic)
        _LOGGER.debug("_mqtt_session: subscribed %s", topic)

    for pub_topic, pub_payload in publish_items:
        client.publish(pub_topic, pub_payload)
        _LOGGER.debug("_mqtt_session: published %s", pub_topic)

    if on_ready:
        try:
            on_ready(status)
        except Exception:
            pass

    collected = []
    deadline  = _time.monotonic() + duration
    while True:
        remaining = deadline - _time.monotonic()
        if remaining <= 0:
            break
        try:
            item = msg_q.get(timeout=min(remaining, 0.1))
        except _queue.Empty:
            # Drain outgoing publish queue
            if outgoing_queue is not None:
                while True:
                    try:
                        out = outgoing_queue.get_nowait()
                    except _queue.Empty:
                        break
                    if out is None:   # stop sentinel
                        client.loop_stop()
                        try:
                            client.disconnect()
                        except Exception:
                            pass
                        return collected, status
                    pub_topic, pub_payload = out
                    client.publish(pub_topic, pub_payload)
                    _LOGGER.debug("_mqtt_session: published %s", pub_topic)
            continue
        if item is None:   # disconnect sentinel
            break
        collected.append(item)
        if on_message:
            try:
                on_message(*item)
            except Exception:
                pass

    client.loop_stop()
    try:
        client.disconnect()
    except Exception:
        pass
    return collected, status


async def _mqtt_session(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    subscribe_topics: list,
    publish_items: list,
    duration: float,
    on_message=None,
    ws_path: str = "/mqtt",
    on_ready=None,
) -> list:
    """Async wrapper: runs _mqtt_session_sync in a thread executor.

    Returns list of (topic, payload_str) tuples.
    """
    import functools
    loop = asyncio.get_running_loop()
    fn = functools.partial(
        _mqtt_session_sync,
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics, publish_items, duration, on_message, ws_path, on_ready,
    )
    messages, status = await loop.run_in_executor(None, fn)
    if status.get("error"):
        _LOGGER.warning("_mqtt_session failed: %s", status["error"])
    return messages


async def _mqtt_session_with_status(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    subscribe_topics: list,
    publish_items: list,
    duration: float,
    on_message=None,
    ws_path: str = "/mqtt",
    on_ready=None,
) -> tuple:
    """Like _mqtt_session but also returns the status dict for diagnostics."""
    import functools
    loop = asyncio.get_running_loop()
    fn = functools.partial(
        _mqtt_session_sync,
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics, publish_items, duration, on_message, ws_path, on_ready,
    )
    return await loop.run_in_executor(None, fn)


async def _mqtt_get_playback_server_info(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    device_id: str,
    client_id: str,
    timeout: float = 15.0,
) -> Optional[dict]:
    """Publish getPlaybackServerInfoReq and return the payload dict, or None.

    MQTT topics from IConstants.java / MqttManage.java:
      publish : iot/v1/s/{userId}/{service}/{method}
      subscribe: iot/v1/cb/{deviceId}/#
    Response arrives on iot/v1/c/{userId}/PlayBack/getPlaybackServerInfoResp
    (or on the device callback topic).
    """
    user_id   = mqtt_user or "0"
    seq       = str(random.randint(100000, 999999))
    pub_topic = f"iot/v1/s/{user_id}/PlayBack/getPlaybackServerInfoReq"
    payload   = json.dumps({
        "method":  "getPlaybackServerInfoReq",
        "service": "PlayBack",
        "devId":   device_id,
        "srcAddr": f"0.{user_id}",
        "seq":     seq,
        "tst":     int(time.time() * 1000),
        "payload": {},
    })

    result_holder: list = []

    def _check(topic, raw):
        try:
            body   = json.loads(raw)
            method = body.get("method", "")
            if "PlaybackServerInfo" not in method and "getPlaybackServer" not in method:
                return
            pl = body.get("payload") or body.get("data") or {}
            if pl.get("serverIP") or pl.get("serverIp"):
                pl["serverIP"] = pl.get("serverIP") or pl.get("serverIp")
                result_holder.append(pl)
        except Exception:
            pass

    await _mqtt_session(
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics=[
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{user_id}/#",
        ],
        publish_items=[(pub_topic, payload)],
        duration=timeout,
        on_message=_check,
    )
    return result_holder[0] if result_holder else None


async def _mqtt_listen(
    mqtt_url: str,
    mqtt_user: str,
    mqtt_pwd: str,
    client_id: str,
    device_id: str,
    duration: float = 60.0,
    on_message=None,
) -> list:
    """Subscribe to all device/user MQTT topics and collect messages for *duration* seconds.

    Returns a list of (topic, payload_str) tuples.
    *on_message(topic, payload_str)* is called for each message as it arrives.
    """
    user_id = mqtt_user or "0"
    return await _mqtt_session(
        mqtt_url, mqtt_user, mqtt_pwd, client_id,
        subscribe_topics=[
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{user_id}/#",
            f"lds/v1/cb/{device_id}/#",
            f"lds/v1/c/{user_id}/#",
            f"iot/v1/s/{user_id}/#",
        ],
        publish_items=[],
        duration=duration,
        on_message=on_message,
    )


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

    @property
    def is_sdes_camera(self) -> bool:
        """True if the camera uses SDES-SRTP rather than DTLS-SRTP.

        Determined by ``properties.enableSdes`` in the device API response:
        ``'1'`` → SDES explicitly enabled → SDES path.
        anything else → DTLS-SRTP path (default).

        ``isDTLS: '0'`` is NOT used here — iOS app session captures confirm
        that cameras with ``isDTLS: '0'`` (e.g. LK.IPC.A000088) still respond
        with a full DTLS fingerprint answer.  ``enableSdes: '0'`` (the default)
        means SDES is disabled, so those cameras must use DTLS.
        """
        props = getattr(self, "_raw_device", {}).get("properties") or {}
        return str(props.get("enableSdes", "0")) == "1"

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

        # Raw device dict retained for transport-type detection (isDTLS field)
        self._raw_device: dict = device

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
            "active-language": "en_US",
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
                # Fall back to the regional MQTT broker URL known to work from
                # the AiDot web client: wss://{region}-mqtt.arnoo.com:8443/mqtt
                _LOGGER.warning(
                    "getServerUrlConfig returned no mqttServerUrl; "
                    "using regional fallback. body=%s", body
                )
                mqtt_host = f"wss://{self._region}-mqtt.arnoo.com:8443/mqtt"

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
                body_data = {"desc": desc_val} if desc_val is not None else {}
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.post(
                            f"{self._smarthome_base}/user/getUser",
                            headers=headers,
                            json=body_data,
                            timeout=aiohttp.ClientTimeout(total=10),
                        ) as resp:
                            body = await resp.json(content_type=None)

                    code = body.get("code")
                    data = body.get("data") or {}
                    _LOGGER.debug(
                        "_async_get_smarthome_auth POST /user/getUser desc=%r -> "
                        "code=%s  data_keys=%s",
                        desc_val, code,
                        list(data.keys()) if isinstance(data, dict) else data,
                    )

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
        # smarthome tenantId (integer 11 from /user/getUser) is different from
        # the AiDot platform tid ("0001IF").  Passing the AiDot tid causes a
        # server-side NumberFormatException (500).  Use the smarthome tenantId
        # if we fetched it; otherwise omit the field entirely.
        _smarthome_tenant_id = str(
            self._smarthome_auth.get("tenantId", "")
            if self._smarthome_auth else ""
        )
        _phone_id = (
            self._user_info.get("terminalIndex")
            or self._user_info.get("phoneId")
            or ""
        )
        last_body: dict = {}
        # The Android SDK uses Retrofit @QueryMap on POST (/deviceController/getP2pId etc.)
        # which appends params as URL query string, NOT as form body.  Try both styles:
        #   "qs"   = params= (URL query string)   <-- Retrofit @QueryMap pattern
        #   "form" = data=   (x-www-form-urlencoded body)
        #   "json" = json=   (application/json body)
        _login_styles = [
            ("qs",   lambda d: {"params": d}),
            ("form", lambda d: {"data":   d}),
            ("json", lambda d: {"json":   d}),
        ]
        async with aiohttp.ClientSession() as session:
            for app_id in (_LEEDARSON_APP_KEY, _AIDOT_APP_ID):
                for pwd_type, pwd_val in pwd_variants:
                    base_data = {
                        "userName":     username,
                        "passWord":     pwd_val,
                        "os":           "ios",
                        "terminalMark": "app",
                        "appId":        app_id,
                        "phoneId":      _phone_id,
                        "locationId":   self._region or "us",
                    }
                    if _smarthome_tenant_id:
                        base_data["tenantId"] = _smarthome_tenant_id
                    for style, make_kw in _login_styles:
                        try:
                            async with session.post(
                                f"{self._smarthome_base}/user/login",
                                headers=login_headers,
                                timeout=aiohttp.ClientTimeout(total=10),
                                **make_kw(base_data),
                            ) as resp:
                                last_body = await resp.json(content_type=None)

                            code = last_body.get("code")
                            _LOGGER.warning(
                                "_async_get_smarthome_auth /user/login style=%s appId=%s pwd=%s "
                                "-> code=%s: %s",
                                style, app_id, pwd_type, code, last_body.get("desc"),
                            )
                            print(f"    [/user/login] style={style} appId={app_id} pwd={pwd_type} "
                                  f"tenantId={_smarthome_tenant_id!r} -> code={code} "
                                  f"desc={last_body.get('desc')!r}")
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
                                    "mqttUser=%s style=%s appId=%s pwd=%s",
                                    mqtt_user, style, app_id, pwd_type,
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
                                "_async_get_smarthome_auth /user/login style=%s appId=%s pwd=%s: %s",
                                style, app_id, pwd_type, exc,
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

    @property
    def _aidot_v21_base(self) -> str:
        return f"https://prod-{self._region}-api.arnoo.com/v21"

    @property
    def _aidot_v32_base(self) -> str:
        return f"https://prod-{self._region}-api.arnoo.com/v32/api/ipc"

    def _aidot_headers(self) -> dict:
        # Auth headers for the AiDot platform API (prod-{region}-api.arnoo.com).
        # Matches AidotClient.async_session_get(): CONF_APP_ID="Appid", APP_ID,
        # CONF_TOKEN="Token", CONF_TERMINAL="Terminal" (see login_const.py/const.py).
        token = (self._user_info.get("accessToken")
                 or self._user_info.get("access_token") or "")
        return {
            "Appid":        "1383974540041977857",
            "Token":        token,
            "Terminal":     "app",
            "Content-Type": "application/json",
        }

    async def async_get_device_user_info(
        self,
        all_device_ids: Optional[List[str]] = None,
    ) -> Optional[dict]:
        """Fetch per-device user info from the AiDot v21 API.

        POST /v21/devices/batchGetDeviceUserInfo
        Returns the raw data dict for this device, or None on failure.
        This is the same call the AiDot widget/app makes; the response includes
        the TUTK p2pId and any per-device streaming credentials.

        Args:
            all_device_ids: All device IDs to include in the batch request.
                The app sends all device IDs in a single call (~260 bytes for
                7 devices). Sending only one ID may cause the server to return
                an empty result. Pass the full list from the account's device
                listing if available.
        """
        import aiohttp
        ids = all_device_ids or [self.device_id]
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self._aidot_v21_base}/devices/batchGetDeviceUserInfo",
                    json={"deviceIds": ids},
                    headers=self._aidot_headers(),
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    body = await resp.json(content_type=None)
                    status = resp.status

            # Store the raw response so callers can inspect it for diagnostics.
            self._last_batch_response = body

            # Server may return a bare JSON array OR {"data": [...]} / {"data": {}}
            if isinstance(body, list):
                data = body
                _LOGGER.debug("batchGetDeviceUserInfo bare-list response for %s: %d items",
                              self.device_id, len(data))
            elif isinstance(body, dict):
                data = body.get("data") or {}
                if data:
                    _LOGGER.debug("batchGetDeviceUserInfo response for %s (status=%d): %s",
                                  self.device_id, status, body)
                else:
                    _LOGGER.warning(
                        "batchGetDeviceUserInfo no data for %s (status=%d): %s",
                        self.device_id, status, body,
                    )
            else:
                data = {}

            # Find the entry for this device
            if isinstance(data, dict):
                return data.get(self.device_id) or next(iter(data.values()), None)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("deviceId") == self.device_id:
                        return item
                return data[0] if data else None
        except Exception as exc:
            _LOGGER.error("async_get_device_user_info failed for %s: %s",
                          self.device_id, exc)
        return None

    async def async_get_p2p_uid(self) -> Optional[str]:
        """Fetch the TUTK P2P UID for this camera.

        Tries two sources in order:
          1. POST /v21/devices/batchGetDeviceUserInfo  (AiDot platform API)
          2. POST /deviceController/getP2pId           (Leedarson smarthome API)
        """
        import aiohttp

        # --- Source 1: AiDot v21 batchGetDeviceUserInfo ---
        try:
            dev_info = await self.async_get_device_user_info()
            if isinstance(dev_info, dict):
                uid = (dev_info.get("p2pId")
                       or dev_info.get("uid")
                       or dev_info.get("tutk_uid")
                       or dev_info.get("tutkUid"))
                if uid:
                    _LOGGER.debug("async_get_p2p_uid: got UID from batchGetDeviceUserInfo: %s", uid)
                    return str(uid)
        except Exception as exc:
            _LOGGER.debug("async_get_p2p_uid: batchGetDeviceUserInfo failed: %s", exc)

        # --- Source 2: Leedarson smarthome /deviceController/getP2pId ---
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
                _LOGGER.debug("async_get_p2p_uid: got UID from getP2pId: %s", uid)
                return str(uid)
            _LOGGER.debug("async_get_p2p_uid: getP2pId returned no UID for %s. body=%s",
                          self.device_id, body)
        except Exception as exc:
            _LOGGER.debug("async_get_p2p_uid: smarthome call failed for %s: %s",
                          self.device_id, exc)

        # --- Source 3: AiDot v32 IPC device detail ---
        # Android app's NewLiveFragment.w5() parses a JSON string from the device
        # object to obtain the TUTK UID. The v32 IPC endpoint may return it directly.
        # Known paths from iOS HTTP traffic: /v32/api/ipc/devices/{id}
        for path in (
            f"/devices/{self.device_id}",
            f"/devices/{self.device_id}/info",
            f"/devices/{self.device_id}/detail",
        ):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        f"{self._aidot_v32_base}{path}",
                        headers=self._aidot_headers(),
                        timeout=aiohttp.ClientTimeout(total=10),
                    ) as resp:
                        body = await resp.json(content_type=None)

                data = body.get("data") or body if isinstance(body, dict) else {}
                uid = (data.get("p2pId") or data.get("tutkUid")
                       or data.get("tutk_uid") or data.get("uid")
                       or data.get("iotcUid") or data.get("p2pUID"))
                if uid:
                    _LOGGER.debug("async_get_p2p_uid: got UID from v32%s: %s", path, uid)
                    return str(uid)
                _LOGGER.debug("async_get_p2p_uid: v32%s returned no UID for %s. body=%s",
                              path, self.device_id, body)
                # If we got a 200-level response (not 404/405), don't try other paths
                break
            except Exception as exc:
                _LOGGER.debug("async_get_p2p_uid: v32%s failed for %s: %s",
                              path, self.device_id, exc)

        _LOGGER.warning(
            "async_get_p2p_uid: all three sources returned empty UID for %s",
            self.device_id,
        )
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
        client_id = (self._user_info.get("mqttClientId") or f"app-{mqtt_user}")

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
        timeout: float = 60.0,
    ) -> Optional[TutkStreamSession]:
        # Open a TUTK IOTC P2P live-stream session.
        # on_frame: called from the receive thread for each decoded VideoFrame.
        # Returns a running TutkStreamSession, or None on failure.
        #
        # Protocol: TUTK IOTC P2P (confirmed from classes.jar.decompiled.zip).
        #   p2pId (TUTK UID) ← POST /v21/devices/batchGetDeviceUserInfo
        #   IOTC_Connect_ByUID_Parallel(uid) → nSID
        #   avClientStart2(nSID, "admin", "admin123") → avIndex
        #   avSendIOCtrl(avIndex, 511, ...) → start video stream
        #   avRecvFrameData2(avIndex, ...) → frame loop
        #
        # Requires libIOTCAPIs.so + libAVAPIs.so from the TUTK SDK.

        uid = await self.async_get_p2p_uid()
        if not uid:
            _LOGGER.error(
                "async_open_live_stream: p2pId not available for %s. "
                "Ensure batchGetDeviceUserInfo returns data (check auth/request "
                "format) or that the smarthome getP2pId endpoint is reachable.",
                self.device_id,
            )
            return None

        _LOGGER.debug(
            "async_open_live_stream: TUTK P2P uid=%s for %s", uid, self.device_id)
        session = TutkStreamSession(uid=uid, on_frame=on_frame)
        try:
            ok = await asyncio.wait_for(session.start(), timeout=timeout)
        except asyncio.TimeoutError:
            _LOGGER.error(
                "async_open_live_stream: TUTK connect timed out after %.0fs for %s",
                timeout, self.device_id,
            )
            return None
        if not ok:
            return None

        _LOGGER.info(
            "TUTK live stream session open for %s (uid=%s)",
            self.device_id, uid,
        )
        return session

    async def async_get_ice_config(self, device_id: str) -> Optional[dict]:
        """Fetch STUN/TURN ICE server credentials for a liveType=2 camera.

        Publishes ``IPC/getIceConfigReq`` via MQTT and waits up to 5 s for the
        ``IPC/getIceConfigResp`` reply.  The response contains per-device and
        per-user TURN credentials for the Arnoo TURN cluster.

        Returns a dict with keys ``app`` (list of user-side ICE server entries)
        and ``dev`` (list of device-side ICE server entries), each entry having
        the shape::

            {"id": str, "token": int, "ttl": int,
             "uris": [...], "dnsUris": [...]}

        Returns ``None`` if the MQTT session fails or no response arrives.
        A fallback ICE config (public STUN only, no TURN credentials) can be
        constructed by the caller if ``None`` is returned.
        """
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        user_id   = str(self.user_id)
        # Use the server-assigned authorised clientId — the broker rejects
        # random or made-up prefixes with rc=4.
        diag_cid  = (
            self._user_info.get("mqttClientId") or
            f"app-{mqtt_user}"
        )
        mqtt_url  = await self._async_get_mqtt_url()
        if not mqtt_url:
            _LOGGER.warning("async_get_ice_config: no MQTT URL available")
            return None

        terminal_idx = self._user_info.get("terminalIndex") or diag_cid.split("-")[0]
        seq     = f"ap{random.randint(1000000, 9999999)}"
        result: dict = {}

        payload = json.dumps({
            "method":  "getIceConfigReq",
            "service": "IPC",
            "srcAddr": f"{terminal_idx}.{user_id}",
            "seq":     seq,
            "tst":     int(time.time() * 1000),
            "payload": {"deviceId": device_id, "userId": user_id},
        })

        def _capture(topic: str, raw: str) -> None:
            # Accept any message on the user callback topic that looks like
            # an ICE config response.
            if "iceconfig" in topic.lower() or "getice" in topic.lower():
                try:
                    msg = json.loads(raw)
                    inner = (msg.get("payload") or msg.get("data") or msg)
                    if isinstance(inner, dict) and ("app" in inner or "dev" in inner):
                        result["data"] = inner
                    elif isinstance(inner, dict):
                        result["data"] = msg
                except Exception:
                    result["data"] = raw

        await _mqtt_session(
            mqtt_url, mqtt_user, mqtt_pwd, diag_cid,
            subscribe_topics=[f"iot/v1/c/{user_id}/#"],
            publish_items=[(f"iot/v1/s/{user_id}/IPC/getIceConfigReq", payload)],
            duration=5.0,
            on_message=_capture,
        )

        if "data" not in result:
            _LOGGER.warning(
                "async_get_ice_config: no getIceConfigResp received for device %s; "
                "the device may not support MQTT ICE config (try after opening app live view)",
                device_id,
            )
        return result.get("data")

    @staticmethod
    def generate_webrtc_peer_id(
        live_type: int = 2, stream_id: int = 0, *, sdes: bool = False
    ) -> str:
        """Generate a peerId for a WebRTC connection.

        Format observed in iOS app telemetry:
        ``{32-hex-session}_{6-hex-random}_{liveType}_{streamId}_{version}``

        The trailing version digit encodes the signalling transport:
        ``1`` for SDES-SRTP cameras, ``2`` for DTLS-SRTP cameras.
        iOS app telemetry (2025-03-23) confirms: LK.IPC.A001513 (SDES,
        ``enableSdes: "1"``) uses ``_1`` and responds; LK.IPC.A000088 /
        LK.IPC.A001064 (DTLS, ``enableSdes: "0"``) use ``_2`` and respond.
        SDES cameras appear to silently discard webrtcReq with ``_2``.
        """
        import os
        session = os.urandom(16).hex()          # 32 hex chars
        rand6   = os.urandom(3).hex()           # 6 hex chars
        version = 1 if sdes else 2
        return f"{session}_{rand6}_{live_type}_{stream_id}_{version}"

    async def async_open_webrtc_stream(
        self,
        on_frame: Optional[Callable[["VideoFrame"], None]] = None,
        *,
        stream_id: int = 0,
        timeout: float = 30.0,
        output_path: Optional[str] = None,
        status_callback: Optional[Callable[[str], None]] = None,
        force_sdes: Optional[bool] = None,
    ) -> "WebRTCSession":
        """Open a liveType=2 WebRTC stream via MQTT signaling.

        Performs the full WebRTC handshake over MQTT, then delivers decoded
        video frames to ``on_frame`` (and/or records to ``output_path``).

        Supports both DTLS-SRTP cameras (aiortc path, peerid suffix ``_2``)
        and SDES-SRTP cameras (ffmpeg path, peerid suffix ``_1``).  The
        transport is auto-detected from ``self.is_sdes_camera`` unless
        overridden by ``force_sdes``.

        Protocol (confirmed from live MQTT capture, 2025-03 / 2026-03):
          1. Subscribe ``iot/v1/c/{userId}/#`` on the authorised MQTT clientId
          2. Publish to ``iot/v1/s/{userId}/IPC/getIceConfigReq`` (server-side wake)
             → wait 2 s for broker session init
          3. Publish to ``iot/v1/s/{userId}/IPC/livePlayReq`` (camera-side arm)
             → wait 0.5 s for camera WebRTC subsystem to arm
          4. Create peer connection (aiortc or SDES SDP), add recvonly tracks
          5. Generate SDP offer → publish to ``iot/v1/s/{userId}/IPC/webrtcReq``
          6. Receive ``IPC/webrtcResp`` on ``iot/v1/c/{userId}/#`` → set remote description
          7. Exchange ICE candidates on ``iot/v1/s/{userId}/IPC/iceCandidateReq``
          8. Receive media tracks → call ``on_frame`` for each VideoFrame

        Topic routing: ALL IPC publish messages (getIceConfigReq, livePlayReq,
        webrtcReq, iceCandidateReq) go to ``iot/v1/s/{userId}/IPC/...``.
        The broker routes to the specific camera using the ``devId`` field in
        the JSON payload, NOT based on the MQTT topic path.  Confirmed from
        iOS app telemetry (2025-03-23): explicit publish logs show userId in
        the topic for iceCandidateReq and livePlayReq.

        Parameters
        ----------
        on_frame : callable or None
            Called with each ``av.VideoFrame`` from the camera (DTLS path only).
        stream_id : int
            Stream index: 0 = main stream, 1 = sub-stream.
        timeout : float
            Seconds to wait for ICE connection before raising RuntimeError.
        output_path : str or None
            Record the stream to this file (e.g. ``/tmp/live.ts``) via
            aiortc MediaRecorder (DTLS) or ffmpeg (SDES).  Supports any
            container ffmpeg can write; ``.ts`` is streamable via vlc/ffplay.
        force_sdes : bool or None
            Override transport auto-detection.  ``True`` → SDES path,
            ``False`` → DTLS path, ``None`` → auto (uses ``is_sdes_camera``).

        Returns
        -------
        WebRTCSession or SdesSession
            Call ``await session.stop()`` to close the stream.

        Raises
        ------
        ImportError
            If ``aiortc`` is not installed (DTLS path only).
            (``pip install python-aidot[webrtc]``).
        RuntimeError
            If the MQTT connection fails or ICE does not complete within
            ``timeout`` seconds.
        """
        import queue as _q_mod

        use_sdes = force_sdes if force_sdes is not None else self.is_sdes_camera

        if not use_sdes:
            try:
                from aiortc import RTCPeerConnection, RTCSessionDescription
                from aiortc.sdp import candidate_from_sdp
            except ImportError:
                raise ImportError(
                    "aiortc is required for WebRTC streaming. "
                    "Install with: pip install python-aidot[webrtc]"
                )

        # ------------------------------------------------------------------ #
        # Credentials + MQTT setup
        # ------------------------------------------------------------------ #
        smarthome_auth = await self._async_get_smarthome_auth()
        mqtt_user = (smarthome_auth or {}).get("mqttUser") or str(self.user_id)
        mqtt_pwd  = (smarthome_auth or {}).get("mqttPassword") or ""
        user_id   = str(self.user_id)
        mqtt_cid  = (
            self._user_info.get("mqttClientId") or
            (self._user_info.get("_userConfigRaw") or {}).get("mqtt", {}).get("clientId") or
            f"app-{mqtt_user}"
        )
        # terminalIndex is the session prefix of mqtt_cid (e.g. "1i1h3m" from "1i1h3m-{userId}").
        # The camera validates srcAddr against active MQTT sessions; "0.{userId}" matches nothing.
        terminal_idx = (
            mqtt_cid.split('-')[0]
            if '-' in mqtt_cid
            else (self._user_info.get("terminalIndex") or "0")
        )
        mqtt_url = await self._async_get_mqtt_url()
        if not mqtt_url:
            raise RuntimeError("async_open_webrtc_stream: no MQTT URL available")

        device_id = self.device_id
        peer_id   = self.generate_webrtc_peer_id(
            live_type=2, stream_id=stream_id, sdes=use_sdes
        )
        loop      = asyncio.get_running_loop()

        sub_topics       = [
            f"iot/v1/c/{user_id}/#",
            f"iot/v1/cb/{device_id}/#",
            f"iot/v1/c/{device_id}/#",   # catch webrtcResp routed to device channel
        ]
        # iOS app telemetry (2025-03-23) confirms ALL IPC publish topics use
        # the userId path.  The broker routes to the specific camera using the
        # ``devId`` field inside the JSON payload, NOT the MQTT topic path.
        webrtc_req_topic = f"iot/v1/s/{user_id}/IPC/webrtcReq"
        ice_cand_topic   = f"iot/v1/s/{user_id}/IPC/iceCandidateReq"
        live_play_topic  = f"iot/v1/s/{user_id}/IPC/livePlayReq"

        # ------------------------------------------------------------------ #
        # MQTT ↔ asyncio bridge
        # ------------------------------------------------------------------ #
        outgoing_q:   _q_mod.Queue      = _q_mod.Queue()
        answer_fut:      asyncio.Future    = loop.create_future()
        ice_q:           asyncio.Queue     = asyncio.Queue()
        camera_ready_ev: asyncio.Event     = asyncio.Event()  # set when camera is on MQTT

        # Gate: block asyncio until MQTT is connected + subscribed
        import threading as _threading
        _mqtt_ready_ev     = _threading.Event()
        _mqtt_conn_status: dict = {}

        def _status(msg: str) -> None:
            """Fire status_callback (if provided) and log at INFO level."""
            if status_callback:
                status_callback(msg)
            _LOGGER.info("webrtc: %s", msg)

        def _on_mqtt_ready(st: dict) -> None:
            _mqtt_conn_status.update(st)
            _mqtt_ready_ev.set()

        def _on_mqtt_message(topic: str, payload_str: str) -> None:
            _LOGGER.info("webrtc rx  topic=%s  %.400s", topic, payload_str)
            try:
                msg = json.loads(payload_str)
            except Exception:
                loop.call_soon_threadsafe(
                    lambda t=topic, p=payload_str: _status(
                        f"camera raw (non-JSON)  topic={t}  data={p[:200]!r}"
                    )
                )
                return
            method = msg.get("method") or ""
            inner  = msg.get("payload") or {}
            # Fire camera_ready_ev the moment the camera appears on MQTT — either via its
            # explicit wake-ACK (lowPowerActiveStateResp) or any message on the device channel.
            if method == "lowPowerActiveStateResp" or topic.startswith(f"iot/v1/c/{device_id}/"):
                loop.call_soon_threadsafe(camera_ready_ev.set)
            if method == "webrtcResp":
                resp_pid = inner.get("peerid")
                if resp_pid != peer_id:
                    loop.call_soon_threadsafe(
                        lambda rp=resp_pid: _status(
                            f"webrtcResp IGNORED — peerid mismatch:"
                            f" got {rp!r}"
                            f" expected ...{peer_id[-12:]}"
                        )
                    )
                    return
                answer = inner.get("offer") or inner.get("answer") or {}
                if answer.get("sdp") and not answer_fut.done():
                    loop.call_soon_threadsafe(answer_fut.set_result, answer)
            elif method == "iceCandidateReq":
                if inner.get("peerid") != peer_id:
                    return   # high-volume; suppress status noise for ICE mismatches
                cand = inner.get("candidate") or {}
                if cand.get("candidate"):
                    loop.call_soon_threadsafe(ice_q.put_nowait, cand)
            else:
                loop.call_soon_threadsafe(
                    lambda m=method, p=inner, t=topic: _status(
                        f"camera replied  topic={t}  method={m!r}  payload={p!r}"
                    )
                )

        # Run MQTT in a thread executor (very long duration; stopped via
        # outgoing_q sentinel when the caller calls WebRTCSession.stop()).
        mqtt_fut = loop.run_in_executor(
            None,
            lambda: _mqtt_session_sync(
                mqtt_url, mqtt_user, mqtt_pwd, mqtt_cid,
                sub_topics, [], 3600.0, _on_mqtt_message,
                "/mqtt", _on_mqtt_ready, outgoing_q,
            ),
        )

        # Wait for MQTT to be connected and subscribed before proceeding.
        # threading.Event.wait(timeout) returns True if set, False on timeout.
        mqtt_ok = await loop.run_in_executor(
            None, lambda: _mqtt_ready_ev.wait(timeout=15.0)
        )
        if not mqtt_ok or not _mqtt_conn_status.get("connected"):
            outgoing_q.put_nowait(None)   # stop MQTT thread
            _err = (
                _mqtt_conn_status.get("error")
                or _mqtt_conn_status.get("rc_str")
                or f"rc={_mqtt_conn_status.get('rc')}"
            )
            raise RuntimeError(
                f"async_open_webrtc_stream: MQTT connection failed: {_err}"
            )
        _status(f"MQTT connected (clientId={mqtt_cid})")

        # ------------------------------------------------------------------ #
        # Send getIceConfigReq first — this warms up the broker-side WebRTC
        # session and registers the camera routing so the subsequent webrtcReq
        # is forwarded to the device.  iOS app telemetry confirms getIceConfigReq
        # is always sent before webrtcReq.  Without this step the broker echoes
        # webrtcReq back to us but never routes it to the camera.
        # ------------------------------------------------------------------ #
        _ice_req_payload = json.dumps({
            "method":  "getIceConfigReq",
            "service": "IPC",
            "srcAddr": f"{terminal_idx}.{user_id}",
            "seq":     f"ap{random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            "payload": {"deviceId": device_id, "userId": user_id},
        })
        outgoing_q.put_nowait(
            (f"iot/v1/s/{user_id}/IPC/getIceConfigReq", _ice_req_payload)
        )
        _status("getIceConfigReq sent — waiting for camera to wake (up to 12s)")
        try:
            await asyncio.wait_for(camera_ready_ev.wait(), timeout=12.0)
            _status("Camera awake — got MQTT signal")
        except asyncio.TimeoutError:
            _status("Camera wake timeout — proceeding anyway (may already be active)")

        # ------------------------------------------------------------------ #
        # Send livePlayReq BEFORE the SDP offer.  iOS app telemetry confirms
        # this message is always sent first to arm the camera's WebRTC
        # subsystem; the camera silently ignores webrtcReq without it.
        # ------------------------------------------------------------------ #
        _live_req_payload = json.dumps({
            "method":  "livePlayReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"{terminal_idx}.{user_id}",
            "seq":     f"ap{random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            "payload": {
                "peerid":  peer_id,
                "devId":   device_id,
                "dstAddr": user_id,
            },
        })
        outgoing_q.put_nowait((live_play_topic, _live_req_payload))
        _status(f"livePlayReq sent  peerid={peer_id}")
        await asyncio.sleep(0.5)

        # ------------------------------------------------------------------ #
        # Branch: SDES-SRTP cameras use ffmpeg; DTLS cameras use aiortc
        # ------------------------------------------------------------------ #
        if use_sdes:
            return await self._open_sdes_stream(
                peer_id=peer_id,
                user_id=user_id,
                device_id=device_id,
                terminal_idx=terminal_idx,
                outgoing_q=outgoing_q,
                answer_fut=answer_fut,
                loop=loop,
                timeout=timeout,
                output_path=output_path,
                _status=_status,
                mqtt_fut=mqtt_fut,
            )

        # ------------------------------------------------------------------ #
        # aiortc peer connection (DTLS-SRTP path)
        # ------------------------------------------------------------------ #
        from aiortc import RTCConfiguration, RTCIceServer
        pc = RTCPeerConnection(
            configuration=RTCConfiguration(
                iceServers=[RTCIceServer(urls=["stun:stun.l.google.com:19302"])]
            )
        )
        pc.addTransceiver("audio", direction="recvonly")   # mid:0  audio
        pc.addTransceiver("video", direction="recvonly")   # mid:1  H264 (primary video)
        pc.addTransceiver("video", direction="recvonly")   # mid:2  H265 (camera firmware always sends both)
        pc.createDataChannel("data")                        # mid:3  SCTP datachannel
        # Live capture confirms AiDot cameras (LK.IPC.A000088 and others) answer
        # with a 4-section SDP: audio + H264-video + H265-video + application/SCTP.
        # The offer must have the same number of m-sections or aiortc's
        # setRemoteDescription will reject the answer.

        track_tasks: list = []

        @pc.on("track")
        def _on_track(track) -> None:
            if track.kind == "video" and on_frame is not None:
                t = asyncio.ensure_future(_webrtc_consume_video(track, on_frame))
                track_tasks.append(t)

        recorder = None
        if output_path:
            try:
                from aiortc.contrib.media import MediaRecorder
                recorder = MediaRecorder(output_path)

                _video_recorded = [False]

                @pc.on("track")
                def _on_track_rec(track) -> None:
                    if track.kind == "video":
                        if not _video_recorded[0]:
                            recorder.addTrack(track)
                            _video_recorded[0] = True
                    else:
                        recorder.addTrack(track)
            except Exception as exc:
                _LOGGER.warning(
                    "async_open_webrtc_stream: MediaRecorder not available: %s", exc
                )

        # ------------------------------------------------------------------ #
        # Create SDP offer and publish webrtcReq
        # ------------------------------------------------------------------ #
        offer = await pc.createOffer()
        await pc.setLocalDescription(offer)
        _LOGGER.debug(
            "webrtc: SDP offer (first 500 chars):\n%s",
            pc.localDescription.sdp[:500],
        )

        def _sdp_transport(sdp: str, kind: str) -> str:
            for line in sdp.splitlines():
                if line.startswith(f"m={kind} "):
                    parts = line.split()
                    return parts[2] if len(parts) > 2 else "?"
            return "absent"

        _sdp = pc.localDescription.sdp
        _status(
            f"SDP offer  m=video={_sdp_transport(_sdp, 'video')}"
            f"  m=audio={_sdp_transport(_sdp, 'audio')}"
        )
        _mlines = [ln for ln in _sdp.splitlines() if ln.startswith("m=")]
        _status("SDP m-sections (%d): %s" % (len(_mlines), " | ".join(_mlines)))

        def _seq() -> str:
            return f"ap{random.randint(1000000, 9999999)}"

        def _upgrade_sctp(sdp: str) -> str:
            """Convert aiortc pre-RFC-8841 SCTP section to RFC 8841 format.

            aiortc generates the legacy format:
                m=application PORT DTLS/SCTP 5000
                a=sctpmap:5000 webrtc-datachannel 65535
                a=max-message-size:65536

            Cameras (and modern browsers) expect RFC 8841:
                m=application 9 UDP/DTLS/SCTP webrtc-datachannel
                a=sctp-port:5000
            """
            import re as _re
            out = []
            for line in _re.split(r'\r?\n', sdp):
                if _re.match(r'^m=application \d+ DTLS/SCTP \d+$', line):
                    out.append('m=application 9 UDP/DTLS/SCTP webrtc-datachannel')
                elif line.startswith('a=sctpmap:'):
                    out.append('a=sctp-port:5000')
                elif line.startswith('a=max-message-size:'):
                    pass   # not used in RFC 8841
                else:
                    out.append(line)
            return '\r\n'.join(out)

        def _patch_offer_mid2_h265(sdp: str) -> str:
            """Replace mid:2 video codecs with H265-only (PT 96).

            aiortc cannot offer H265 natively, so it generates H264+VP8 for
            every video transceiver.  Cameras with liveType=2 require H265 to
            appear in the offer for mid:2 before they will respond with
            webrtcResp.  This function rewrites the mid:2 m-section in-place:

              m=video PORT PROTO 96
              a=mid:2
              a=recvonly          ← kept
              a=rtcp-mux          ← kept
              a=ice-*/a=fingerprint/a=setup/a=extmap  ← kept
              a=rtpmap:96 H265/90000      ← injected
              (all H264/VP8 rtpmap/fmtp/ssrc lines removed)
            """
            import re as _re
            lines = _re.split(r'\r?\n', sdp)
            # Split into sections: list of (m_line_index, [lines]) for each m-section
            sections: list[list[str]] = []
            current: list[str] = []
            for ln in lines:
                if ln.startswith('m=') and current:
                    sections.append(current)
                    current = [ln]
                else:
                    current.append(ln)
            if current:
                sections.append(current)

            result: list[str] = []
            for sec in sections:
                if not any(a.rstrip() == 'a=mid:2' for a in sec):
                    result.extend(sec)
                    continue
                # This is mid:2 — patch it
                new_sec: list[str] = []
                mid2_inserted = False
                for ln in sec:
                    if ln.startswith('m=video '):
                        # Replace codec list with single PT 96
                        parts = ln.split()
                        # parts: ['m=video', port, proto, pt1, pt2, ...]
                        new_sec.append(' '.join(parts[:3]) + ' 96')
                    elif (ln.startswith('a=rtpmap:') or
                          ln.startswith('a=fmtp:') or
                          ln.startswith('a=ssrc:') or
                          ln.startswith('a=ssrc-group:') or
                          ln.startswith('a=rtcp-fb:')):
                        pass  # drop all codec/SSRC/RTCP-FB lines
                    else:
                        new_sec.append(ln)
                        if ln.rstrip() == 'a=mid:2' and not mid2_inserted:
                            new_sec.append('a=rtpmap:96 H265/90000')
                            mid2_inserted = True
                if not mid2_inserted:
                    # fallback: append at end of section
                    new_sec.append('a=rtpmap:96 H265/90000')
                result.extend(new_sec)
            return '\r\n'.join(result)

        def _normalize_bundle_ice_credentials(sdp: str) -> str:
            """Unify all m-section ICE credentials to match the BUNDLE master (mid:0).

            RFC 8843 §7.1.3 requires all bundled m-sections to carry the same
            ice-ufrag and ice-pwd.  aiortc generates a separate ICETransport per
            transceiver, giving each a unique credential pair.  Cameras that
            validate this requirement silently reject offers with mismatched
            credentials.  We overwrite every m-section's credentials with those
            of the first m-section (the BUNDLE master, mid:0).

            This is safe because: after BUNDLE negotiation succeeds, aiortc uses
            only mid:0's ICETransport for all media; the camera's ICE checks go
            exclusively to mid:0, whose credentials remain unchanged.
            """
            import re as _re
            lines = _re.split(r'\r?\n', sdp)
            master_ufrag: str | None = None
            master_pwd:   str | None = None
            in_msection = False
            for ln in lines:
                if ln.startswith('m='):
                    in_msection = True
                if in_msection:
                    if ln.startswith('a=ice-ufrag:') and master_ufrag is None:
                        master_ufrag = ln
                    if ln.startswith('a=ice-pwd:') and master_pwd is None:
                        master_pwd = ln
                if master_ufrag and master_pwd:
                    break
            if not (master_ufrag and master_pwd):
                return sdp   # no ICE credentials found; leave SDP unchanged
            result = []
            for ln in lines:
                if ln.startswith('a=ice-ufrag:'):
                    result.append(master_ufrag)
                elif ln.startswith('a=ice-pwd:'):
                    result.append(master_pwd)
                else:
                    result.append(ln)
            return '\r\n'.join(result)

        _offer_sdp = _normalize_bundle_ice_credentials(
            _patch_offer_mid2_h265(_upgrade_sctp(pc.localDescription.sdp))
        )
        _patched_mlines = [ln for ln in _offer_sdp.splitlines() if ln.startswith("m=")]
        _status("Offer m-sections (patched): %s" % " | ".join(_patched_mlines))

        webrtc_req_payload = json.dumps({
            "method":  "webrtcReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"{terminal_idx}.{user_id}",
            "seq":     _seq(),
            "tst":     int(time.time() * 1000),
            "payload": {
                "peerid":  peer_id,
                "devId":   device_id,
                "offer":   {"type": pc.localDescription.type,
                             "sdp":  _offer_sdp},
                "trackId": 0,
                "dstAddr": user_id,
            },
        })
        outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
        _status(f"webrtcReq sent  peerid={peer_id}")

        # Forward our own ICE candidates to the camera via MQTT
        @pc.on("icecandidate")
        def _on_local_ice(candidate) -> None:
            if candidate is None:
                return
            cand_str = (
                f"candidate:{candidate.foundation} {candidate.component} "
                f"{candidate.protocol} {candidate.priority} {candidate.ip} "
                f"{candidate.port} typ {candidate.type}"
            )
            if getattr(candidate, "relatedAddress", None):
                cand_str += (
                    f" raddr {candidate.relatedAddress}"
                    f" rport {candidate.relatedPort}"
                )
            payload = json.dumps({
                "method":  "iceCandidateReq",
                "service": "IPC",
                "devId":   device_id,
                "srcAddr": f"{terminal_idx}.{user_id}",
                "seq":     _seq(),
                "tst":     int(time.time() * 1000),
                "payload": {
                    "peerid":    peer_id,
                    "devId":     device_id,
                    "candidate": {"candidate": cand_str},
                    "dstAddr":   user_id,
                },
            })
            outgoing_q.put_nowait((ice_cand_topic, payload))

        # ------------------------------------------------------------------ #
        # Wait for SDP answer from camera
        # ------------------------------------------------------------------ #
        try:
            answer = await asyncio.wait_for(answer_fut, timeout=timeout)
        except asyncio.TimeoutError:
            _status(f"no webrtcResp in {timeout}s")
            outgoing_q.put_nowait(None)
            await pc.close()
            raise RuntimeError(
                f"async_open_webrtc_stream: no webrtcResp received within {timeout}s"
            )

        _ans_sdp = answer["sdp"]
        _ans_mlines = [ln for ln in _ans_sdp.splitlines() if ln.startswith("m=")]
        _status(
            f"webrtcResp received — m=video={_sdp_transport(_ans_sdp, 'video')}"
            f"  m=audio={_sdp_transport(_ans_sdp, 'audio')}"
        )
        _status("Answer m-sections (%d): %s" % (len(_ans_mlines), " | ".join(_ans_mlines)))

        def _patch_answer_mid2_for_aiortc(sdp: str) -> str:
            """Make the camera's H265 answer digestible by aiortc.

            The camera answers mid:2 with `a=rtpmap:96 H265/90000`.  aiortc
            doesn't know H265 so setRemoteDescription would raise.  Swapping
            the rtpmap to H264 lets aiortc accept the answer; the actual RTP
            payload type (96) remains unchanged so the ICE/DTLS path works.
            Mid:2 video will be undecoded but we only record mid:1 anyway.
            """
            import re as _re
            lines = _re.split(r'\r?\n', sdp)
            sections: list[list[str]] = []
            current: list[str] = []
            for ln in lines:
                if ln.startswith('m=') and current:
                    sections.append(current)
                    current = [ln]
                else:
                    current.append(ln)
            if current:
                sections.append(current)

            result: list[str] = []
            for sec in sections:
                if not any(a.rstrip() == 'a=mid:2' for a in sec):
                    result.extend(sec)
                    continue
                new_sec = []
                for ln in sec:
                    if _re.match(r'^a=rtpmap:96 H265/', ln):
                        new_sec.append('a=rtpmap:96 H264/90000')
                    else:
                        new_sec.append(ln)
                result.extend(new_sec)
            return '\r\n'.join(result)

        _ans_sdp_aiortc = _patch_answer_mid2_for_aiortc(_ans_sdp)
        try:
            await pc.setRemoteDescription(
                RTCSessionDescription(
                    sdp=_ans_sdp_aiortc,
                    type=answer.get("type", "answer"),
                )
            )
        except Exception as exc:
            _status(f"setRemoteDescription failed: {exc}")
            outgoing_q.put_nowait(None)
            await pc.close()
            raise RuntimeError(
                f"async_open_webrtc_stream: setRemoteDescription failed: {exc}"
            ) from exc

        # ------------------------------------------------------------------ #
        # Apply remote ICE candidates + wait for ICE connection
        # ------------------------------------------------------------------ #
        connected_ev = asyncio.Event()

        @pc.on("connectionstatechange")
        async def _on_conn_state() -> None:
            _LOGGER.debug("WebRTC connectionState: %s", pc.connectionState)
            if pc.connectionState in ("connected", "completed"):
                connected_ev.set()
            elif pc.connectionState in ("failed", "closed"):
                connected_ev.set()   # unblock the wait; session will detect failure

        deadline = time.monotonic() + timeout
        while not connected_ev.is_set() and time.monotonic() < deadline:
            # Drain incoming ICE candidates from the camera
            while True:
                try:
                    cand_dict = ice_q.get_nowait()
                except asyncio.QueueEmpty:
                    break
                cand_line = cand_dict.get("candidate", "")
                if cand_line.startswith("candidate:"):
                    cand_line = cand_line[len("candidate:"):]
                # Strip non-standard trailing extensions (generation, network-cost)
                # that aioice's candidate_from_sdp cannot parse.
                import re as _re
                cand_line = _re.sub(r'\s+generation\s+\d+.*$', '', cand_line).strip()
                try:
                    ice_cand = candidate_from_sdp(cand_line)
                    await pc.addIceCandidate(ice_cand)
                except Exception as exc:
                    _LOGGER.debug(
                        "async_open_webrtc_stream: addIceCandidate error: %s", exc
                    )
            await asyncio.sleep(0.1)

        if pc.connectionState not in ("connected", "completed"):
            outgoing_q.put_nowait(None)
            await pc.close()
            raise RuntimeError(
                f"async_open_webrtc_stream: ICE connection not established "
                f"(state={pc.connectionState}) within {timeout}s"
            )

        if recorder:
            await recorder.start()

        _LOGGER.info(
            "WebRTC stream open for %s (peerid=%s)", device_id, peer_id
        )
        return WebRTCSession(
            pc=pc,
            outgoing_q=outgoing_q,
            mqtt_fut=mqtt_fut,
            recorder=recorder,
            track_tasks=track_tasks,
        )

    # Keep old name as alias
    async_open_kvs_stream = async_open_webrtc_stream

    # ------------------------------------------------------------------ #
    # SDES-SRTP streaming path (cameras with isDTLS == '0')
    # ------------------------------------------------------------------ #

    async def _open_sdes_stream(
        self,
        *,
        peer_id: str,
        user_id: str,
        device_id: str,
        terminal_idx: str,
        outgoing_q,
        answer_fut,
        loop,
        timeout: float,
        output_path: Optional[str],
        _status,
        mqtt_fut,
    ) -> "SdesSession":
        """SDES-SRTP streaming path using a hand-crafted SDP offer and ffmpeg.

        SDES cameras negotiate SRTP keys inline in the SDP (``a=crypto:`` lines)
        rather than via a DTLS handshake.  aiortc does not support SDES-SRTP, so
        this path sends a manually constructed SDP offer, waits for the camera's
        SDP answer, writes it to a temp file, and launches ffmpeg to receive and
        record the SRTP stream.
        """
        import base64
        import os
        import subprocess
        import tempfile
        import json

        smarthome_auth = await self._async_get_smarthome_auth()
        user_id = user_id or str(self.user_id)

        webrtc_req_topic = f"iot/v1/s/{user_id}/IPC/webrtcReq"

        def _seq() -> str:
            import random
            return f"ap{random.randint(1000000, 9999999)}"

        # --- Allocate UDP ports and determine local IP ---------------------- #
        import socket as _socket

        _audio_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _audio_sock.bind(("0.0.0.0", 0))
        audio_port = _audio_sock.getsockname()[1]

        _video_sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
        _video_sock.bind(("0.0.0.0", 0))
        video_port = _video_sock.getsockname()[1]

        # Use the outbound interface toward 8.8.8.8 to find our local IP.
        # connect() on a UDP socket does not send any packet.
        with _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM) as _s:
            _s.connect(("8.8.8.8", 80))
            local_ip = _s.getsockname()[0]

        # --- Build SDES SDP offer ------------------------------------------ #
        # AES_CM_128_HMAC_SHA1_80: 16-byte key + 14-byte salt = 30 bytes.
        srtp_key_audio = base64.b64encode(os.urandom(30)).decode()
        srtp_key_video = base64.b64encode(os.urandom(30)).decode()
        # ICE credentials — included for RFC compliance; no STUN checks done.
        ufrag = base64.b64encode(os.urandom(3)).decode()[:4]
        pwd   = base64.b64encode(os.urandom(18)).decode()[:24]
        ts = int(time.time())
        sdes_offer_sdp = (
            "v=0\r\n"
            f"o=- {ts} {ts} IN IP4 {local_ip}\r\n"
            "s=-\r\n"
            "t=0 0\r\n"
            "a=group:BUNDLE 0 1\r\n"
            f"a=ice-ufrag:{ufrag}\r\n"
            f"a=ice-pwd:{pwd}\r\n"
            f"m=audio {audio_port} RTP/SAVPF 0 8\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "a=mid:0\r\n"
            "a=recvonly\r\n"
            "a=rtcp-mux\r\n"
            f"a=ice-ufrag:{ufrag}\r\n"
            f"a=ice-pwd:{pwd}\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            f"a=candidate:1 1 UDP 2130706431 {local_ip} {audio_port} typ host\r\n"
            "a=end-of-candidates\r\n"
            f"m=video {video_port} RTP/SAVPF 96 97\r\n"
            f"c=IN IP4 {local_ip}\r\n"
            "a=mid:1\r\n"
            "a=recvonly\r\n"
            "a=rtcp-mux\r\n"
            f"a=ice-ufrag:{ufrag}\r\n"
            f"a=ice-pwd:{pwd}\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
            "a=rtpmap:97 H265/90000\r\n"
            f"a=candidate:1 1 UDP 2130706431 {local_ip} {video_port} typ host\r\n"
            "a=end-of-candidates\r\n"
        )

        _status(
            f"SDP offer (SDES)  local={local_ip}"
            f"  audio={audio_port}  video={video_port}"
        )

        # Send livePlayReq before the SDP offer to arm the camera's stream.
        import random as _random
        _live_req_sdes = json.dumps({
            "method":  "livePlayReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"{terminal_idx}.{user_id}",
            "seq":     f"ap{_random.randint(1000000, 9999999)}",
            "tst":     int(time.time() * 1000),
            "payload": {
                "peerid":  peer_id,
                "devId":   device_id,
                "dstAddr": user_id,
            },
        })
        _live_play_topic_sdes = f"iot/v1/s/{user_id}/IPC/livePlayReq"
        outgoing_q.put_nowait((_live_play_topic_sdes, _live_req_sdes))
        _status(f"livePlayReq sent (SDES)  peerid={peer_id}")
        import asyncio as _asyncio
        await _asyncio.sleep(0.5)

        webrtc_req_payload = json.dumps({
            "method":  "webrtcReq",
            "service": "IPC",
            "devId":   device_id,
            "srcAddr": f"{terminal_idx}.{user_id}",
            "seq":     _seq(),
            "tst":     int(time.time() * 1000),
            "payload": {
                "peerid":  peer_id,
                "devId":   device_id,
                "offer":   {"type": "offer", "sdp": sdes_offer_sdp},
                "trackId": 0,
                "dstAddr": user_id,
            },
        })
        outgoing_q.put_nowait((webrtc_req_topic, webrtc_req_payload))
        _status(f"webrtcReq sent (SDES)  peerid={peer_id}")

        # --- Wait for SDP answer ------------------------------------------- #
        try:
            answer = await asyncio.wait_for(answer_fut, timeout=timeout)
        except asyncio.TimeoutError:
            _status(f"no webrtcResp in {timeout}s")
            outgoing_q.put_nowait(None)
            raise RuntimeError(
                f"_open_sdes_stream: no webrtcResp received within {timeout}s"
            )

        _ans_sdp = answer.get("sdp", "")
        _ans_mlines = [ln for ln in _ans_sdp.splitlines() if ln.startswith("m=")]
        _status(
            "webrtcResp received (SDES) — answer m-sections (%d): %s"
            % (len(_ans_mlines), " | ".join(_ans_mlines))
        )

        # --- Build local-receiver SDP for ffmpeg ----------------------------- #
        # We write OUR ports and OUR SRTP keys.  c=IN IP4 0.0.0.0 tells ffmpeg
        # to bind locally (listen mode) rather than connect to a remote address.
        # The camera sends SDES-SRTP to our local_ip:{audio_port,video_port}.
        ffmpeg_sdp = (
            "v=0\r\n"
            f"o=- {ts} {ts} IN IP4 0.0.0.0\r\n"
            "s=aidot-sdes-rx\r\n"
            "t=0 0\r\n"
            f"m=audio {audio_port} RTP/SAVPF 0 8\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_audio}\r\n"
            "a=rtpmap:0 PCMU/8000\r\n"
            "a=rtpmap:8 PCMA/8000\r\n"
            f"m=video {video_port} RTP/SAVPF 96 97\r\n"
            "c=IN IP4 0.0.0.0\r\n"
            f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{srtp_key_video}\r\n"
            "a=rtpmap:96 H264/90000\r\n"
            "a=fmtp:96 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f\r\n"
            "a=rtpmap:97 H265/90000\r\n"
        )

        sdp_fd, sdp_path = tempfile.mkstemp(suffix=".sdp", prefix="aidot_sdes_")
        with os.fdopen(sdp_fd, "w") as f:
            f.write(ffmpeg_sdp)

        # --- Launch ffmpeg -------------------------------------------------- #
        dest = output_path or "/dev/null"
        cmd = [
            "ffmpeg", "-y",
            "-loglevel", "warning",
            "-protocol_whitelist", "file,rtp,udp,srtp",
            "-i", sdp_path,
            "-c", "copy",
            dest,
        ]
        _LOGGER.info("SDES ffmpeg cmd: %s", " ".join(cmd))
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        _status(f"SDES stream recording → {dest}  (ffmpeg pid={proc.pid})")

        return SdesSession(
            proc=proc,
            sdp_path=sdp_path,
            outgoing_q=outgoing_q,
            mqtt_fut=mqtt_fut,
            audio_sock=_audio_sock,
            video_sock=_video_sock,
        )

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
