#!/usr/bin/env python3
"""
test_camera.py - Exercise the camera additions to python-aidot.

Usage:
  cd /path/to/python-aidot
  python3 test_camera.py --username you@email.com --password yourpass [--country US]

  # Run on a specific camera only (device UID from the device list printed above):
  python3 test_camera.py --username ... --password ... --device DEVICE_ID --webrtc

Optional flags:
  --device DEVICE_ID      Only run tests for this camera's AiDot device UID
  --list-recordings       List recordings from the past 24 hours
  --play                  Stream the first available recording for 15 seconds
  --p2p                   Fetch the TUTK P2P UID (live stream token)
  --live                  Open live stream via MQTT connectipc + TCP
  --diag-mqtt             Verbose MQTT diagnostics (use when --live fails)
  --diag-live             Sniff MQTT signalling — open the AiDot app live view
                          while this runs so the WebRTC traffic is captured
  --webrtc                Open a liveType=2 WebRTC stream (requires aiortc):
                            pip install python-aidot[webrtc]
  --webrtc-output PATH    Record the stream to PATH.

                          Recommended formats:
                            /tmp/cam.ts      MPEG-TS — streamable while recording
                            /tmp/cam.mkv     Matroska — full playback after stop
                            pipe:1           Raw mux to stdout (pipe into ffmpeg)

                          Playback / re-broadcast options (MPEG-TS recommended):

                            ffmpeg (re-stream to RTSP via MediaMTX / go2rtc):
                              ffmpeg -re -i /tmp/cam.ts -c copy \
                                -f rtsp rtsp://localhost:8554/cam

                            go2rtc (add to go2rtc.yaml, then open in any RTSP client):
                              streams:
                                cam: ffmpeg:/tmp/cam.ts#video=copy#audio=copy

                            VLC (direct live playback):
                              vlc /tmp/cam.ts
                              vlc rtsp://localhost:8554/cam   # after go2rtc/MediaMTX

                          SDES cameras use ffmpeg directly — no aiortc required.
  --webrtc-seconds N      Seconds to stream during --webrtc (default: 30)
  --log-file PATH         Write all output to PATH as well as stdout
  --verbose               Extra detail: ICE config URIs, paho logs
"""

import argparse
import asyncio
import sys
import time

import aiohttp


class _Tee:
    """Write to both the real stdout and a log file simultaneously.

    Installed as sys.stdout when --log-file is given so that all print()
    calls go to both the terminal and the file with no code changes at
    call sites.
    """
    def __init__(self, path: str) -> None:
        self._file   = open(path, "w", encoding="utf-8", buffering=1)
        self._stdout = sys.__stdout__

    def write(self, s: str) -> None:
        self._stdout.write(s)
        self._file.write(s)

    def flush(self) -> None:
        self._stdout.flush()
        self._file.flush()

    def fileno(self) -> int:          # needed by some logging handlers
        return self._stdout.fileno()

    def close(self) -> None:
        self._file.close()

    isatty = lambda self: False       # noqa: E731

# Run from the python-aidot repo root so the local aidot package is found.
sys.path.insert(0, ".")

try:
    from aidot.client import AidotClient
    from aidot.device_client import VideoFrame
except ImportError as e:
    print(f"ERROR: Could not import aidot. Run this script from the python-aidot directory.\n  {e}")
    sys.exit(1)

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def ms_to_str(ts_ms: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts_ms / 1000))


def find_cameras(devices: list) -> list:
    # Heuristic: cameras have a productId or modelId containing "CAM" or "IPC",
    # or a serviceModule identity that starts with "control.camera".
    cameras = []
    for dev in devices:
        product = dev.get("product") or {}
        modules = product.get("serviceModules") or []
        identities = [m.get("identity", "") for m in modules]
        model = (dev.get("modelId") or "").upper()
        if (any("camera" in i.lower() or "ipc" in i.lower() for i in identities)
                or "CAM" in model or "IPC" in model):
            cameras.append(dev)
    return cameras


def on_frame(frame: VideoFrame) -> None:
    kind = ("KEYFRAME" if frame.is_keyframe
            else "P/B-frame" if frame.is_video
            else "audio" if frame.is_audio
            else f"type={frame.frame_type}")
    enc  = " [encrypted]" if frame.is_encrypted else ""
    size = len(frame.data)
    ts   = (ms_to_str(frame.timestamp) if frame.timestamp > 1_000_000_000_000
            else f"ts={frame.timestamp}")
    print(f"  frame  {kind:<10}  {size:>6} bytes  {ts}{enc}")


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

async def run(args: argparse.Namespace) -> None:
    import sys as _sys
    import logging as _logging
    if args.verbose:
        _logging.getLogger("aidot.device_client").setLevel(_logging.DEBUG)
        _logging.basicConfig(
            level=_logging.DEBUG,
            format="%(name)s %(levelname)s: %(message)s",
            stream=_sys.stdout,
        )
    else:
        _logging.basicConfig(
            level=_logging.WARNING,
            format="%(name)s %(levelname)s: %(message)s",
            stream=_sys.stdout,
        )
    # Silence chatty third-party libraries that flood output even at --verbose.
    for _noisy in ("aiortc", "aioice", "aioice.ice"):
        _logging.getLogger(_noisy).setLevel(_logging.WARNING)
    async with aiohttp.ClientSession() as http_session:
        client = AidotClient(
            session=http_session,
            country_code=args.country,
            username=args.username,
            password=args.password,
        )

        # Login (now calls /users/login with MD5 password + fetches MQTT pwd via /commons/userConfig)
        print(f"\n[1] Logging in as {args.username} ...")
        try:
            info = await client.async_post_login()
            user_id = info.get("id") or info.get("userId") or "?"
            has_mqtt_pwd = bool(info.get("mqttPassword"))
            print(f"    OK  userId={user_id}  region={client._region}  "
                  f"mqttPassword={'present' if has_mqtt_pwd else 'MISSING'}")
            if not has_mqtt_pwd:
                raw_cfg = info.get("_userConfigRaw") or {}
                print(f"    [userConfig raw keys]: {list(raw_cfg.keys())}")
                print(f"    [userConfig raw body]: {raw_cfg}")
        except Exception as e:
            print(f"    FAILED: {e}")
            return

        # Get all devices
        print("\n[2] Fetching device list ...")
        try:
            result  = await client.async_get_all_device()
            devices = result.get("device_list") or []
            print(f"    {len(devices)} device(s) found")
        except Exception as e:
            print(f"    FAILED: {e}")
            return

        if not devices:
            print("    No devices on account — nothing to test.")
            return

        # Identify cameras
        cameras = find_cameras(devices)
        if not cameras:
            print("\n    No camera devices detected (checked modelId and serviceModules).")
            print("    All devices:")
            for d in devices:
                print(f"      {d.get('id')}  model={d.get('modelId')}  name={d.get('name')}")
            print("\n    You can still test P2P/playback by passing a specific device ID")
            print("    via --device if you know which one is a camera.")
            return

        print(f"    {len(cameras)} camera(s) detected:")
        for cam in cameras:
            print(f"      {cam.get('id')}  model={cam.get('modelId')}  name={cam.get('name')}")

        # Collect all camera IDs upfront for batch API calls.
        # The app sends all device IDs in a single batchGetDeviceUserInfo request
        # (~260 bytes for 7 devices); sending only one may return an empty result.
        # Must be built from the unfiltered list before --device narrows it down.
        _all_camera_ids = [c.get("id") for c in cameras if c.get("id")]

        if args.device:
            cameras = [c for c in cameras if c.get("id") == args.device]
            if not cameras:
                print(f"    --device {args.device!r} not found in camera list")
                return
            print(f"    Filtered to device {args.device!r}")

        # Run selected tests
        for cam in cameras:
            dc = client.get_device_client(cam)
            # Ensure batchGetDeviceUserInfo uses all device IDs (server may
            # return empty results if only a single device ID is sent).
            dc._all_device_ids = _all_camera_ids
            print(f"\n{'='*60}")
            print(f"Camera: {cam.get('name')}  ({cam.get('id')})")
            print(f"{'='*60}")

            # P2P UID
            if args.p2p or not (args.list_recordings or args.play or args.live or
                                args.diag_mqtt or args.diag_live or args.webrtc):
                print("\n[P2P] Camera device fields:")
                for k, v in cam.items():
                    if k != "product":
                        print(f"    {k} = {v!r}")

                import aiohttp as _aiohttp
                base = dc._smarthome_base
                headers_no_ct = {k: v for k, v in dc._leedarson_headers().items()
                                 if k != "Content-Type"}

                print(f"\n[P2P] Trying P2P UID requests against {base}")

                candidates = [
                    ("deviceId (form)", "form", {"deviceId": cam.get("id")}),
                    ("deviceSn (form)", "form", {"deviceSn": cam.get("sn") or cam.get("deviceSn") or cam.get("serialNumber")}),
                    ("deviceId (json)", "json", {"deviceId": cam.get("id")}),
                    ("mac (form)",      "form", {"mac":      cam.get("mac")}),
                ]

                for label, enc, body in candidates:
                    val = list(body.values())[0]
                    if not val:
                        print(f"    {label:<25} skipped (field not present)")
                        continue
                    try:
                        async with _aiohttp.ClientSession() as _s:
                            kw = {"headers": headers_no_ct, "timeout": _aiohttp.ClientTimeout(total=10)}
                            if enc == "json":
                                kw["json"] = body
                            else:
                                kw["data"] = body
                            async with _s.post(f"{base}/deviceController/getP2pId", **kw) as _r:
                                _resp = await _r.json(content_type=None)
                        uid_val = _resp.get("data") or _resp.get("uid")
                        marker = "  *** UID FOUND ***" if uid_val else ""
                        print(f"    {label:<25} -> {_resp}{marker}")
                    except Exception as _e:
                        print(f"    {label:<25} -> ERROR: {_e}")

            # Cloud recordings
            if args.list_recordings or args.play:
                now_ms   = int(time.time() * 1000)
                day_ms   = 24 * 60 * 60 * 1000
                start_ms = now_ms - day_ms

                print(f"\n[REC] Listing recordings from last 24 h ...")
                clips = await dc.async_get_cloud_recordings(start_ms, now_ms)
                if not clips:
                    print("    No recordings found in that window.")
                else:
                    print(f"    {len(clips)} clip(s):")
                    for i, c in enumerate(clips):
                        dur = (c["end"] - c["sta"]) // 1000
                        print(f"      [{i}]  {ms_to_str(c['sta'])}  ->  "
                              f"{ms_to_str(c['end'])}  ({dur}s)")

                # Playback
                if args.play and clips:
                    clip = clips[0]
                    print(f"\n[PLAY] Opening playback for clip [0] "
                          f"({ms_to_str(clip['sta'])} -> {ms_to_str(clip['end'])}) ...")
                    print("    (Ctrl+C to stop early)")

                    session = await dc.async_open_cloud_playback(
                        clip["sta"], clip["end"], on_frame
                    )
                    if session is None:
                        print("    FAILED to open playback session.")
                    else:
                        print(f"    Session open — streaming for {args.play_seconds}s ...")
                        try:
                            await asyncio.sleep(args.play_seconds)
                        except asyncio.CancelledError:
                            pass
                        finally:
                            await session.stop()
                        print("    Session stopped.")

            if args.diag_mqtt or args.live:
                # --------------------------------------------------------------- #
                # MQTT diagnostics: print broker URL, connection status, and
                # ALL raw messages received so we can see what the broker delivers.
                # --------------------------------------------------------------- #
                print(f"\n[DIAG] All raw device fields for {cam.get('name')}:")
                for _dk, _dv in cam.items():
                    print(f"    {_dk} = {_dv!r}")

                # Dump ALL user_info keys
                print(f"\n[DIAG] All user_info keys ({len(dc._user_info)} total):")
                SENSITIVE = ("token", "password", "pwd", "secret")
                for k, v in sorted(dc._user_info.items()):
                    if any(x in k.lower() for x in SENSITIVE):
                        print(f"    {k!r}: <redacted len={len(str(v))}>")
                    else:
                        print(f"    {k!r}: {v!r}")

                _lid = dc._user_info

                # --- batchGetDeviceUserInfo probe (AiDot v21 API) ---
                # Send all camera IDs in one batch (mirrors app behaviour ~260B body).
                import json as _dui_json
                print(f"\n[DIAG] Fetching batchGetDeviceUserInfo "
                      f"(batch of {len(_all_camera_ids)} device(s)) ...")
                _dev_user_info = await dc.async_get_device_user_info(
                    all_device_ids=_all_camera_ids)
                _raw_batch = getattr(dc, '_last_batch_response', None)
                if _dev_user_info:
                    _p2p = (_dev_user_info.get("p2pId") or _dev_user_info.get("uid")
                            or _dev_user_info.get("tutk_uid"))
                    print(f"    batchGetDeviceUserInfo data for {cam.get('id')}:")
                    print(f"    {_dui_json.dumps(_dev_user_info, indent=6, default=str)}")
                    if not _p2p:
                        print(f"    (no p2pId — TUTK P2P not supported by this camera)")
                else:
                    print(f"    batchGetDeviceUserInfo: call failed for {cam.get('id')}")
                    print(f"    raw server response: {_raw_batch}")

                # --- P2P UID probe ---
                print(f"\n[DIAG] Fetching P2P UID for {cam.get('id')} ...")
                _p2p_uid = await dc.async_get_p2p_uid()
                if _p2p_uid:
                    print(f"    P2P UID: {_p2p_uid!r}  (TUTK/LiveAndPlayBack path available)")
                else:
                    print(f"    P2P UID: None  (P2P not available; relay path needed)")

            if args.diag_live:
                # ----------------------------------------------------------- #
                # MQTT live-stream sniffer + HTTP provisioning probe
                # ----------------------------------------------------------- #
                import json as _dlj
                from aidot.device_client import _mqtt_session_with_status

                print(f"\n[DIAG-LIVE] Live-stream provisioning probe for {cam.get('name')} ...")

                # Fetch MQTT credentials
                _sm_auth = await dc._async_get_smarthome_auth()
                _mqtt_user = (_sm_auth or {}).get("mqttUser") or str(dc.user_id)
                _mqtt_pwd  = (_sm_auth or {}).get("mqttPassword") or ""
                # Use the EXACT authorised clientId from the server config.
                # The broker requires the server-assigned {terminalIndex}-{userId}
                # format; random or made-up prefixes are rejected with rc=4.
                _mqtt_cid  = (dc._user_info.get("mqttClientId") or
                              (dc._user_info.get("_userConfigRaw") or {}).get("mqtt", {}).get("clientId") or
                              f"app-{_mqtt_user}")
                _mqtt_url  = await dc._async_get_mqtt_url()

                print(f"    MQTT broker   : {_mqtt_url}")
                print(f"    MQTT user     : {_mqtt_user}")
                print(f"    MQTT clientId : {_mqtt_cid}")
                print(f"    MQTT pwd      : {'<present>' if _mqtt_pwd else '<MISSING>'}")

                # Print any streaming-related keys from getServerUrlConfig response.
                _raw_cfg = (dc._smarthome_auth or {}).get("raw") or {}
                if _raw_cfg and set(_raw_cfg.keys()) != {"source"}:
                    _stream_keys = {k: v for k, v in _raw_cfg.items()
                                    if any(x in k.lower() for x in
                                           ("live", "stream", "rtsp", "webrtc", "kvs",
                                            "signal", "media", "play", "video", "ipc"))}
                    if _stream_keys:
                        print(f"    getServerUrlConfig streaming keys: {_stream_keys}")
                    elif args.verbose:
                        print(f"    getServerUrlConfig keys: {sorted(_raw_cfg.keys())}")

                # ICE config (HTTP — no MQTT session needed)
                print(f"\n[DIAG-LIVE] Fetching ICE server config (STUN/TURN credentials) ...")
                _ice_cfg = await dc.async_get_ice_config(cam.get("id"))
                if _ice_cfg:
                    _app_entries = _ice_cfg.get("app") or []
                    _dev_entries = _ice_cfg.get("dev") or []
                    _cam_dev = next((e for e in _dev_entries if e.get("id") == cam.get("id")), None)
                    print(f"    ICE config received — "
                          f"{len(_app_entries)} app entr{'y' if len(_app_entries)==1 else 'ies'}, "
                          f"{len(_dev_entries)} device entr{'y' if len(_dev_entries)==1 else 'ies'}")
                    if _cam_dev:
                        _uris = _cam_dev.get("uris") or []
                        print(f"    This camera: token={_cam_dev.get('token','?')}  "
                              f"ttl={_cam_dev.get('ttl','?')}  uris={_uris}")
                    if args.verbose:
                        for _e in _app_entries:
                            print(f"      app  id={_e.get('id','?')}  token={_e.get('token','?')}  ttl={_e.get('ttl','?')}")
                            for _u in (_e.get("uris") or []):
                                print(f"           uri: {_u}")
                        for _e in _dev_entries:
                            _marker = "  *** this camera ***" if _e.get("id") == cam.get("id") else ""
                            print(f"      dev  id={_e.get('id','?')}  token={_e.get('token','?')}{_marker}")
                            for _u in (_e.get("uris") or []):
                                print(f"           uri: {_u}")
                else:
                    print(f"    (no ICE config received — sniff may capture it if app is active)")

                # Passive MQTT sniff — single persistent session using the
                # authorised clientId.  The on_ready hook waits for ENTER so the
                # 60-second capture window starts exactly when the user says, while
                # the broker connection (and any early messages) are preserved.
                _sniff_secs = args.diag_live_seconds
                _live_topics = [
                    f"iot/v1/cb/{cam.get('id')}/#",
                    f"iot/v1/c/{_mqtt_user}/#",
                    f"lds/v1/cb/{cam.get('id')}/#",
                    f"lds/v1/c/{_mqtt_user}/#",
                ]

                _seen = []
                def _on_msg(topic, payload):
                    _seen.append((topic, payload))
                    try:
                        _p = _dlj.loads(payload)
                        _pstr = _dlj.dumps(_p, indent=6, default=str)
                    except Exception:
                        _p = None
                        _pstr = repr(payload[:500])
                    print(f"  MQTT  topic={topic}")
                    print(f"        {_pstr}")
                    # For webrtcReq/webrtcResp: highlight SDP transport line
                    _method = _p.get("method") if isinstance(_p, dict) else None
                    if _method in ("webrtcReq", "webrtcResp"):
                        _inner = (_p.get("payload") or {})
                        _sdp   = ((_inner.get("offer") or _inner.get("answer") or {})).get("sdp", "")
                        _pid   = _inner.get("peerid", "?")
                        _vtrans = next(
                            (ln.split()[2] for ln in _sdp.splitlines()
                             if ln.startswith("m=video ") and len(ln.split()) > 2),
                            "absent",
                        )
                        print(f"        *** {_method}: peerid={_pid}")
                        print(f"        *** SDP m=video transport: {_vtrans}")

                def _on_ready(st):
                    """Called from the MQTT thread after subscription.
                    Blocks on stdin so the capture window starts after ENTER.
                    """
                    if not st.get("connected"):
                        err = st.get("error") or st.get("rc_str") or f"rc={st.get('rc')}"
                        print(f"\n[DIAG-LIVE] MQTT connection FAILED: {err}")
                        if args.verbose:
                            for _ll in st.get("log", [])[-10:]:
                                print(f"  paho: {_ll}")
                        return
                    print(f"\n[DIAG-LIVE] MQTT connected (clientId={_mqtt_cid})")
                    print()
                    print(f"    STEP 1: Open the AiDot app on your phone")
                    print(f"    STEP 2: Navigate to the live view for '{cam.get('name')}'")
                    print(f"    STEP 3: Press ENTER below AFTER the live view is open")
                    print()
                    # Write prompt to stderr so it appears on the terminal even
                    # when stdout is redirected to a file (--log-file).
                    sys.stderr.write(
                        f"    >>> Press ENTER to start the {_sniff_secs}s capture window ... "
                    )
                    sys.stderr.flush()
                    sys.stdin.readline()
                    print(f"    Capture started — keep the live view open for {_sniff_secs}s ...")
                    print()

                print(f"\n[DIAG-LIVE] Connecting to MQTT broker for {_sniff_secs}s sniff ...")
                _sniff_msgs, _sniff_status = await _mqtt_session_with_status(
                    _mqtt_url, _mqtt_user, _mqtt_pwd, _mqtt_cid,
                    _live_topics, [], float(_sniff_secs), _on_msg,
                    ws_path="/mqtt", on_ready=_on_ready,
                )
                if _sniff_status.get("connected"):
                    print(f"\n    Sniff complete. {len(_seen)} message(s) captured.")
                else:
                    _err = _sniff_status.get("error") or _sniff_status.get("rc_str") or f"rc={_sniff_status.get('rc')}"
                    print(f"\n    MQTT connection failed: {_err}")
                    if args.verbose:
                        for _logline in _sniff_status.get("log", [])[-10:]:
                            print(f"      paho: {_logline}")

            if args.live and not args.diag_mqtt and not args.webrtc:
                print(f"\n[LIVE] Opening live stream for {cam.get('name', cam.get('id'))} ...")
                print("    (Ctrl+C to stop early)")

                session = await dc.async_open_live_stream(on_frame)
                if session is None:
                    print("    FAILED to open live stream session.")
                    if dc.is_sdes_camera:
                        print("    (This camera uses WebRTC/SDES streaming — try --webrtc)")
                else:
                    print(f"    Session open — streaming for {args.live_seconds}s ...")
                    try:
                        await asyncio.sleep(args.live_seconds)
                    except asyncio.CancelledError:
                        pass
                    finally:
                        await session.stop()
                    print("    Session stopped.")

            if args.webrtc:
                # ----------------------------------------------------------- #
                # WebRTC live stream via MQTT signaling + aiortc (DTLS cameras)
                # or ffmpeg SRTP receiver (SDES cameras, isDTLS == '0').
                #
                # Capture to MPEG-TS (streamable while recording):
                #   python3 test_camera.py ... --webrtc --webrtc-output /tmp/cam.ts
                #
                # Re-broadcast as RTSP with ffmpeg → MediaMTX / go2rtc:
                #   ffmpeg -re -i /tmp/cam.ts -c copy -f rtsp rtsp://localhost:8554/cam
                #
                # go2rtc pull (go2rtc.yaml):
                #   streams:
                #     cam: ffmpeg:/tmp/cam.ts#video=copy#audio=copy
                #
                # VLC direct:
                #   vlc /tmp/cam.ts
                #   vlc rtsp://localhost:8554/cam   # after go2rtc / MediaMTX
                # ----------------------------------------------------------- #
                # Check for aiortc (required for DTLS cameras; SDES cameras use ffmpeg).
                # Print a note but do NOT skip — SDES cameras work without aiortc.
                try:
                    import aiortc as _aiortc_check  # noqa: F401
                    _has_aiortc = True
                except ImportError:
                    _has_aiortc = False

                if not _has_aiortc:
                    print(f"\n[WEBRTC] Note: aiortc not installed "
                          f"(needed for DTLS cameras; SDES cameras use ffmpeg).")
                    print(f"    pip install aiortc")

                print(f"\n[WEBRTC] Opening WebRTC stream for {cam.get('name', cam.get('id'))} ...")
                if args.webrtc_output:
                    print(f"    Recording to: {args.webrtc_output}")
                print(f"    Connecting (timeout {args.webrtc_timeout}s) ...")

                _wrtc_frames = [0]
                def _wrtc_on_frame(frame) -> None:
                    _wrtc_frames[0] += 1
                    if _wrtc_frames[0] % 30 == 1:
                        print(f"    [WEBRTC] frame #{_wrtc_frames[0]}  "
                              f"{getattr(frame, 'width', '?')}x{getattr(frame, 'height', '?')}")

                def _wrtc_status(msg: str) -> None:
                    print(f"    {msg}")

                try:
                    _wrtc_session = await dc.async_open_webrtc_stream(
                        on_frame=_wrtc_on_frame,
                        output_path=args.webrtc_output or None,
                        timeout=args.webrtc_timeout,
                        status_callback=_wrtc_status,
                        force_sdes=True if args.webrtc_sdes else (False if args.webrtc_dtls else None),
                    )
                    print(f"    WebRTC connected — streaming for {args.webrtc_seconds}s ...")
                    print("    (Ctrl+C to stop early)")
                    try:
                        await asyncio.sleep(args.webrtc_seconds)
                    except asyncio.CancelledError:
                        pass
                    finally:
                        await _wrtc_session.stop()
                    print(f"    Session stopped. {_wrtc_frames[0]} frame(s) received.")
                except ImportError as _ie:
                    print(f"    ERROR: {_ie}")
                except RuntimeError as _re:
                    print(f"    FAILED: {_re}")
                except Exception as _exc:
                    print(f"    UNEXPECTED ERROR [{type(_exc).__name__}]: {_exc}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test camera additions to python-aidot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--username",  required=True,  help="AiDot account email")
    parser.add_argument("--password",  required=True,  help="AiDot account password")
    parser.add_argument("--country",   default="US",   help="Country code (default: US)")
    parser.add_argument("--p2p",       action="store_true",
                        help="Fetch TUTK P2P UID for each camera")
    parser.add_argument("--list-recordings", action="store_true",
                        help="List cloud recordings from the past 24 hours")
    parser.add_argument("--play",      action="store_true",
                        help="Play back the first available recording")
    parser.add_argument("--play-seconds", type=int, default=15,
                        help="How many seconds to stream during --play (default: 15)")
    parser.add_argument("--live",      action="store_true",
                        help="Open live stream via MQTT connectipc + TCP")
    parser.add_argument("--live-seconds", type=int, default=15,
                        help="How many seconds to stream during --live (default: 15)")
    parser.add_argument("--diag-mqtt", action="store_true",
                        help="Verbose MQTT diagnostics: show broker URL, raw messages, "
                             "and ALL topics received (use this when --live fails)")
    parser.add_argument("--diag-live", action="store_true",
                        help="Probe live-stream provisioning API and sniff MQTT for "
                             "--diag-live-seconds seconds (open app live view during sniff)")
    parser.add_argument("--diag-live-seconds", type=int, default=60,
                        help="How many seconds to sniff MQTT during --diag-live (default: 60)")
    parser.add_argument("--device", metavar="DEVICE_ID",
                        help="Run tests on only the camera with this AiDot device UID")
    parser.add_argument("--log-file", metavar="PATH",
                        help="Write all output to PATH in addition to stdout "
                             "(prompt still appears on terminal even when stdout is redirected)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show detailed probe output: per-URI ICE config, paho logs, "
                             "HTTP/MQTT exploratory probes")
    parser.add_argument("--webrtc", action="store_true",
                        help="Open a liveType=2 WebRTC stream via MQTT signaling (requires aiortc)")
    parser.add_argument("--webrtc-output", metavar="PATH",
                        help="Record the stream to this file (e.g. /tmp/cam.ts). "
                             "Use .ts for live viewing (ffplay/VLC) or RTSP re-broadcast "
                             "via ffmpeg+MediaMTX / go2rtc. SDES cameras use ffmpeg directly.")
    parser.add_argument("--webrtc-seconds", type=int, default=30,
                        help="How many seconds to stream during --webrtc (default: 30)")
    parser.add_argument("--webrtc-timeout", type=float, default=30.0,
                        help="Seconds to wait for WebRTC ICE connection (default: 30)")
    parser.add_argument("--webrtc-sdes", action="store_true",
                        help="Force SDES-SRTP path (ffmpeg, peerid _1) regardless of "
                             "isDTLS device property; use to test SDES cameras explicitly")
    parser.add_argument("--webrtc-dtls", action="store_true",
                        help="Force DTLS-SRTP path (aiortc, peerid _2) regardless of "
                             "isDTLS device property; use to override SDES auto-detection")

    args = parser.parse_args()

    # Companion flags imply --webrtc so users don't need to add --webrtc explicitly
    # when they already specify --webrtc-output, --webrtc-sdes, or --webrtc-dtls.
    if not args.webrtc and (args.webrtc_output or args.webrtc_sdes or args.webrtc_dtls):
        args.webrtc = True

    # Default: run all tests if no specific flag given
    if not any([args.p2p, args.list_recordings, args.play, args.live,
                args.diag_mqtt, args.diag_live, args.webrtc]):
        args.p2p             = True
        args.list_recordings = True
        args.play            = True
        args.live            = True

    _tee = None
    if args.log_file:
        _tee = _Tee(args.log_file)
        sys.stdout = _tee

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")
    finally:
        if _tee:
            sys.stdout = sys.__stdout__
            _tee.close()


if __name__ == "__main__":
    main()
