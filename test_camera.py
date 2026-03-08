#!/usr/bin/env python3
"""
test_camera.py - Exercise the camera additions to python-aidot.

Usage:
  cd /path/to/python-aidot
  python3 test_camera.py --username you@email.com --password yourpass --country US

Optional flags:
  --list-recordings   List recordings from the past 24 hours for each camera
  --play              Stream the first available recording for 15 seconds
  --p2p               Fetch the TUTK P2P UID for each camera (live stream token)
  --live              Open live stream via MQTT connectipc + TCP
  --diag-mqtt         Verbose MQTT diagnostics: show broker URL, raw messages,
                      and ALL topics received (use this when --live fails)
"""

import argparse
import asyncio
import sys
import time

import aiohttp

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
    async with aiohttp.ClientSession() as http_session:
        client = AidotClient(
            session=http_session,
            country_code=args.country,
            username=args.username,
            password=args.password,
        )

        # Login
        print(f"\n[1] Logging in as {args.username} ...")
        try:
            info = await client.async_post_login()
            user_id = info.get("id") or info.get("userId") or "?"
            print(f"    OK  userId={user_id}  region={client._region}")
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
            print("    via --device-id if you know which one is a camera.")
            return

        print(f"    {len(cameras)} camera(s) detected:")
        for cam in cameras:
            print(f"      {cam.get('id')}  model={cam.get('modelId')}  name={cam.get('name')}")

        # Run selected tests
        for cam in cameras:
            dc = client.get_device_client(cam)
            print(f"\n{'='*60}")
            print(f"Camera: {cam.get('name')}  ({cam.get('id')})")
            print(f"{'='*60}")

            # P2P UID
            if args.p2p or not (args.list_recordings or args.play or args.live or args.diag_mqtt):
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
                props = cam.get("properties") or {}
                live_type   = props.get("liveType", "?")
                spt_preconn = props.get("sptPreconn", "?")
                ip_addr_raw = props.get("ipAddress", "")
                enable_sdes = props.get("enableSdes", "?")
                is_dtls     = props.get("isDTLS", "?")
                password    = cam.get("password", "")

                # Decode corrupted IP: '49.57.50.46' = ASCII bytes '1','9','2','.'
                # The camera stores the IP string bytes as dotted-decimal octets.
                def decode_ip(raw):
                    try:
                        parts   = [int(x) for x in raw.split(".")]
                        decoded = bytes(parts).decode("ascii")
                        import re
                        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", decoded):
                            return decoded
                    except Exception:
                        pass
                    return raw

                ip_addr = decode_ip(ip_addr_raw) if ip_addr_raw else ""

                print(f"\n[DIAG] Device streaming properties for {cam.get('name')}:")
                print(f"    liveType={live_type}  sptPreconn={spt_preconn}  "
                      f"enableSdes={enable_sdes}  isDTLS={is_dtls}")
                print(f"    ipAddress raw={ip_addr_raw!r}  decoded={ip_addr!r}")
                print(f"    password={password!r}")

                # Dump ALL user_info keys
                print(f"\n[DIAG] All user_info keys ({len(dc._user_info)} total):")
                SENSITIVE = ("token", "password", "pwd", "secret")
                for k, v in sorted(dc._user_info.items()):
                    if any(x in k.lower() for x in SENSITIVE):
                        print(f"    {k!r}: <redacted len={len(str(v))}>")
                    else:
                        print(f"    {k!r}: {v!r}")

                _lid = dc._user_info
                print(f"\n[DIAG] login_info notable fields:")
                print(f"    id (smarthome userId): {_lid.get('id')!r}")
                print(f"    url: {_lid.get('url')!r}")
                print(f"    tid: {_lid.get('tid')!r}")
                print(f"    terminalIndex: {_lid.get('terminalIndex')!r}")

                # Raw probe: /user/login and /user/getUser directly
                import aiohttp as _ah
                _tid    = _lid.get("tid") or ""
                _tidx   = _lid.get("terminalIndex") or ""
                _token  = _lid.get("accessToken") or ""
                _uname  = _lid.get("username") or ""
                _pwd    = _lid.get("password") or ""
                print(f"\n[DIAG] accessToken prefix: {_token[:8]}...  len={len(_token)}")
                print(f"[DIAG] tid={_tid!r}  terminalIndex={_tidx!r}")
                _smarthome_base = f"https://{_lid.get('region') or 'us'}-smarthome.arnoo.com:443"
                _leedarson_headers = {
                    "terminal":        "thirdPlatFormUser",
                    "active-language": "en_US",
                    "appKey":          "appa070",
                    "access-token":    _token,
                    "token":           _token,
                    "Content-Type":    "application/json",
                }
                # MQTT broker is global-us-mqtt; try matching global-us-smarthome host too
                _global_smarthome_base = f"https://global-{_lid.get('region') or 'us'}-smarthome.arnoo.com:443"
                print(f"[DIAG] Probing smarthome endpoints for MQTT credentials...")
                print(f"       hosts: {_smarthome_base}  AND  {_global_smarthome_base}")
                async with _ah.ClientSession() as _sess:
                    # Probe 1: /user/getUser on both hosts, 3 request styles
                    _uid_for_getuser = _lid.get("id") or ""
                    for _base_host in (_smarthome_base, _global_smarthome_base):
                        for _gu_style, _gu_kw in (
                            ("json", {"json":   {"desc": _uid_for_getuser}}),
                            ("qs",   {"params": {"desc": _uid_for_getuser}}),
                            ("form", {"data":   {"desc": _uid_for_getuser}}),
                        ):
                            try:
                                async with _sess.post(
                                    f"{_base_host}/user/getUser",
                                    headers=_leedarson_headers,
                                    timeout=_ah.ClientTimeout(total=8),
                                    **_gu_kw,
                                ) as _r:
                                    _rb = await _r.json(content_type=None)
                                _d = _rb.get("data") or {}
                                _has_mqtt = any(k in str(_rb) for k in
                                    ("mqqtPwd", "mqttPwd", "associatedAccount", "authInfo", "mqtt"))
                                _marker = "  *** HAS MQTT DATA ***" if _has_mqtt else ""
                                _host_s = "global" if "global" in _base_host else "regional"
                                print(f"    [{_host_s}][{_gu_style}] POST /user/getUser -> "
                                      f"code={_rb.get('code')} "
                                      f"data_keys={list(_d.keys()) if isinstance(_d, dict) else _d!r}"
                                      f"{_marker}")
                                if _has_mqtt:
                                    print(f"       data={_d}")
                            except Exception as _e:
                                _host_s = "global" if "global" in _base_host else "regional"
                                print(f"    [{_host_s}][{_gu_style}] POST /user/getUser "
                                      f"EXCEPTION: {type(_e).__name__}: {_e}")

                    # Probe 2: candidate MQTT-credential endpoints on both hosts
                    _uid_for_probe = _lid.get("id") or str(dc.user_id)
                    _mqtt_cred_endpoints = [
                        ("GET",  "/user/getMqttInfo",              {}),
                        ("POST", "/user/getMqttInfo",              {"userId": _tid or _uname}),
                        ("GET",  "/user/authInfo",                 {"userId": _tid or _uname}),
                        ("POST", "/user/authInfo",                 {"userId": _tid or _uname}),
                        ("GET",  "/commonController/getMqttConfig", {}),
                        ("POST", "/commonController/getMqttConfig", {}),
                        ("GET",  "/user/getUserMqtt",              {}),
                        ("POST", "/user/getUserMqtt",              {"userId": _tid or _uname}),
                        ("POST", "/user/reqUserAuthInfo",          {"userId": _uid_for_probe}),
                        ("GET",  "/user/reqUserAuthInfo",          {"userId": _uid_for_probe}),
                        ("POST", "/iot/getToken",                  {"userId": _uid_for_probe}),
                        ("POST", "/user/getUserAuthInfo",          {"userId": _uid_for_probe}),
                    ]
                    for _base_url in [_smarthome_base, _global_smarthome_base]:
                        for _method, _ep, _params in _mqtt_cred_endpoints:
                            try:
                                _kw = {"headers": _leedarson_headers,
                                       "timeout": _ah.ClientTimeout(total=6)}
                                if _method == "GET":
                                    _kw["params"] = _params
                                    _req = _sess.get(f"{_base_url}{_ep}", **_kw)
                                else:
                                    _kw["json"] = _params
                                    _req = _sess.post(f"{_base_url}{_ep}", **_kw)
                                async with _req as _r:
                                    _rb = await _r.json(content_type=None)
                                _d = _rb.get("data") or {}
                                _has_mqtt = any(k in str(_rb)
                                                for k in ("mqtt", "Mqtt", "MQTT", "authInfo"))
                                _marker = "  *** HAS MQTT DATA ***" if _has_mqtt else ""
                                _host_label = "global" if "global" in _base_url else "regional"
                                print(f"    [{_host_label}] {_method} {_ep} -> "
                                      f"code={_rb.get('code')} desc={_rb.get('desc')!r}{_marker}")
                                if _has_mqtt:
                                    print(f"       data={_d}")
                            except Exception as _e:
                                _host_label = "global" if "global" in _base_url else "regional"
                                print(f"    [{_host_label}] {_method} {_ep} -> "
                                      f"ERROR: {type(_e).__name__}: {_e}")

                    # Probe 3: /user/login
                    # The Android SDK uses Retrofit @QueryMap on POST, which sends
                    # params as URL query string (not form body).  We try both:
                    #   "qs"   = params= (URL query string on POST)  <-- SDK pattern
                    #   "form" = data=   (application/x-www-form-urlencoded body)
                    #   "json" = json=   (application/json body)
                    import hashlib as _hl
                    _md5_pwd = _hl.md5(_pwd.encode()).hexdigest().upper() if _pwd else ""
                    _login_hdr_noct = {"terminal": "thirdPlatFormUser",
                                       "active-language": "en_US", "appKey": "appa070"}
                    _login_hdr_json = {**_login_hdr_noct, "Content-Type": "application/json"}
                    for _apid in ("appa070", "1383974540041977857"):
                        for _tmark in ("app", "thirdPlatFormUser"):
                            for _tdata in ({}, {"tenantId": "11"}):
                                for _pwd_type, _pwd_val in (("plain", _pwd), ("md5", _md5_pwd)):
                                    _base_body = {
                                        "userName": _uname, "passWord": _pwd_val,
                                        "os": "ios", "terminalMark": _tmark,
                                        "appId": _apid, "phoneId": _tidx,
                                        "locationId": "us", **_tdata,
                                    }
                                    _label = (f"appId={_apid} tmark={_tmark} "
                                              f"tenantId={_tdata.get('tenantId','<none>')} "
                                              f"pwd={_pwd_type}")
                                    for _style, _kw, _hdr in (
                                        ("qs",   {"params": _base_body}, _login_hdr_noct),
                                        ("form", {"data":   _base_body}, _login_hdr_noct),
                                        ("json", {"json":   _base_body}, _login_hdr_json),
                                    ):
                                        try:
                                            async with _sess.post(
                                                f"{_smarthome_base}/user/login",
                                                headers=_hdr,
                                                timeout=_ah.ClientTimeout(total=8),
                                                **_kw,
                                            ) as _r:
                                                _rb = await _r.json(content_type=None)
                                            _code = _rb.get("code")
                                            _has_auth = any(k in str(_rb) for k in
                                                ("mqqtPwd", "mqttPwd", "associatedAccount",
                                                 "authInfo", "mqtt"))
                                            _ok = "  *** AUTH DATA ***" if _has_auth else ""
                                            print(f"    /user/login [{_style}] {_label} -> "
                                                  f"code={_code} desc={_rb.get('desc')!r}"
                                                  f"{_ok}")
                                            if _has_auth or _code in (200, 0):
                                                print(f"       DATA: {_rb.get('data')}")
                                        except Exception as _e:
                                            print(f"    /user/login [{_style}] {_label} "
                                                  f"EXCEPTION: {type(_e).__name__}: {_e}")

                # Step A: fetch server config
                print(f"\n[DIAG] Calling getServerUrlConfig (full response logged at WARNING)...")
                mqtt_url = await dc._async_get_mqtt_url()
                print(f"[DIAG] MQTT broker URL: {mqtt_url!r}")
                srv_cfg  = dc._smarthome_auth or {}
                _raw_cfg = srv_cfg.get("raw", {})
                print(f"[DIAG] getServerUrlConfig data keys: {list(_raw_cfg.keys())}")
                print(f"[DIAG] getServerUrlConfig httpHeader: {_raw_cfg.get('httpHeader')!r}")
                print(f"[DIAG] getServerUrlConfig uniqueMsgId: {_raw_cfg.get('uniqueMsgId')!r}")
                print(f"[DIAG] getServerUrlConfig heartbeat: {_raw_cfg.get('heartbeat')!r}")

                # Step B: fetch MQTT credentials (all strategies)
                print(f"\n[DIAG] Fetching MQTT credentials (all strategies)...")
                smarthome_auth = await dc._async_get_smarthome_auth()
                if smarthome_auth:
                    print(f"    mqttUser: {smarthome_auth.get('mqttUser')!r}")
                    _mp = smarthome_auth.get("mqttPassword") or ""
                    print(f"    mqttPassword: <len={len(_mp)}>")
                    print(f"    raw keys: {list(smarthome_auth.get('raw', {}).keys())}")
                    mqtt_user_for_diag = smarthome_auth.get("mqttUser") or str(dc.user_id)
                    mqtt_pwd_used      = smarthome_auth.get("mqttPassword") or ""
                else:
                    print("    FAILED — all strategies exhausted")
                    mqtt_user_for_diag = _lid.get("id") or str(dc.user_id)
                    mqtt_pwd_used      = ""

                access_token = _lid.get("accessToken") or _lid.get("access_token") or ""
                print(f"[DIAG] accessToken present: {bool(access_token)} len={len(access_token)}")

                if not mqtt_url:
                    print("    ERROR: Could not fetch MQTT broker URL — skipping MQTT diag")
                else:
                    import paho.mqtt.client as _mqtt
                    import ssl as _ssl
                    import threading as _threading
                    import urllib.parse as _up
                    import random as _random
                    import json as _json

                    # Build credential candidates to try in order.
                    _access_token   = _lid.get("accessToken") or _lid.get("access_token") or ""
                    _smarthome_uid  = _lid.get("id") or str(dc.user_id)
                    _terminal_idx   = _lid.get("terminalIndex") or ""
                    _raw_http_hdr   = srv_cfg.get("raw", {}).get("httpHeader") or ""
                    _hdr_token = ""
                    if isinstance(_raw_http_hdr, dict):
                        _hdr_token = (_raw_http_hdr.get("token")
                                      or _raw_http_hdr.get("access-token") or "")
                    elif isinstance(_raw_http_hdr, str) and "{" in _raw_http_hdr:
                        try:
                            _hdr_obj   = _json.loads(_raw_http_hdr)
                            _hdr_token = (_hdr_obj.get("token")
                                          or _hdr_obj.get("access-token") or "")
                        except Exception:
                            pass

                    _init_pwd = _lid.get("initPassword") or ""

                    _cred_candidates = []
                    if _access_token:
                        _cred_candidates.append((_smarthome_uid, _access_token, "userId+accessToken"))
                    if mqtt_user_for_diag and mqtt_pwd_used:
                        _cred_candidates.append((mqtt_user_for_diag, mqtt_pwd_used, "smarthome_auth"))
                    if _hdr_token and _hdr_token != _access_token:
                        _cred_candidates.append((_smarthome_uid, _hdr_token, "userId+httpHeader.token"))
                    if _terminal_idx:
                        _cred_candidates.append((_smarthome_uid, _terminal_idx, "userId+terminalIndex"))
                    if _access_token:
                        _cred_candidates.append((_access_token, _access_token, "accessToken+accessToken"))
                    if _tid and _access_token:
                        _cred_candidates.append((f"{_smarthome_uid}@{_tid}", _access_token, "userId@tid+accessToken"))
                        _cred_candidates.append((f"{_tid}:{_smarthome_uid}", _access_token, "tid:userId+accessToken"))
                    _app_client_id = f"app-{_smarthome_uid}"
                    if _access_token:
                        _cred_candidates.append((_app_client_id, _access_token, "app-userId+accessToken"))
                    # initPassword (4-char PIN stored in login_info) as MQTT password
                    if _init_pwd and _access_token:
                        _cred_candidates.append((_smarthome_uid, _init_pwd, "userId+initPassword"))
                    _cred_candidates.append((_smarthome_uid, "", "userId+empty"))

                    # WebSocket paths to try — broker may not use /mqtt
                    _ws_paths = ["/mqtt", "/", "/ws", "/mqtt/"]

                    print(f"    MQTT will try {len(_cred_candidates)} credential combinations")
                    for _cred_label in [c[2] for c in _cred_candidates]:
                        print(f"      - {_cred_label}")

                    user_id   = _smarthome_uid
                    seq       = str(_random.randint(100_000, 999_999))
                    sub_topic    = f"iot/v1/c/{user_id}/#"
                    sub_topic_cb = f"iot/v1/cb/{user_id}/#"
                    pub_topic    = f"iot/v1/s/{user_id}/IPCAM/connectipc"

                    req_body = _json.dumps({
                        "service": "IPCAM",
                        "method":  "connectipc",
                        "seq":     seq,
                        "srcAddr": f"0.{user_id}",
                        "payload": {
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "deviceId":  cam.get("id"),
                            "clientId":  f"diag-probe",
                        },
                    })

                    parsed    = _up.urlparse(mqtt_url)
                    host      = parsed.hostname or mqtt_url
                    port      = parsed.port or 443
                    path      = parsed.path or "/mqtt"
                    use_tls   = parsed.scheme in ("wss", "mqtts")
                    transport = "websockets" if parsed.scheme in ("wss", "ws") else "tcp"

                    done_event    = _threading.Event()
                    messages_seen = []
                    connect_rc_box = [None]

                    def _on_connect(c, ud, flags, rc):
                        connect_rc_box[0] = rc
                        print(f"    MQTT on_connect rc={rc} ({'OK' if rc == 0 else 'FAILED'})")
                        if rc == 0:
                            c.subscribe(sub_topic, qos=1)
                            c.subscribe(sub_topic_cb, qos=1)
                            c.publish(pub_topic, req_body, qos=1)
                            print(f"    MQTT subscribed to {sub_topic}")
                            print(f"    MQTT subscribed to {sub_topic_cb}")
                            print(f"    MQTT published connectipc seq={seq}")

                    def _on_message(c, ud, msg):
                        try:
                            payload_str = msg.payload.decode("utf-8")
                        except Exception:
                            payload_str = repr(msg.payload[:200])
                        messages_seen.append((msg.topic, payload_str))
                        print(f"    MQTT <<< topic={msg.topic}")
                        print(f"           payload={payload_str[:300]}")

                    def _on_disconnect(c, ud, rc):
                        print(f"    MQTT disconnected rc={rc}")

                    mqtt_success = False
                    for _cred_user, _cred_pwd, _cred_label in _cred_candidates:
                        # For the first credential combo, also try all WS paths.
                        # For subsequent combos use the default path (skip path sweep
                        # once we know rc=4 = bad creds on the default path).
                        _paths_to_try = _ws_paths if _cred_label == _cred_candidates[0][2] else [path]
                        for _try_path in _paths_to_try:
                            _path_label = f" path={_try_path}" if _try_path != path else ""
                            print(f"\n    [MQTT attempt] {_cred_label}{_path_label}  user={_cred_user[:16]}...")
                            connect_rc_box[0] = None
                            messages_seen.clear()
                            done_event.clear()
                            _client_id = f"app-{_smarthome_uid}"

                            def _run(_u=_cred_user, _p=_cred_pwd, _cid=_client_id, _wp=_try_path):
                                mqttc = _mqtt.Client(client_id=_cid, transport=transport)
                                if use_tls:
                                    mqttc.tls_set(cert_reqs=_ssl.CERT_REQUIRED)
                                if transport == "websockets":
                                    mqttc.ws_set_options(path=_wp)
                                mqttc.username_pw_set(_u, _p)
                                mqttc.on_connect    = _on_connect
                                mqttc.on_message    = _on_message
                                mqttc.on_disconnect = _on_disconnect
                                try:
                                    mqttc.connect(host, port, keepalive=30)
                                    mqttc.loop_start()
                                    done_event.wait(timeout=8)
                                except Exception as e:
                                    print(f"    MQTT connect exception: {e}")
                                finally:
                                    mqttc.loop_stop()
                                    try:
                                        mqttc.disconnect()
                                    except Exception:
                                        pass

                            await asyncio.get_event_loop().run_in_executor(None, _run)

                            if connect_rc_box[0] == 0:
                                print(f"    *** MQTT CONNECTED with {_cred_label}{_path_label} ***")
                                mqtt_success = True
                                if messages_seen:
                                    print(f"    MQTT: {len(messages_seen)} message(s) received")
                                else:
                                    print("    MQTT: connected but no response to connectipc within 8s")
                                break
                            else:
                                print(f"    rc={connect_rc_box[0]} -> skip")

                        if mqtt_success:
                            break

                    if not mqtt_success:
                        print("\n    MQTT: all credential combinations failed (rc=4 or rc=5)")

            if args.live and not args.diag_mqtt:
                print(f"\n[LIVE] Opening live stream for {cam.get('name', cam.get('id'))} ...")
                print("    (Ctrl+C to stop early)")

                session = await dc.async_open_live_stream(on_frame)
                if session is None:
                    print("    FAILED to open live stream session.")
                else:
                    print(f"    Session open — streaming for {args.live_seconds}s ...")
                    try:
                        await asyncio.sleep(args.live_seconds)
                    except asyncio.CancelledError:
                        pass
                    finally:
                        await session.stop()
                    print("    Session stopped.")


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

    args = parser.parse_args()

    # Default: run all tests if no specific flag given
    if not any([args.p2p, args.list_recordings, args.play, args.live, args.diag_mqtt]):
        args.p2p             = True
        args.list_recordings = True
        args.play            = True
        args.live            = True

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted.")


if __name__ == "__main__":
    main()
