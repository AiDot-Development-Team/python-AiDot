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
    import logging as _logging
    _logging.basicConfig(
        level=_logging.WARNING,
        format="%(name)s %(levelname)s: %(message)s",
    )
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
            print("    via --device-id if you know which one is a camera.")
            return

        print(f"    {len(cameras)} camera(s) detected:")
        for cam in cameras:
            print(f"      {cam.get('id')}  model={cam.get('modelId')}  name={cam.get('name')}")

        if args.device:
            cameras = [c for c in cameras if c.get("id") == args.device]
            if not cameras:
                print(f"    --device {args.device!r} not found in camera list")
                return
            print(f"    Filtered to device {args.device!r}")

        # Collect all camera IDs upfront for batch API calls.
        # The app sends all device IDs in a single batchGetDeviceUserInfo request
        # (~260 bytes for 7 devices); sending only one may return an empty result.
        _all_camera_ids = [c.get("id") for c in cameras if c.get("id")]

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
                print(f"\n[DIAG] All raw device fields for {cam.get('name')}:")
                for _dk, _dv in cam.items():
                    if _dk != "product":
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
    parser.add_argument("--device", metavar="DEVICE_ID",
                        help="Run tests on only the camera with this AiDot device UID")

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
