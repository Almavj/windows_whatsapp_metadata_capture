
"""WhatsApp for Windows call peer-metadata capture. See README.md for usage."""

import argparse
import collections
import datetime
import html as html_mod
import json
import os
import struct
import sys
import time
import urllib.parse
import urllib.request
import webbrowser

try:
    import frida
except ImportError:
    print("frida not installed:  pip install frida", file=sys.stderr)
    sys.exit(1)

PROCESS = "WhatsApp.Root.exe"

AGENT = r"""
'use strict';

var VOIP = 'WhatsAppNative.Voip.dll';

// RVA tables are per-build. WhatsApp Desktop auto-updates and every offset
// shifts when it does, so hooking a build we have no table for plants inline
// trampolines at wrong addresses and crashes WhatsApp on the next call. Keyed
// by the loaded module's byte size (a cheap, reliable build fingerprint).
// Resolved from the self-labeling assert macro + .pdata; see resolve_rva.py.
// KEY = PE SizeOfImage (in-memory mapped size = Frida module.size), NOT the
// on-disk file size — the two differ by section padding.
var BUILDS = {
  12525568: {   // WhatsAppDesktop 2.2631.102.0  (SizeOfImage 0xBF2000)
    wa_call_set_field_stat_numeric:                       0x68600,
    wa_call_set_field_stat_str:                           0x68900,
    parse_endpoint_address:                              0x2853B0,
    platform_to_cstr:                                    0x20C1E0,
    wa_transport_get_peer_public_addr_str:               0x415270,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x20A4A0,
    wa_call_participant_get_peer_test_bucket_str:        0x20A450,
    wa_call_participant_get_multi_device_info_count:     0x20A890,
    wa_call_participant_get_active_device_info_const:    0x20A7B0,
    wa_call_participant_get_audio_level:                 0x20B8A0,
    wa_call_participant_get_offer_msg:                   0x20AB80,
  },
  12619776: {   // WhatsAppDesktop 2.2632.100.0  (SizeOfImage 0xC09000)
    wa_call_set_field_stat_numeric:                       0x64D70,
    wa_call_set_field_stat_str:                           0x65070,
    parse_endpoint_address:                              0x285390,
    platform_to_cstr:                                    0x20BD90,
    wa_transport_get_peer_public_addr_str:               0x42D200,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x20A050,
    wa_call_participant_get_peer_test_bucket_str:        0x20A000,
    wa_call_participant_get_multi_device_info_count:     0x20A440,
    wa_call_participant_get_active_device_info_const:    0x20A360,
    wa_call_participant_get_audio_level:                 0x20B450,
    wa_call_participant_get_offer_msg:                   0x20A730,
  },
  12709888: {   // WhatsAppDesktop 2.2636.100.0  (SizeOfImage 0xC1F000)
    wa_call_set_field_stat_numeric:                       0x65730,
    wa_call_set_field_stat_str:                           0x659E0,
    parse_endpoint_address:                              0x28BFF0,
    platform_to_cstr:                                    0x212170,
    wa_transport_get_peer_public_addr_str:               0x4335B0,
    wa_call_participant_get_peer_test_bucket_id_list_str: 0x210370,
    wa_call_participant_get_peer_test_bucket_str:        0x210320,
    wa_call_participant_get_multi_device_info_count:     0x210760,
    wa_call_participant_get_active_device_info_const:    0x210680,
    wa_call_participant_get_audio_level:                 0x211830,
    wa_call_participant_get_offer_msg:                   0x210A50,
  },
};
var RVA = null;   // selected at runtime from BUILDS by module size

var PLATFORM = ['unknown','android','iphone','wp','ios_tablet','kaios','windows',
  'portal','mac_os_electron','windows_electron','wearm','macos','capi','ipad',
  'smba','smbi','web'];

var OFF_PLATFORM = 0x58;

function emit(ev, data) { data = data || {}; data.event = ev; data.ts = Date.now(); send(data); }

function cstr(p) {
  try { return (p === null || p.isNull()) ? null : p.readUtf8String(); }
  catch (e) { return null; }
}

function moduleBase(name) {
  var lower = name.toLowerCase();
  try {
    if (typeof Module.findBaseAddress === 'function') {
      var b = Module.findBaseAddress(name);
      if (b) return b;
    }
  } catch (e) {}
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(name);
      if (m) return m.base;
    }
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (String(mods[i].name).toLowerCase() === lower) return mods[i].base;
    }
  } catch (e) {}
  return null;
}

function moduleSize(name) {
  var lower = name.toLowerCase();
  try {
    if (typeof Process.findModuleByName === 'function') {
      var m = Process.findModuleByName(name);
      if (m && m.size) return m.size;
    }
  } catch (e) {}
  try {
    var mods = Process.enumerateModules();
    for (var i = 0; i < mods.length; i++) {
      if (String(mods[i].name).toLowerCase() === lower) return mods[i].size;
    }
  } catch (e) {}
  return null;
}

function main() {
  var base = moduleBase(VOIP);
  if (base === null) { emit('error', { message: VOIP + ' not loaded' }); return; }

  // Pick the RVA table for THIS build. If we don't recognise it, refuse to
  // hook — planting hooks at stale offsets is exactly what crashes WhatsApp.
  var size = moduleSize(VOIP);
  RVA = BUILDS[size];
  if (!RVA) {
    emit('error', {
      message: 'unknown ' + VOIP + ' build (size=' + size + ') — refusing to hook ' +
               'so WhatsApp will not crash. Re-run resolve_rva.py against this DLL and ' +
               'add a BUILDS[' + size + '] entry.',
      module_size: size
    });
    return;
  }

  function at(n) { return base.add(RVA[n]); }
  var hooked = [];

  try {
    Interceptor.attach(at('wa_call_set_field_stat_numeric'), {
      onEnter: function (args) {
        var name = cstr(args[1]);
        if (!name) return;
        var v = null;
        try { v = this.context.rsp.add(0x38).readDouble(); } catch (e) {}
        emit('field_stat', { name: name, field_id: args[2].toInt32(), value: v });
      }
    });
    hooked.push('field_stat_numeric');
  } catch (e) { emit('hook_error', { fn: 'field_stat_numeric', err: String(e) }); }

  try {
    Interceptor.attach(at('wa_call_set_field_stat_str'), {
      onEnter: function (args) {
        var name = cstr(args[1]);
        if (!name) return;
        emit('field_stat_str', { name: name, field_id: args[2].toInt32(), value: cstr(args[3]) });
      }
    });
    hooked.push('field_stat_str');
  } catch (e) { emit('hook_error', { fn: 'field_stat_str', err: String(e) }); }

  try {
    var seenEp = {};
    Interceptor.attach(at('parse_endpoint_address'), {
      onEnter: function (args) { this.out = args[1]; },
      onLeave: function (ret) {
        if (ret.toInt32() === 0 || this.out.isNull()) return;
        try {
          var o = this.out;
          var v4 = o.add(0x18).readU8() !== 0, v6 = o.add(0x19).readU8() !== 0;
          var rec = {};
          if (v4) {
            var b = new Uint8Array(o.readByteArray(4));
            rec.ipv4 = b[0] + '.' + b[1] + '.' + b[2] + '.' + b[3];
            rec.ipv4_port = o.add(0x14).readU16();
          }
          if (v6) {
            var c = new Uint8Array(o.add(4).readByteArray(16)), parts = [];
            for (var k = 0; k < 16; k += 2) parts.push(((c[k] << 8) | c[k+1]).toString(16));
            rec.ipv6 = '[' + parts.join(':') + ']';
            rec.ipv6_port = o.add(0x16).readU16();
          }
          var key = (rec.ipv4 || rec.ipv6) + ':' + (rec.ipv4_port || rec.ipv6_port);
          if (seenEp[key]) return;
          seenEp[key] = 1;
          emit('endpoint', rec);
        } catch (e) {}
      }
    });
    hooked.push('parse_endpoint_address');
  } catch (e) { emit('hook_error', { fn: 'parse_endpoint_address', err: String(e) }); }

  try {
    var lastPlat = null;
    Interceptor.attach(at('wa_call_participant_get_active_device_info_const'), {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try {
          var p = ret.add(OFF_PLATFORM).readU32();
          if (p === 0 || p === lastPlat) return;
          lastPlat = p;
          emit('peer_platform', {
            platform_id: p,
            platform: (p < PLATFORM.length) ? PLATFORM[p] : 'out_of_range'
          });
        } catch (e) {}
      }
    });
    hooked.push('peer_platform');
  } catch (e) {}

  function scalar(fnName, evName, field) {
    try {
      var lastByCtx = {};
      Interceptor.attach(at(fnName), {
        onEnter: function (args) { this.ctx = args[0].toString(); },
        onLeave: function (ret) {
          var v; try { v = ret.toInt32(); } catch (e) { return; }
          if (lastByCtx[this.ctx] === v) return;
          lastByCtx[this.ctx] = v;
          var rec = { ctx: this.ctx }; rec[field] = v;
          emit(evName, rec);
        }
      });
      hooked.push(evName);
    } catch (e) {}
  }
  scalar('wa_call_participant_get_multi_device_info_count', 'peer_device_count', 'device_count');
  scalar('wa_call_participant_get_audio_level', 'peer_audio_level', 'level');

  try {
    Interceptor.attach(at('wa_transport_get_peer_public_addr_str'), {
      onEnter: function (args) { this.buf = args[1]; },
      onLeave: function () {
        var s = cstr(this.buf);
        if (s) emit('peer_public_addr', { addr: s });
      }
    });
    hooked.push('peer_public_addr');
  } catch (e) {}

  ['wa_call_participant_get_peer_test_bucket_id_list_str',
   'wa_call_participant_get_peer_test_bucket_str'].forEach(function (n) {
    try {
      var last = null;
      Interceptor.attach(at(n), {
        onLeave: function (ret) {
          var s = cstr(ret);
          if (!s || s === last) return;
          last = s;
          emit('peer_test_bucket', { fn: n, value: s });
        }
      });
      hooked.push(n);
    } catch (e) {}
  });

  try {
    var lastOffer = null;
    Interceptor.attach(at('wa_call_participant_get_offer_msg'), {
      onLeave: function (ret) {
        if (ret.isNull()) return;
        try {
          var b = new Uint8Array(ret.readByteArray(192)), runs = [], cur = '';
          for (var i = 0; i < b.length; i++) {
            var c = b[i];
            if (c >= 0x20 && c < 0x7f) cur += String.fromCharCode(c);
            else { if (cur.length >= 8) runs.push(cur); cur = ''; }
          }
          if (cur.length >= 8) runs.push(cur);
          var key = runs.join('|');
          if (!runs.length || key === lastOffer) return;
          lastOffer = key;
          emit('peer_offer_msg', { strings: runs });
        } catch (e) {}
      }
    });
    hooked.push('peer_offer_msg');
  } catch (e) {}

  emit('hook_ready', { module: VOIP, base: base.toString(), module_size: size, hooked: hooked });
}

if (moduleBase(VOIP) !== null) main();
else {
  var iv = setInterval(function () {
    if (moduleBase(VOIP) !== null) { clearInterval(iv); main(); }
  }, 250);
  emit('waiting', { message: VOIP + ' not yet loaded' });
}
"""

META_V4 = [
    ("31.13.0.0", 16), ("157.240.0.0", 16), ("185.60.216.0", 22),
    ("179.60.192.0", 22), ("129.134.0.0", 16), ("66.220.144.0", 20),
    ("69.63.176.0", 20), ("69.171.224.0", 19), ("74.119.76.0", 22),
    ("102.132.96.0", 20), ("103.4.96.0", 22), ("173.252.64.0", 18),
    ("204.15.20.0", 22), ("163.70.128.0", 17), ("57.144.0.0", 14),
]

NETWORK_MEDIUM = {
    0: "unclassified (connected, but type could not be determined)",
    1: "cellular",
    2: "not cellular (Wi-Fi, or Ethernet on a desktop peer)",
    3: "no active network resolved when the stanza was composed",
}

def ip_to_int(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        parts = [int(x) for x in parts]
    except ValueError:
        return None
    if any(p < 0 or p > 255 for p in parts):
        return None
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]

def is_meta(ip):
    if not ip:
        return False
    if ":" in ip:
        return ip.lstrip("[").lower().startswith("2a03:2880")
    value = ip_to_int(ip)
    if value is None:
        return False
    for net, bits in META_V4:
        base = ip_to_int(net)
        mask = 0 if bits == 0 else (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
        if (value & mask) == (base & mask):
            return True
    return False

def addr_class(ip):
    if not ip:
        return "unknown"
    if ":" in ip:
        return "ipv6"
    try:
        parts = [int(x) for x in ip.split(".")]
    except ValueError:
        return "unknown"
    if len(parts) != 4:
        return "unknown"
    if parts[0] == 10 or (parts[0] == 172 and 16 <= parts[1] <= 31) \
            or (parts[0] == 192 and parts[1] == 168):
        return "private (RFC1918)"
    if parts[0] == 100 and 64 <= parts[1] <= 127:
        return "carrier-grade NAT (RFC6598)"
    if parts[0] == 127:
        return "loopback"
    return "public"

def num_list(text):
    if not text:
        return None
    try:
        return [float(x) for x in str(text).split(",") if x != ""]
    except ValueError:
        return None


def geolocate_ip(ip):
    """Resolve an IP to an approximate location via ip-api.com.

    Free, keyless, no dependency beyond the stdlib. Returns a dict with lat/lon,
    city, country, ISP and AS, or a dict with an 'error' key when the lookup
    fails (offline, rate-limited, or a reserved address). Never raises.
    """
    if not ip:
        return None
    ip = str(ip).strip().strip("[]")
    if ip.startswith(("10.", "127.", "192.168.", "169.254.")) or ip in ("", "0.0.0.0"):
        return {"query": ip, "error": "reserved / non-routable address"}
    fields = ("status,message,country,countryCode,regionName,city,zip,"
              "lat,lon,timezone,isp,org,as,query")
    url = "http://ip-api.com/json/%s?fields=%s" % (
        urllib.parse.quote(ip), urllib.parse.quote(fields))
    try:
        with urllib.request.urlopen(url, timeout=6) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as exc:
        return {"query": ip, "error": "lookup failed: %s" % exc}
    if data.get("status") != "success":
        return {"query": ip, "error": data.get("message") or "lookup unsuccessful"}
    return data

def build_report(events, geo_lookup=True):
    numeric, strings = {}, {}
    for e in events:
        if e.get("event") == "field_stat":
            numeric[e["name"]] = e.get("value")
        elif e.get("event") == "field_stat_str":
            strings[e["name"]] = e.get("value")

    stamps = [e["ts"] for e in events if "ts" in e]
    duration_ms = (max(stamps) - min(stamps)) if stamps else 0

    def get(name):
        return numeric.get(name)

    contexts = collections.defaultdict(dict)
    for e in events:
        ctx = e.get("ctx")
        if not ctx:
            continue
        entry = contexts[ctx]
        entry["events"] = entry.get("events", 0) + 1
        if e.get("event") == "peer_device_count":
            entry["device_count"] = e.get("device_count")
    peer_ctx = None
    for ctx, entry in contexts.items():
        if entry.get("device_count"):
            peer_ctx = ctx

    relays, peer_side, seen = [], [], set()
    for e in events:
        if e.get("event") != "endpoint":
            continue
        for ip, port in ((e.get("ipv4"), e.get("ipv4_port")),
                         (e.get("ipv6"), e.get("ipv6_port"))):
            if not ip or (ip, port) in seen:
                continue
            seen.add((ip, port))
            row = {"ip": ip, "port": port, "address_class": addr_class(ip.strip("[]"))}
            (relays if is_meta(ip) else peer_side).append(row)

    public_eps = [e for e in peer_side if e["address_class"] == "public"]
    private_eps = [e for e in peer_side
                   if "private" in e["address_class"] or "carrier" in e["address_class"]]

    our_rtt = num_list(strings.get("relay_measured_c2r_rtt_list"))
    peer_rtt = num_list(strings.get("relay_measured_max_peer_c2r_rtt_list"))
    servers = [s.strip() for s in (strings.get("call_relay_servers") or "").split(",") if s.strip()]

    latency, degenerate = [], None
    if our_rtt and peer_rtt and len(our_rtt) == len(peer_rtt):

        degenerate = (len(set(peer_rtt)) == 1) or any(v < 0 for v in peer_rtt)
        for i, (ours, theirs) in enumerate(zip(our_rtt, peer_rtt)):
            delta = theirs - ours
            latency.append({
                "relay": servers[i] if i < len(servers) else None,
                "our_rtt_ms": ours, "peer_rtt_ms": theirs, "delta_ms": delta,

                "_note": ("peer is closer to this relay than we are"
                          if delta < 0 else
                          "peer is farther from this relay than we are"),
            })

    levels = [(e["ts"], e.get("level")) for e in events
              if e.get("event") == "peer_audio_level"
              and (peer_ctx is None or e.get("ctx") == peer_ctx)]
    speech = None
    if levels:
        t0 = levels[0][0]
        vals = [v for _, v in levels if v is not None]
        loud = [v for v in vals if v > 0]
        speech = {
            "samples": len(levels),
            "approx_interval_ms": round((levels[-1][0] - t0) / max(1, len(levels) - 1)),
            "max_level": max(vals) if vals else None,
            "mean_level_while_speaking": round(sum(loud) / len(loud), 1) if loud else None,
            "silent_samples": len(vals) - len(loud),
            "series": [{"t_ms": t - t0, "level": v} for t, v in levels],
            "_note": "speech energy sampled by the client; zeros are silence",
        }

    platform = strings.get("call_peer_platform")
    for e in events:
        if e.get("event") == "peer_platform" and not platform:
            platform = e.get("platform")

    device_count = None
    for e in events:
        if e.get("event") == "peer_device_count" and e.get("device_count"):
            device_count = e.get("device_count")

    call_ids = []
    for e in events:
        if e.get("event") == "peer_offer_msg":
            call_ids.extend(e.get("strings") or [])

    medium_peer, medium_self = get("peer_call_network"), get("call_network")

    geo_ip, geo_source = None, None
    if public_eps:
        geo_ip = public_eps[0]["ip"]
        geo_source = "public_endpoint (unmasked)"
    elif strings.get("call_peer_ip_str"):
        geo_ip = strings.get("call_peer_ip_str")
        geo_source = "telemetry (masked /24)"
    geolocation = None
    if geo_ip and geo_lookup:
        geolocation = geolocate_ip(geo_ip)
        if isinstance(geolocation, dict):
            geolocation["source"] = geo_source

    return {
        "capture": {
            "events": len(events),
            "duration_s": round(duration_ms / 1000.0, 1),
            "numeric_fields": len(numeric),
            "string_fields": len(strings),
        },
        "peer": {
            "identity": {
                "platform": platform,
                "app_version": strings.get("call_peer_app_version"),
                "device_class": strings.get("device_class"),
                "hardware_year_class": get("peer_year_class_2016"),
                "linked_device_count": device_count,
                "_note": "platform from the 17-entry platform_to_cstr enum; "
                         "device count from multi_device_info_count",
            },
            "network": {
                "public_endpoints": [
                    dict(e, _note="server-reflexive candidate from call signalling "
                                  "— full address and port, not masked")
                    for e in public_eps],
                "private_endpoints": [
                    dict(e, _note="host candidate from the peer's own LAN or carrier "
                                  "NAT; delivered even when the two sides are on "
                                  "different networks")
                    for e in private_eps],
                "telemetry_view": {
                    "peer_public_ip_masked": strings.get("call_peer_ip_str"),
                    "peer_lan_prefix_masked": strings.get("peer_local_ip_prefix"),
                    "_note": "the telemetry path masks the peer address to /24 while "
                             "the signalling path above does not",
                },
                "geolocation": geolocation,
                "medium": {
                    "peer": medium_peer,
                    "peer_meaning": NETWORK_MEDIUM.get(int(medium_peer)) if medium_peer is not None else None,
                    "self": medium_self,
                    "self_meaning": NETWORK_MEDIUM.get(int(medium_self)) if medium_self is not None else None,
                },
                "nat": {
                    "symmetric": bool(get("is_in_sym_nat")) if get("is_in_sym_nat") is not None else None,
                    "ipv6_capable": bool(get("is_ipv6_capable")) if get("is_ipv6_capable") is not None else None,
                    "p2p_disabled": bool(get("call_p2p_disabled")) if get("call_p2p_disabled") is not None else None,
                    "_note": "p2p_disabled is the desktop equivalent of Android's "
                             "disallowAllP2P(). False means 'Protect IP address in "
                             "calls' was not in effect. Media going over a relay does "
                             "not imply the address was protected — candidates are "
                             "still exchanged either way.",
                },
            },
            "relays": {
                "servers": servers,
                "observed_candidates": [
                    dict(r, _note="Meta infrastructure — the relay, not the peer")
                    for r in relays],
                "latency": latency,
                "latency_usable": (None if degenerate is None else not degenerate),
                "latency_spread_ms": (round(max(peer_rtt) - min(peer_rtt), 1)
                                      if peer_rtt and not degenerate else None),
                "_note": "identical or negative peer values are placeholders; no "
                         "location inference can be drawn from them. A mixed "
                         "profile (closer to some relays, farther from others) "
                         "is more discriminating than a uniform one.",
            },
            "behaviour": {
                "speech_activity": speech,
                "silence_ms": get("dtx_rx_duration_t"),
                "silence_ratio_pct": (round(100.0 * get("dtx_rx_duration_t") / duration_ms, 1)
                                      if get("dtx_rx_duration_t") and duration_ms else None),
                "_note": "dtx_rx_duration_t is how long the peer transmitted nothing",
            },
            "fingerprint": {
                "frame_length_ms": get("avg_rx_frame_length_ms"),
                "decode_time_ms": get("avg_decode_t"),
                "jitter_buffer_ms": get("jb_avg_delay"),
                "uplink_bwe_bps": get("call_rx_avg_bwe"),
                "_note": "rx-side values describe what the peer produced",
            },
            "correlation": {
                "abtest_bucket": strings.get("call_peer_test_bucket"),
                "abtest_id_list": strings.get("call_peer_test_bucket_id_list"),
                "call_ids": call_ids,
                "_note": "the bucket id was identical across three calls to the same "
                         "device, so it links calls over a short window. It tracks the "
                         "DEVICE: another device on the same account gave a different "
                         "platform, version and LAN address.",
            },
        },
        "self": {
            "public_ip": strings.get("call_self_ip_str"),
            "lan_prefix": strings.get("local_ip_prefix"),
            "reflexive_ip": strings.get("signaling_reflexive_ip_self"),
            "_note": "included so peer values can be told apart from ours",
        },
        "participant_contexts": [
            {"ctx": ctx,
             "role": "peer" if ctx == peer_ctx else ("self" if peer_ctx else "unknown"),
             "device_count": entry.get("device_count"),
             "events": entry.get("events")}
            for ctx, entry in contexts.items()],
        "caveats": [
            "No JID or phone number exists on this layer — confirmed across three "
            "runs; the VoIP layer works with a call id instead.",
            "No location data in call signalling; relay latency is the only "
            "geographic proxy and it is not always a real measurement.",
            "battery_low is present in telemetry but which side it belongs to was "
            "never established.",
            "WAM hooks did not fire during calls, so the messaging surface is not "
            "covered here.",
        ],
    }

I18N = {
    "en": {
        "app.title": "WhatsApp Peer Capture",
        "app.subtitle": "Metadata observed from the other side of the call",
        "app.generated": "generated",
        "app.lang": "Language",
        "footer": "wa_peer.py - authorized research capture - data reflects a single call",
        "stat.events": "events", "stat.duration": "duration (s)",
        "stat.numeric": "numeric fields", "stat.strings": "string fields",
        "hl.public": "Peer public endpoint (unmasked, from call signalling)",
        "hl.telemetry": "Peer public IP (telemetry, masked to /24)",
        "hl.none_label": "Peer address", "hl.none_value": "not captured this run",
        "sec.identity": "Peer identity", "sec.mediumnat": "Network medium & NAT",
        "sec.public": "Public endpoints (unmasked)",
        "sec.private": "Private / host endpoints",
        "sec.telemetry": "Telemetry view (masked)",
        "sec.geo": "IP geolocation", "sec.map": "Location map",
        "sec.behaviour": "Behaviour", "sec.relays": "Relay servers",
        "sec.speech": "Speech activity", "sec.fingerprint": "RX fingerprint",
        "sec.correlation": "Correlation", "sec.self": "Our side (self)",
        "sec.callids": "Call IDs", "sec.caveats": "Caveats",
        "lbl.platform": "Platform", "lbl.appver": "App version",
        "lbl.devclass": "Device class", "lbl.hwyear": "Hardware year class",
        "lbl.linked": "Linked device count",
        "lbl.peer_medium": "Peer network medium",
        "lbl.self_medium": "Self network medium",
        "lbl.sym_nat": "Symmetric NAT", "lbl.ipv6": "IPv6 capable",
        "lbl.p2p": "P2P disabled (IP protected)",
        "lbl.pub_masked": "Peer public IP (masked /24)",
        "lbl.lan_masked": "Peer LAN prefix (masked)",
        "lbl.geo_source": "Source", "lbl.geo_ip": "IP", "lbl.city": "City",
        "lbl.region": "Region", "lbl.country": "Country",
        "lbl.zip": "Postal code", "lbl.coords": "Coordinates",
        "lbl.tz": "Timezone", "lbl.isp": "ISP", "lbl.org": "Organization",
        "lbl.asn": "AS / network",
        "lbl.silence_ms": "Silence (ms)", "lbl.silence_ratio": "Silence ratio (%)",
        "lbl.samples": "Samples", "lbl.interval": "Sample interval (ms)",
        "lbl.max_level": "Max level",
        "lbl.mean_level": "Mean level while speaking",
        "lbl.silent_samples": "Silent samples",
        "lbl.frame_len": "Avg frame length (ms)",
        "lbl.decode_t": "Avg decode time (ms)",
        "lbl.jitter": "Jitter buffer (ms)", "lbl.uplink": "Uplink BWE (bps)",
        "lbl.ab_bucket": "A/B test bucket", "lbl.ab_list": "A/B test id list",
        "lbl.pub_ip": "Public IP", "lbl.lan_prefix": "LAN prefix",
        "lbl.reflexive": "Reflexive IP", "lbl.servers": "servers",
        "th.ip": "IP", "th.port": "Port", "th.class": "Class",
        "th.relay": "Relay", "th.our_rtt": "Our RTT",
        "th.peer_rtt": "Peer RTT", "th.delta": "delta ms",
        "empty.none": "none captured", "empty.nodata": "no data captured",
        "empty.no_latency": "no usable latency samples",
        "empty.no_speech": "no speech-energy samples", "empty.none2": "none",
        "map.nogeo": "No location: no routable public IP was captured this run.",
        "map.error": "Location lookup failed or was skipped (--no-geo).",
        "map.offline": "Map tiles need an internet connection.",
        "cav.0": "No JID or phone number exists on this layer - confirmed across three runs; the VoIP layer works with a call id instead.",
        "cav.1": "No location data in call signalling; relay latency is the only geographic proxy and it is not always a real measurement.",
        "cav.2": "battery_low is present in telemetry but which side it belongs to was never established.",
        "cav.3": "WAM hooks did not fire during calls, so the messaging surface is not covered here.",
    },
}



def _t_en(key):
    return I18N["en"].get(key, key)


def _esc(v):
    if v is None or v == "":
        return "&mdash;"
    return html_mod.escape(str(v))


def _rows(pairs):
    """pairs: list of (i18n_key, value). Skips rows whose value is None/''.

    The label is emitted with a data-i18n key plus its English text as a no-JS
    fallback; the client-side switcher overwrites it in the chosen language.
    """
    out = []
    for key, value in pairs:
        if value is None or value == "":
            continue
        out.append(
            '<div class="row"><span class="k" data-i18n="%s">%s</span>'
            '<span class="v">%s</span></div>'
            % (key, _esc(_t_en(key)), _esc(value)))
    return out and "".join(out) or (
        '<div class="empty" data-i18n="empty.nodata">%s</div>'
        % _esc(_t_en("empty.nodata")))


def render_html(report):
    peer = report.get("peer", {})
    ident = peer.get("identity", {})
    net = peer.get("network", {})
    relays = peer.get("relays", {})
    behaviour = peer.get("behaviour", {})
    fp = peer.get("fingerprint", {})
    corr = peer.get("correlation", {})
    selfd = report.get("self", {})
    cap = report.get("capture", {})

    public_eps = net.get("public_endpoints", []) or []
    private_eps = net.get("private_endpoints", []) or []
    tele = net.get("telemetry_view", {}) or {}
    medium = net.get("medium", {}) or {}
    nat = net.get("nat", {}) or {}
    geo = net.get("geolocation") or {}

    headline_ip, headline_key = None, None
    if public_eps:
        headline_ip = "%s:%s" % (public_eps[0].get("ip"), public_eps[0].get("port"))
        headline_key = "hl.public"
    elif tele.get("peer_public_ip_masked"):
        headline_ip = tele.get("peer_public_ip_masked")
        headline_key = "hl.telemetry"

    if headline_ip:
        headline_block = (
            '<div class="headline"><div class="hl-label" data-i18n="%s">%s</div>'
            '<div class="hl-ip">%s</div></div>'
            % (headline_key, _esc(_t_en(headline_key)), _esc(headline_ip)))
    else:
        headline_block = (
            '<div class="headline none">'
            '<div class="hl-label" data-i18n="hl.none_label">%s</div>'
            '<div class="hl-ip" data-i18n="hl.none_value">%s</div></div>'
            % (_esc(_t_en("hl.none_label")), _esc(_t_en("hl.none_value"))))

    def ep_table(eps):
        if not eps:
            return ('<div class="empty" data-i18n="empty.none">%s</div>'
                    % _esc(_t_en("empty.none")))
        body = "".join(
            '<tr><td class="mono">%s</td><td class="mono">%s</td><td>%s</td></tr>'
            % (_esc(e.get("ip")), _esc(e.get("port")), _esc(e.get("address_class")))
            for e in eps)
        return ('<table><thead><tr>'
                '<th data-i18n="th.ip">%s</th>'
                '<th data-i18n="th.port">%s</th>'
                '<th data-i18n="th.class">%s</th>'
                '</tr></thead><tbody>%s</tbody></table>'
                % (_esc(_t_en("th.ip")), _esc(_t_en("th.port")),
                   _esc(_t_en("th.class")), body))

    latency = relays.get("latency", []) or []
    if latency:
        lat_body = "".join(
            '<tr><td class="mono">%s</td><td>%s</td><td>%s</td>'
            '<td class="%s">%s</td></tr>' % (
                _esc(l.get("relay")), _esc(l.get("our_rtt_ms")),
                _esc(l.get("peer_rtt_ms")),
                "neg" if (l.get("delta_ms") or 0) < 0 else "pos",
                _esc(l.get("delta_ms")))
            for l in latency)
        lat_html = ('<table><thead><tr>'
                    '<th data-i18n="th.relay">%s</th>'
                    '<th data-i18n="th.our_rtt">%s</th>'
                    '<th data-i18n="th.peer_rtt">%s</th>'
                    '<th data-i18n="th.delta">%s</th>'
                    '</tr></thead><tbody>%s</tbody></table>'
                    % (_esc(_t_en("th.relay")), _esc(_t_en("th.our_rtt")),
                       _esc(_t_en("th.peer_rtt")), _esc(_t_en("th.delta")), lat_body))
    else:
        lat_html = ('<div class="empty" data-i18n="empty.no_latency">%s</div>'
                    % _esc(_t_en("empty.no_latency")))

    speech = behaviour.get("speech_activity")
    if speech:
        speech_html = _rows([
            ("lbl.samples", speech.get("samples")),
            ("lbl.interval", speech.get("approx_interval_ms")),
            ("lbl.max_level", speech.get("max_level")),
            ("lbl.mean_level", speech.get("mean_level_while_speaking")),
            ("lbl.silent_samples", speech.get("silent_samples")),
        ])
    else:
        speech_html = ('<div class="empty" data-i18n="empty.no_speech">%s</div>'
                       % _esc(_t_en("empty.no_speech")))

    call_ids = corr.get("call_ids") or []
    call_ids_html = ("".join('<span class="chip">%s</span>' % _esc(c) for c in call_ids)
                     if call_ids else
                     '<div class="empty" data-i18n="empty.none2">%s</div>'
                     % _esc(_t_en("empty.none2")))

    if geo and not geo.get("error"):
        coords = None
        if geo.get("lat") is not None and geo.get("lon") is not None:
            coords = "%s, %s" % (geo.get("lat"), geo.get("lon"))
        geo_html = _rows([
            ("lbl.geo_source", geo.get("source")),
            ("lbl.geo_ip", geo.get("query")),
            ("lbl.city", geo.get("city")),
            ("lbl.region", geo.get("regionName")),
            ("lbl.country", "%s (%s)" % (geo.get("country"), geo.get("countryCode"))
             if geo.get("country") else None),
            ("lbl.zip", geo.get("zip")),
            ("lbl.coords", coords),
            ("lbl.tz", geo.get("timezone")),
            ("lbl.isp", geo.get("isp")),
            ("lbl.org", geo.get("org")),
            ("lbl.asn", geo.get("as")),
        ])
    elif geo and geo.get("error"):
        geo_html = ('<div class="empty">%s &mdash; %s</div>'
                    % (_esc(geo.get("query")), _esc(geo.get("error"))))
    else:
        geo_html = ('<div class="empty" data-i18n="map.nogeo">%s</div>'
                    % _esc(_t_en("map.nogeo")))

    if geo and not geo.get("error") and geo.get("lat") is not None \
            and geo.get("lon") is not None:
        label_bits = [b for b in (geo.get("city"), geo.get("country")) if b]
        label = ", ".join(label_bits) or geo.get("query") or ""
        if geo.get("query"):
            label = ("%s (%s)" % (label, geo.get("query"))).strip()
        map_cfg = {"state": "ok", "lat": geo.get("lat"), "lon": geo.get("lon"),
                   "label": label}
    elif geo and geo.get("error"):
        map_cfg = {"state": "error"}
    else:
        map_cfg = {"state": "nogeo"}

    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    caveats = report.get("caveats", []) or []
    caveats_html = "".join(
        '<li data-i18n="cav.%d">%s</li>' % (i, _esc(c))
        for i, c in enumerate(caveats))

    return HTML_TEMPLATE % {
        "i18n_json": json.dumps(I18N, ensure_ascii=True),
        "map_config": json.dumps(map_cfg, ensure_ascii=True),
        "generated": _esc(generated),
        "events": _esc(cap.get("events")),
        "duration": _esc(cap.get("duration_s")),
        "numeric": _esc(cap.get("numeric_fields")),
        "strings": _esc(cap.get("string_fields")),
        "headline": headline_block,
        "identity": _rows([
            ("lbl.platform", ident.get("platform")),
            ("lbl.appver", ident.get("app_version")),
            ("lbl.devclass", ident.get("device_class")),
            ("lbl.hwyear", ident.get("hardware_year_class")),
            ("lbl.linked", ident.get("linked_device_count")),
        ]),
        "public_eps": ep_table(public_eps),
        "private_eps": ep_table(private_eps),
        "telemetry": _rows([
            ("lbl.pub_masked", tele.get("peer_public_ip_masked")),
            ("lbl.lan_masked", tele.get("peer_lan_prefix_masked")),
        ]),
        "geo": geo_html,
        "medium_nat": _rows([
            ("lbl.peer_medium", medium.get("peer_meaning")),
            ("lbl.self_medium", medium.get("self_meaning")),
            ("lbl.sym_nat", nat.get("symmetric")),
            ("lbl.ipv6", nat.get("ipv6_capable")),
            ("lbl.p2p", nat.get("p2p_disabled")),
        ]),
        "servers": (", ".join(relays.get("servers", []))
                    if relays.get("servers") else None) or "&mdash;",
        "latency": lat_html,
        "speech": speech_html,
        "behaviour": _rows([
            ("lbl.silence_ms", behaviour.get("silence_ms")),
            ("lbl.silence_ratio", behaviour.get("silence_ratio_pct")),
        ]),
        "fingerprint": _rows([
            ("lbl.frame_len", fp.get("frame_length_ms")),
            ("lbl.decode_t", fp.get("decode_time_ms")),
            ("lbl.jitter", fp.get("jitter_buffer_ms")),
            ("lbl.uplink", fp.get("uplink_bwe_bps")),
        ]),
        "correlation": _rows([
            ("lbl.ab_bucket", corr.get("abtest_bucket")),
            ("lbl.ab_list", corr.get("abtest_id_list")),
        ]),
        "call_ids": call_ids_html,
        "self": _rows([
            ("lbl.pub_ip", selfd.get("public_ip")),
            ("lbl.lan_prefix", selfd.get("lan_prefix")),
            ("lbl.reflexive", selfd.get("reflexive_ip")),
        ]),
        "caveats": caveats_html,
    }


HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WhatsApp Peer Capture</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
  :root{
    --bg:#0b0e13; --panel:#151b24; --panel2:#1b2330; --border:#28313d;
    --text:#e7edf5; --muted:#8b97a7; --accent:#25d366; --accent2:#34b7f1;
    --neg:#3fb950; --pos:#d29922;
    --shadow:0 1px 0 rgba(255,255,255,.03),0 8px 24px rgba(0,0,0,.35);
  }
  *{box-sizing:border-box}
  html,body{scroll-behavior:smooth}
  body{margin:0;background:
      radial-gradient(1200px 600px at 80%% -10%%,rgba(52,183,241,.10),transparent 60%%),
      radial-gradient(900px 500px at -10%% 10%%,rgba(37,211,102,.10),transparent 55%%),
      var(--bg);
    color:var(--text);min-height:100vh;
    font:15px/1.55 "Segoe UI",Roboto,Helvetica,Arial,"Noto Sans Arabic",
      "Microsoft YaHei","PingFang SC",sans-serif;
    padding:28px 16px}
  .wrap{max-width:1040px;margin:0 auto}
  .topbar{display:flex;align-items:center;justify-content:space-between;
    gap:16px;flex-wrap:wrap;margin-bottom:6px}
  .brand{display:flex;align-items:center;gap:13px}
  .logo{width:42px;height:42px;border-radius:12px;flex:none;
    background:linear-gradient(135deg,var(--accent),var(--accent2));
    display:flex;align-items:center;justify-content:center;box-shadow:var(--shadow)}
  h1{font-size:22px;margin:0;font-weight:650;letter-spacing:.2px}
  .sub{color:var(--muted);font-size:13px;margin:3px 0 0}
  .stat-row{display:flex;gap:14px;flex-wrap:wrap;margin:22px 0}
  .stat{background:var(--panel);border:1px solid var(--border);border-radius:12px;
    padding:12px 18px;min-width:130px;box-shadow:var(--shadow)}
  .stat .n{font-size:22px;font-weight:650}
  .stat .l{color:var(--muted);font-size:11px;text-transform:uppercase;
    letter-spacing:.05em;margin-top:2px}
  .headline{background:linear-gradient(135deg,#12261b,#0f1f2b);
    border:1px solid var(--border);border-radius:16px;padding:22px 24px;
    margin-bottom:20px;box-shadow:var(--shadow);position:relative;overflow:hidden}
  .headline:before{content:"";position:absolute;inset:0;
    background:linear-gradient(135deg,rgba(37,211,102,.08),transparent 55%%);
    pointer-events:none}
  .headline.none{background:var(--panel)}
  .hl-label{color:var(--muted);font-size:12px;text-transform:uppercase;
    letter-spacing:.06em;margin-bottom:8px}
  .hl-ip{font:600 30px/1.15 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
    color:var(--accent);word-break:break-all}
  .headline.none .hl-ip{color:var(--muted);font-size:20px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));
    gap:16px}
  .card{background:var(--panel);border:1px solid var(--border);
    border-radius:16px;padding:18px 20px;box-shadow:var(--shadow);
    transition:border-color .15s ease,transform .15s ease}
  .card:hover{border-color:#33414f}
  .card.full{grid-column:1/-1}
  .card h2{font-size:12px;text-transform:uppercase;letter-spacing:.07em;
    color:var(--muted);margin:0 0 14px;font-weight:650;
    display:flex;align-items:center;gap:8px}
  .card h2:before{content:"";width:8px;height:8px;border-radius:3px;
    background:linear-gradient(135deg,var(--accent),var(--accent2))}
  .row{display:flex;justify-content:space-between;gap:16px;
    padding:8px 0;border-bottom:1px solid rgba(255,255,255,.05)}
  .row:last-child{border-bottom:0}
  .k{color:var(--muted)}
  .v{text-align:end;font-weight:500;word-break:break-word}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
  .empty{color:var(--muted);font-style:italic;font-size:13px}
  table{width:100%%;border-collapse:collapse;font-size:14px}
  th{text-align:start;color:var(--muted);font-weight:500;font-size:12px;
    padding:7px 8px;border-bottom:1px solid var(--border)}
  td{padding:8px 8px;border-bottom:1px solid rgba(255,255,255,.05)}
  td.neg{color:var(--neg)} td.pos{color:var(--pos)}
  .chip{display:inline-block;background:var(--panel2);border:1px solid var(--border);
    border-radius:20px;padding:4px 12px;margin:3px 4px 3px 0;font-size:12px;
    font-family:ui-monospace,monospace}
  #map{height:340px;width:100%%;border-radius:12px;overflow:hidden;
    display:none;border:1px solid var(--border)}
  #map-fallback{display:none}
  .leaflet-container{background:#0f141b}
  .caveats{margin:0;padding-inline-start:18px;color:var(--muted);font-size:13px}
  .caveats li{margin:7px 0}
  footer{color:var(--muted);font-size:12px;text-align:center;margin-top:30px}
</style>
</head>
<body>
<div class="wrap">
  <div class="topbar">
    <div class="brand">
      <div class="logo" aria-hidden="true">
        <svg viewBox="0 0 24 24" width="22" height="22" fill="none"
             stroke="#0b0e13" stroke-width="2" stroke-linecap="round"
             stroke-linejoin="round">
          <path d="M12 21s7-6.5 7-11a7 7 0 1 0-14 0c0 4.5 7 11 7 11z"></path>
          <circle cx="12" cy="10" r="2.5"></circle>
        </svg>
      </div>
      <div>
        <h1 data-i18n="app.title">WhatsApp Peer Capture</h1>
        <div class="sub"><span data-i18n="app.subtitle">Metadata observed from the other side of the call</span>
          &middot; <span data-i18n="app.generated">generated</span> %(generated)s</div>
      </div>
    </div>
  </div>

  <div class="stat-row">
    <div class="stat"><div class="n">%(events)s</div><div class="l" data-i18n="stat.events">events</div></div>
    <div class="stat"><div class="n">%(duration)s</div><div class="l" data-i18n="stat.duration">duration (s)</div></div>
    <div class="stat"><div class="n">%(numeric)s</div><div class="l" data-i18n="stat.numeric">numeric fields</div></div>
    <div class="stat"><div class="n">%(strings)s</div><div class="l" data-i18n="stat.strings">string fields</div></div>
  </div>

  %(headline)s

  <div class="grid">
    <div class="card">
      <h2 data-i18n="sec.geo">IP geolocation</h2>
      %(geo)s
    </div>
    <div class="card">
      <h2 data-i18n="sec.identity">Peer identity</h2>
      %(identity)s
    </div>
    <div class="card">
      <h2 data-i18n="sec.mediumnat">Network medium &amp; NAT</h2>
      %(medium_nat)s
    </div>
    <div class="card full">
      <h2 data-i18n="sec.map">Location map</h2>
      <div id="map"></div>
      <div id="map-fallback" class="empty"></div>
    </div>
    <div class="card full">
      <h2 data-i18n="sec.public">Public endpoints (unmasked)</h2>
      %(public_eps)s
    </div>
    <div class="card full">
      <h2 data-i18n="sec.private">Private / host endpoints</h2>
      %(private_eps)s
    </div>
  </div>
</div>

<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
var I18N = %(i18n_json)s;
var MAP = %(map_config)s;
var DEFAULT_LANG = "en";
var CUR = null;
try { CUR = localStorage.getItem("wa_lang"); } catch (e) {}
if (!CUR || !I18N[CUR]) { CUR = DEFAULT_LANG; }
var mapFallbackKey = null;

function tr(k){
  var d = I18N[CUR] || I18N.en;
  if (d && d[k] != null) return d[k];
  if (I18N.en[k] != null) return I18N.en[k];
  return k;
}
function applyLang(lang){
  CUR = I18N[lang] ? lang : "en";
  try { localStorage.setItem("wa_lang", CUR); } catch (e) {}
  var root = document.documentElement;
  root.lang = CUR;
  root.dir = (CUR === "ar") ? "rtl" : "ltr";
  var nodes = document.querySelectorAll("[data-i18n]");
  for (var i = 0; i < nodes.length; i++){
    var k = nodes[i].getAttribute("data-i18n");
    var v = tr(k);
    if (v != null) nodes[i].textContent = v;
  }
  var sel = document.getElementById("lang");
  if (sel) sel.value = CUR;
  if (mapFallbackKey){
    var fb = document.getElementById("map-fallback");
    if (fb) fb.textContent = tr(mapFallbackKey);
  }
}
function showFallback(key){
  mapFallbackKey = key;
  var el = document.getElementById("map");
  if (el) el.style.display = "none";
  var fb = document.getElementById("map-fallback");
  if (fb){ fb.style.display = "block"; fb.textContent = tr(key); }
}
function initMap(){
  if (!MAP || MAP.state !== "ok"){
    showFallback(MAP && MAP.state === "error" ? "map.error" : "map.nogeo");
    return;
  }
  if (typeof L === "undefined"){ showFallback("map.offline"); return; }
  var el = document.getElementById("map");
  el.style.display = "block";
  try {
    var m = L.map("map", {scrollWheelZoom:false}).setView([MAP.lat, MAP.lon], 10);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
      {maxZoom:18, attribution:"(c) OpenStreetMap contributors"}).addTo(m);
    L.circle([MAP.lat, MAP.lon],
      {radius:12000, color:"#25d366", weight:1,
       fillColor:"#25d366", fillOpacity:0.12}).addTo(m);
    L.marker([MAP.lat, MAP.lon]).addTo(m).bindPopup(MAP.label).openPopup();
    setTimeout(function(){ m.invalidateSize(); }, 100);
  } catch (e){ showFallback("map.offline"); }
}
document.addEventListener("DOMContentLoaded", function(){
  applyLang(CUR);
  var sel = document.getElementById("lang");
  if (sel){ sel.addEventListener("change", function(){ applyLang(this.value); }); }
  initMap();
});
</script>
</body>
</html>"""

def write_outputs(report, outdir=".", open_browser=True):
    """Save full JSON + an HTML dashboard and (optionally) open the HTML."""
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    try:
        os.makedirs(outdir, exist_ok=True)
    except Exception:
        outdir = "."
    json_path = os.path.join(outdir, "wa_peer_full_%s.json" % ts)
    html_path = os.path.join(outdir, "wa_peer_report_%s.html" % ts)

    with open(json_path, "w", encoding="utf8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    with open(html_path, "w", encoding="utf8") as f:
        f.write(render_html(report))

    print("full JSON  -> %s" % os.path.abspath(json_path), file=sys.stderr)
    print("HTML report -> %s" % os.path.abspath(html_path), file=sys.stderr)

    if open_browser:
        try:
            webbrowser.open("file:///" + os.path.abspath(html_path).replace("\\", "/"))
        except Exception as e:
            print("could not open browser: %s" % e, file=sys.stderr)
    return json_path, html_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--process", default=PROCESS)
    ap.add_argument("--seconds", type=float, default=0, help="0 = until Ctrl+C")
    ap.add_argument("--raw", metavar="PATH", help="also write the raw event stream")
    ap.add_argument("--compact", action="store_true")
    ap.add_argument("--outdir", default=".",
                    help="where to write the full JSON + HTML report (default: cwd)")
    ap.add_argument("--no-browser", action="store_true",
                    help="write the HTML report but do not auto-open it")
    ap.add_argument("--no-geo", action="store_true",
                    help="skip the online IP geolocation lookup (fully offline)")
    args = ap.parse_args()

    try:
        session = frida.attach(args.process)
    except frida.ProcessNotFoundError:
        print(json.dumps({"error": "%s is not running" % args.process}, indent=2))
        return 1

    events = []
    raw_file = open(args.raw, "a", encoding="utf8") if args.raw else None

    def on_message(message, data):
        if message.get("type") == "error":
            print("[agent error] %s" % message.get("description"), file=sys.stderr)
            return
        payload = message.get("payload")
        if payload is None:
            return
        events.append(payload)
        if raw_file:
            raw_file.write(json.dumps(payload, ensure_ascii=False) + "\n")
            raw_file.flush()
        if payload.get("event") == "error":
            print("[agent] %s" % payload.get("message"), file=sys.stderr)
            return
        if payload.get("event") == "hook_ready":
            print("attached to %s (build size=%s) — %d hooks. Place or accept a call, "
                  "then Ctrl+C."
                  % (args.process, payload.get("module_size"),
                     len(payload.get("hooked", []))), file=sys.stderr)

    script = session.create_script(AGENT)
    script.on("message", on_message)
    script.load()

    deadline = time.time() + args.seconds if args.seconds else None
    try:
        while True:
            if deadline and time.time() > deadline:
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass
    finally:
        if raw_file:
            raw_file.close()
        try:
            session.detach()
        except Exception:
            pass

    report = build_report(events, geo_lookup=not args.no_geo)
    print(json.dumps(report, indent=None if args.compact else 2, ensure_ascii=False))

    write_outputs(report, outdir=args.outdir, open_browser=not args.no_browser)
    return 0

if __name__ == "__main__":
    sys.exit(main())
