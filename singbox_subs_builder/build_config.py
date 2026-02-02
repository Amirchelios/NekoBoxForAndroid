#!/usr/bin/env python3
"""Build a sing-box config by fetching and merging subscription sublinks.

Output format is aligned with the example provided by the user.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

LINK_RE = re.compile(
    r"(vmess|vless|trojan|ss|ssr|socks|http)://[^\s<>\"']+",
    re.IGNORECASE,
)

BASE64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


def _b64_decode(data: str) -> Optional[str]:
    data = data.strip()
    data = data.replace("-", "+").replace("_", "/")
    pad = "=" * ((4 - len(data) % 4) % 4)
    try:
        raw = base64.b64decode(data + pad)
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return None


def maybe_decode_subscription(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    if "://" in stripped:
        return stripped
    if BASE64_RE.match(stripped):
        decoded = _b64_decode(stripped)
        if decoded and "://" in decoded:
            return decoded
    return stripped


def fetch_url(url: str, timeout: int, retries: int) -> str:
    last_err = None
    for i in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            try:
                return data.decode("utf-8")
            except UnicodeDecodeError:
                return data.decode("utf-8", errors="ignore")
        except Exception as exc:
            last_err = exc
            if i < retries:
                time.sleep(0.3)
    raise RuntimeError(f"fetch failed: {url} ({last_err})")


def extract_links(text: str) -> List[str]:
    if not text:
        return []
    text = maybe_decode_subscription(text)
    return [m.group(0) for m in LINK_RE.finditer(text)]


def short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:8]


def safe_tag(name: str) -> str:
    name = name.strip() or "node"
    name = re.sub(r"[\r\n\t]", " ", name)
    return name


def unique_tag(base: str, used: set) -> str:
    tag = base
    if tag not in used:
        used.add(tag)
        return tag
    idx = 2
    while True:
        tag = f"{base}-{idx}"
        if tag not in used:
            used.add(tag)
            return tag
        idx += 1


def default_tls(tls_enabled: bool, server_name: Optional[str] = None) -> Optional[Dict]:
    if not tls_enabled:
        return None
    tls_obj: Dict = {
        "enabled": True,
        "insecure": False,
        "alpn": ["http/1.1"],
        "utls": {"enabled": True, "fingerprint": "chrome"},
    }
    if server_name:
        tls_obj["server_name"] = server_name
    return tls_obj


def parse_vmess(uri: str) -> Tuple[Optional[Dict], Optional[str]]:
    try:
        payload = uri[len("vmess://") :]
        decoded = _b64_decode(payload)
        if not decoded:
            return None, "vmess base64 decode failed"
        obj = json.loads(decoded)
        server = obj.get("add") or obj.get("host")
        port = int(obj.get("port"))
        uuid = obj.get("id")
        if not (server and port and uuid):
            return None, "vmess missing required fields"

        tag = safe_tag(obj.get("ps") or f"vmess-{short_hash(uri)}")
        out = {
            "type": "vmess",
            "tag": tag,
            "server": server,
            "server_port": port,
            "uuid": uuid,
            "security": "auto",
            "alter_id": int(obj.get("aid") or 0),
        }

        net = (obj.get("net") or "tcp").lower()
        host = obj.get("host") or obj.get("sni")
        path = obj.get("path") or ""
        if net != "tcp":
            transport: Dict = {"type": net}
            if net == "ws":
                transport["path"] = path or "/"
                if host:
                    transport["headers"] = {"Host": host}
            elif net == "grpc":
                transport["service_name"] = path
            elif net in ("http", "h2"):
                if path:
                    transport["path"] = path
                if host:
                    transport["host"] = [host]
            out["transport"] = transport

        tls = (obj.get("tls") or "").lower()
        tls_obj = default_tls(tls in ("tls", "reality"), host)
        if tls_obj:
            out["tls"] = tls_obj
        return out, None
    except Exception as exc:
        return None, f"vmess parse error: {exc}"


def parse_vless_or_trojan(uri: str, proto: str) -> Tuple[Optional[Dict], Optional[str]]:
    try:
        parsed = urllib.parse.urlparse(uri)
        if not parsed.username or not parsed.hostname or not parsed.port:
            return None, f"{proto} missing required parts"
        tag = safe_tag(urllib.parse.unquote(parsed.fragment or f"{proto}-{short_hash(uri)}"))
        out: Dict = {
            "type": proto,
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
        }
        if proto == "vless":
            out["uuid"] = parsed.username
            out["flow"] = ""
        else:
            out["password"] = parsed.username

        params = urllib.parse.parse_qs(parsed.query)

        def _p(key: str) -> Optional[str]:
            v = params.get(key)
            return v[0] if v else None

        sec = (_p("security") or "").lower()
        sni = _p("sni") or _p("peer") or _p("serverName")
        tls_obj = default_tls(sec in ("tls", "reality"), sni)
        if tls_obj:
            fp = _p("fp") or _p("fingerprint")
            if fp:
                tls_obj["utls"] = {"enabled": True, "fingerprint": fp}
            if sec == "reality":
                pub = _p("pbk") or _p("publicKey")
                sid = _p("sid") or _p("shortId")
                spx = _p("spx") or _p("spiderX")
                reality = {"enabled": True}
                if pub:
                    reality["public_key"] = pub
                if sid:
                    reality["short_id"] = sid
                if spx:
                    reality["spider_x"] = spx
                tls_obj["reality"] = reality
            out["tls"] = tls_obj

        if proto == "vless":
            flow = _p("flow")
            if flow:
                out["flow"] = flow

        ttype = (_p("type") or "tcp").lower()
        if ttype != "tcp":
            transport: Dict = {"type": ttype}
            path = _p("path")
            host = _p("host")
            service_name = _p("serviceName")
            if ttype == "ws":
                transport["path"] = path or "/"
                if host:
                    transport["headers"] = {"Host": host}
            elif ttype == "grpc":
                if service_name:
                    transport["service_name"] = service_name
            elif ttype in ("http", "h2"):
                if path:
                    transport["path"] = path
                if host:
                    transport["host"] = [host]
            out["transport"] = transport
        elif proto == "vless":
            out["transport"] = {}

        return out, None
    except Exception as exc:
        return None, f"{proto} parse error: {exc}"


def parse_ss(uri: str) -> Tuple[Optional[Dict], Optional[str]]:
    try:
        parsed = urllib.parse.urlparse(uri)
        if not parsed.hostname:
            payload = uri[len("ss://") :]
            decoded = _b64_decode(payload)
            if not decoded:
                return None, "ss decode failed"
            parsed = urllib.parse.urlparse("ss://" + decoded)
        method = None
        password = None
        if parsed.username and parsed.password:
            method = urllib.parse.unquote(parsed.username)
            password = urllib.parse.unquote(parsed.password)
        else:
            userinfo, _, hostport = parsed.netloc.rpartition("@")
            if userinfo:
                decoded = _b64_decode(userinfo)
                if decoded and ":" in decoded:
                    method, password = decoded.split(":", 1)
                    parsed = urllib.parse.urlparse("ss://" + hostport)
        if not (parsed.hostname and parsed.port and method and password):
            return None, "ss missing required parts"

        tag = safe_tag(urllib.parse.unquote(parsed.fragment or f"ss-{short_hash(uri)}"))
        out = {
            "type": "shadowsocks",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
            "method": method,
            "password": password,
        }
        return out, None
    except Exception as exc:
        return None, f"ss parse error: {exc}"


def parse_socks_http(uri: str, proto: str) -> Tuple[Optional[Dict], Optional[str]]:
    try:
        parsed = urllib.parse.urlparse(uri)
        if not parsed.hostname or not parsed.port:
            return None, f"{proto} missing host/port"
        tag = safe_tag(urllib.parse.unquote(parsed.fragment or f"{proto}-{short_hash(uri)}"))
        out = {
            "type": "socks" if proto == "socks" else "http",
            "tag": tag,
            "server": parsed.hostname,
            "server_port": parsed.port,
        }
        if parsed.username:
            out["username"] = urllib.parse.unquote(parsed.username)
        if parsed.password:
            out["password"] = urllib.parse.unquote(parsed.password)
        return out, None
    except Exception as exc:
        return None, f"{proto} parse error: {exc}"


def parse_link(link: str) -> Tuple[Optional[Dict], Optional[str]]:
    link = link.strip()
    if link.startswith("vmess://"):
        return parse_vmess(link)
    if link.startswith("vless://"):
        return parse_vless_or_trojan(link, "vless")
    if link.startswith("trojan://"):
        return parse_vless_or_trojan(link, "trojan")
    if link.startswith("ss://"):
        return parse_ss(link)
    if link.startswith("socks://"):
        return parse_socks_http(link, "socks")
    if link.startswith("http://") or link.startswith("https://"):
        return parse_socks_http(link, "http")
    if link.startswith("ssr://"):
        return None, "ssr not supported"
    return None, "unknown scheme"


def load_sublinks(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8") as f:
        lines = []
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            lines.append(line)
    return lines


def build_config(outbounds: List[Dict]) -> Dict:
    proxy_tags = [o["tag"] for o in outbounds]
    config = {
        "dns": {
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18",
            },
            "final": "dns-remote",
            "independent_cache": True,
            "rules": [
                {"domain": ["dns.google"], "server": "dns-direct"},
                {"outbound": ["any"], "server": "dns-direct"},
                {"disable_cache": True, "inbound": ["tun-in"], "server": "dns-fake"},
            ],
            "servers": [
                {"address": "rcode://success", "tag": "dns-block"},
                {"address": "local", "detour": "direct", "tag": "dns-local"},
                {
                    "address": "https://223.5.5.5/dns-query",
                    "address_resolver": "dns-local",
                    "detour": "direct",
                    "strategy": "ipv4_only",
                    "tag": "dns-direct",
                },
                {
                    "address": "https://dns.google/dns-query",
                    "address_resolver": "dns-direct",
                    "strategy": "ipv4_only",
                    "tag": "dns-remote",
                },
                {"address": "fakeip", "strategy": "ipv4_only", "tag": "dns-fake"},
            ],
        },
        "experimental": {
            "clash_api": {
                "external_controller": "127.0.0.1:9090",
                "external_ui": "../files/yacd",
            }
        },
        "inbounds": [
            {
                "domain_strategy": "",
                "endpoint_independent_nat": True,
                "inet4_address": ["172.19.0.1/28"],
                "mtu": 9000,
                "sniff": True,
                "sniff_override_destination": False,
                "stack": "system",
                "tag": "tun-in",
                "type": "tun",
            },
            {
                "domain_strategy": "",
                "listen": "127.0.0.1",
                "listen_port": 2080,
                "sniff": True,
                "sniff_override_destination": False,
                "tag": "mixed-in",
                "type": "mixed",
            },
        ],
        "log": {"level": "warn"},
        "outbounds": [
            {
                "type": "selector",
                "tag": "proxy",
                "outbounds": ["auto_parallel", "auto", *proxy_tags, "direct"],
            },
            {"type": "direct", "tag": "direct"},
            {
                "type": "parallel",
                "tag": "auto_parallel",
                "outbounds": proxy_tags,
                "strategy": "race",
                "concurrency": 15,
                "delay": "300ms",
                "timeout": "5000ms",
            },
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": proxy_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interrupt_exist_connections": False,
                "interval": "10s",
                "tolerance": 50,
            },
            *outbounds,
        ],
    }
    return config


def main() -> int:
    ap = argparse.ArgumentParser(description="Build sing-box config from sublinks.")
    ap.add_argument("--input", default="sublinks.txt", help="Path to sublinks file")
    ap.add_argument("--output", default="singbox.json", help="Output config path")
    ap.add_argument("--timeout", type=int, default=10, help="Fetch timeout (seconds)")
    ap.add_argument("--retries", type=int, default=2, help="Fetch retries")
    args = ap.parse_args()

    if not os.path.exists(args.input):
        print(f"Input not found: {args.input}", file=sys.stderr)
        return 1

    sublinks = load_sublinks(args.input)
    if not sublinks:
        print("No sublinks found.", file=sys.stderr)
        return 1

    all_links: List[str] = []
    failed_sources: List[str] = []

    for link in sublinks:
        if link.startswith("http://") or link.startswith("https://"):
            try:
                content = fetch_url(link, args.timeout, args.retries)
                extracted = extract_links(content)
                if extracted:
                    all_links.extend(extracted)
                else:
                    failed_sources.append(f"empty: {link}")
            except Exception as exc:
                failed_sources.append(f"fetch error: {link} ({exc})")
        else:
            extracted = extract_links(link)
            if extracted:
                all_links.extend(extracted)
            else:
                failed_sources.append(f"invalid line: {link}")

    if not all_links:
        print("No proxy links extracted.", file=sys.stderr)
        if failed_sources:
            print("Failures:")
            for it in failed_sources[:10]:
                print("-", it)
        return 2

    outbounds: List[Dict] = []
    used_tags = set()
    failed_links: List[str] = []

    for link in all_links:
        ob, err = parse_link(link)
        if ob is None:
            failed_links.append(f"{link} ({err})")
            continue
        # enforce tag as type-hash style
        ob["tag"] = unique_tag(f"{ob['type']}-{short_hash(link)}", used_tags)
        outbounds.append(ob)

    if not outbounds:
        print("No valid proxies parsed.", file=sys.stderr)
        for it in failed_links[:10]:
            print("-", it)
        return 3

    config = build_config(outbounds)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    print(f"OK: wrote {args.output}")
    print(f"Proxies: {len(outbounds)}")
    if failed_sources:
        print(f"Source failures: {len(failed_sources)}")
    if failed_links:
        print(f"Link failures: {len(failed_links)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
