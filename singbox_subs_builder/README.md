# singbox_subs_builder

Build a sing-box JSON config by fetching multiple subscription sublinks and merging all proxies into one config.

## Files
- `build_config.py` — main script
- `sublinks.txt` — input list (one sublink per line)
- `singbox.json` — output config (generated)

## Usage
```bash
python build_config.py --input sublinks.txt --output singbox.json
```

Optional flags:
- `--timeout 10` fetch timeout (seconds)
- `--retries 2` fetch retries

## Input format
`subLinks.txt` should contain one link per line:
```
https://example.com/sub1
https://example.com/sub2
```

Lines starting with `#` are ignored.

## Notes
- Supported schemes: `vmess://`, `vless://`, `trojan://`, `ss://`, `socks://`, `http(s)://`.
- `ssr://` is skipped (not supported).
- The output config includes:
  - one mixed inbound on `127.0.0.1:1080`
  - an `AUTO` urltest outbound
  - all parsed proxy outbounds
  - `DIRECT` and `BLOCK`
  - route final = `AUTO`

If you want different defaults (ports, DNS, urltest URL, etc.), edit `build_config.py`.
