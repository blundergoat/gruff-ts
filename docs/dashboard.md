# Dashboard

`gruff-ts dashboard` starts a local web UI for running and inspecting scans interactively.

## Start

```sh
npx gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind host. |
| `--port` | `8767` | Bind port. |
| `--project-root` | current directory | Initial project root. |

## Safety

The dashboard has no authentication. Keep it bound to `127.0.0.1` unless you trust every machine on the network: its `/scan` endpoint reads filesystem paths from request parameters, so loopback binding is the main safety boundary.

## No Gating Threshold

`dashboard` has no `--fail-on` flag and cannot appear under `failOn:` in `.gruff-ts.yaml` (setting `failOn.dashboard:` fails config validation with exit `2`).

## Polyglot Repos

`gruff-ts` defaults to port `8767`, `gruff-rs` to `8766`, and `gruff-go`, `gruff-php`, and `gruff-py` to `8765`. Pass `--port` if you run several dashboards side by side.
