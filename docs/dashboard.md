# Dashboard

`gruff-ts dashboard` serves a local browser dashboard for repeated analysis.

## Start

```sh
./bin/gruff-ts dashboard --host 127.0.0.1 --port 8767 --project-root .
```

## Options

| Option | Default | Purpose |
| --- | --- | --- |
| `--host` | `127.0.0.1` | Bind host. |
| `--port` | `8767` | Bind port. |
| `--project-root` | current directory | Initial project root. |

## Safety

The dashboard has no authentication and should stay bound to loopback unless the
network is trusted. The `/scan` endpoint analyses filesystem paths from request
parameters, so the bind address is the safety boundary.

## Gating threshold (none)

`dashboard` has no `--fail-on` flag and does not participate in the
`minimumSeverity:` config block - setting `minimumSeverity.dashboard:` in
`.gruff-ts.yaml` is rejected at config load. Whether the dashboard should gate
is a deferred design question; raise it as an issue if your workflow needs it.

## Polyglot Repos

`gruff-ts` defaults to port `8767`, `gruff-rs` defaults to `8766`, and Go, PHP,
and Python default to `8765`. Use `--port` when running multiple dashboards at
once.
