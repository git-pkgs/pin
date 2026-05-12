# pin examples

Four worked examples covering the shapes pin is built for:

- `server-rendered-go/pin.yaml` — three npm assets, Go-app output layout.
- `rails-app/pin.yaml` — Hotwired stack plus a GitHub-release-only library.
- `static-site/pin.yaml` — trust block requiring provenance on every npm asset, a URL-source opted out.
- `library-consumer/main.go` — Go program using `pin.Client` directly instead of the CLI.

Each `pin.yaml` is a runnable manifest. From any of the first three subdirectories:

```
pin sync
pin verify
```

The library consumer:

```
go run ./examples/library-consumer -dir ./examples/server-rendered-go
```
