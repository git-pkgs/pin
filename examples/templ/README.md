# pin + templ

Templ ([templ.guide](https://templ.guide)) is the modern server-rendered Go stack — write `.templ` files, run `templ generate` to compile them to Go, serve them from any router.

Pin's `assets` package returns `[]template.HTML` which templ consumes via `@templ.Raw(html)`. No templ-specific glue is needed in pin; the integration is the four-line snippet in `layout.templ`.

## Setup

```
pin sync               # vendors htmx + tailwindcss/browser under static/vendor
templ generate         # compiles layout.templ → layout_templ.go
go run .               # see main.go for a runnable server
```

## Pattern

```templ
templ Layout(lock *assets.Lock, opts assets.Options) {
    <!DOCTYPE html>
    <html>
        <head>
            for _, tag := range assets.Tags(lock, "style", opts) {
                @templ.Raw(tag)
            }
            for _, tag := range assets.Tags(lock, "script", opts) {
                @templ.Raw(tag)
            }
        </head>
        <body>{ children... }</body>
    </html>
}
```

`assets.Tags(lock, "style"|"script"|"font", opts)` returns one tag per matching file in lockfile order. `opts.Prefix` is the URL path your static-file handler is mounted at — typically `/vendor/`.

For a single asset with a known load order, use `assets.Tag(lock, "htmx.org", opts)` instead of `Tags` — it returns just that package's files, still in lockfile order.

## Serving the files

Any router that takes an `fs.FS` works. The simplest path is `//go:embed`:

```go
//go:embed static/vendor pin.lock
var vendored embed.FS

lockBytes, _ := vendored.ReadFile("pin.lock")
lock, _ := assets.Parse(bytes.NewReader(lockBytes))
afs, _ := assets.FS(vendored, lock)

http.Handle("/vendor/", http.StripPrefix("/vendor", http.FileServer(http.FS(afs))))
```

The lockfile embeds alongside the vendored tree so the binary needs no runtime filesystem dependency.
