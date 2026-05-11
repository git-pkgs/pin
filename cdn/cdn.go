// Package cdn builds URLs for npm package files served via public CDNs.
// The CDN is a transport, not a source of truth: integrity is anchored to
// the registry tarball regardless of which CDN URL is recorded.
package cdn

import "fmt"

type Mirror string

const (
	JSDelivr Mirror = "jsdelivr"
	Unpkg    Mirror = "unpkg"
)

func NPMFileURL(m Mirror, name, version, path string) string {
	switch m {
	case Unpkg:
		return fmt.Sprintf("https://unpkg.com/%s@%s/%s", name, version, path)
	case JSDelivr:
		fallthrough
	default:
		return fmt.Sprintf("https://cdn.jsdelivr.net/npm/%s@%s/%s", name, version, path)
	}
}

func ForgeFileURL(m Mirror, forge, owner, repo, ref, path string) string {
	switch forge {
	case "github":
		return fmt.Sprintf("https://cdn.jsdelivr.net/gh/%s/%s@%s/%s", owner, repo, ref, path)
	case "gitlab":
		return fmt.Sprintf("https://cdn.jsdelivr.net/gl/%s/%s@%s/%s", owner, repo, ref, path)
	}
	return ""
}
