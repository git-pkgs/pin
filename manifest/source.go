package manifest

import (
	"fmt"
	"strings"
)

type SourceKind string

const (
	SourceNPM   SourceKind = "npm"
	SourceForge SourceKind = "forge"
	SourceURL   SourceKind = "url"
)

const (
	ForgeGitHub    = "github"
	ForgeGitLab    = "gitlab"
	ForgeGitea     = "gitea"
	ForgeCodeberg  = "codeberg"
	ForgeBitbucket = "bitbucket"
	ForgeGit       = "git"
)

type Source struct {
	Kind  SourceKind
	Forge string
	Host  string
	Owner string
	Repo  string
	URL   string
}

const minForgePathParts = 2

func ParseSource(s string) (Source, error) {
	if s == "" || s == "npm" {
		return Source{Kind: SourceNPM}, nil
	}

	scheme, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Source{}, fmt.Errorf("unknown source %q", s)
	}

	switch scheme {
	case "url":
		if rest == "" {
			return Source{}, fmt.Errorf("source %q: url is empty", s)
		}
		return Source{Kind: SourceURL, URL: rest}, nil

	case ForgeGit:
		if rest == "" {
			return Source{}, fmt.Errorf("source %q: git URL is empty", s)
		}
		return Source{Kind: SourceForge, Forge: ForgeGit, URL: rest}, nil

	case ForgeGitHub, ForgeGitLab, ForgeCodeberg, ForgeBitbucket:
		return parseForge(scheme, "", rest, s)

	case ForgeGitea:
		host, repoPath, hasHost := strings.Cut(rest, "/")
		if !hasHost || !strings.Contains(host, ".") {
			return Source{}, fmt.Errorf("source %q: gitea requires host/owner/repo", s)
		}
		return parseForge(scheme, host, repoPath, s)
	}

	return Source{}, fmt.Errorf("unknown source scheme %q in %q", scheme, s)
}

func parseForge(forge, host, repoPath, orig string) (Source, error) {
	parts := strings.Split(repoPath, "/")
	if len(parts) < minForgePathParts || parts[0] == "" || parts[len(parts)-1] == "" {
		return Source{}, fmt.Errorf("source %q: expected owner/repo", orig)
	}
	owner := strings.Join(parts[:len(parts)-1], "/")
	repo := parts[len(parts)-1]
	return Source{Kind: SourceForge, Forge: forge, Host: host, Owner: owner, Repo: repo}, nil
}
