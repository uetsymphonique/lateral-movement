// Criteria-based recursive collection from an SMB share (T1119).
package fileops

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/jfjallid/go-smb/smb"
)

// CollectFiles recursively enumerates a remote share directory and retrieves
// every file whose name matches pattern, writing matches under localDir with
// the remote directory tree preserved. pattern is a comma-separated list of
// case-insensitive globs (e.g. "*.config,*.json"); "*" or "" matches all.
//
// This is criteria-based automated collection (T1119): it recurses the whole
// tree and selects by filename, rather than fetching one known path.
func CollectFiles(session *smb.Connection, share, remoteDir, localDir, pattern string) (int, error) {
	remoteDir = normalizeShareDir(remoteDir)
	if err := session.TreeConnect(share); err != nil {
		return 0, fmt.Errorf("TreeConnect \\\\%s: %w", share, err)
	}
	defer session.TreeDisconnect(share)
	// Enumerate everything ("*") and filter locally. Passing a narrow find
	// pattern (e.g. "*.config") directly to ListRecurseDirectory would not
	// match directory names, so it would never descend into subdirectories.
	files, err := session.ListRecurseDirectory(share, remoteDir, "*")
	if err != nil && len(files) == 0 {
		return 0, fmt.Errorf("ListRecurseDirectory \\\\%s\\%s: %w", share, remoteDir, err)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] partial listing of \\\\%s\\%s: %v\n", share, remoteDir, err)
	}

	if err := os.MkdirAll(localDir, 0o755); err != nil {
		return 0, fmt.Errorf("create local dir %s: %w", localDir, err)
	}

	collected := 0
	for _, f := range files {
		if f.IsDir || !matchPattern(f.Name, pattern) {
			continue
		}
		rel := strings.ReplaceAll(remoteRelPath(remoteDir, f.FullPath), "\\", "/")
		dst := filepath.Join(localDir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return collected, fmt.Errorf("create local dir for %s: %w", dst, err)
		}
		if err := GetFile(session, share, f.FullPath, dst); err != nil {
			return collected, err
		}
		collected++
	}
	fmt.Printf("[+] Collected %d file(s) matching %q from \\\\%s\\%s -> %s\n",
		collected, pattern, share, remoteDir, localDir)
	return collected, nil
}

// matchPattern reports whether name matches any comma-separated glob in
// pattern. Matching is case-insensitive to mirror Windows filesystem semantics.
func matchPattern(name, pattern string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" || pattern == "*" {
		return true
	}
	lower := strings.ToLower(name)
	for _, p := range strings.Split(pattern, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		if ok, err := path.Match(p, lower); err == nil && ok {
			return true
		}
	}
	return false
}

// remoteRelPath converts a share-relative FullPath into a path relative to the
// collection root so the local tree mirrors the remote layout.
func remoteRelPath(root, fullPath string) string {
	p := strings.ReplaceAll(fullPath, "/", "\\")
	base := strings.TrimSuffix(strings.ReplaceAll(root, "/", "\\"), "\\")
	switch base {
	case "", ".":
		return strings.TrimPrefix(p, ".\\")
	default:
		if strings.HasPrefix(p, base+"\\") {
			return strings.TrimPrefix(p, base+"\\")
		}
		return p
	}
}
