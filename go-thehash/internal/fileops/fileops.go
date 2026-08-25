// Package fileops implements remote file operations over SMB shares:
// upload, download, delete, and directory listing.
package fileops

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jfjallid/go-smb/smb"
)

// PutFile uploads a local file to a remote SMB share path.
func PutFile(session *smb.Connection, share, remotePath, localPath string) error {
	src, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("open local file: %w", err)
	}
	defer src.Close()

	var written int64
	err = session.PutFile(share, remotePath, 0, func(buf []byte) (int, error) {
		n, readErr := src.Read(buf)
		written += int64(n)
		return n, readErr
	})
	if err != nil {
		return fmt.Errorf("PutFile \\\\%s\\%s\\%s: %w", session.GetAuthUsername(), share, remotePath, err)
	}
	fmt.Printf("[+] Uploaded %d bytes -> \\\\%s\\%s\\%s\n", written, share, share, remotePath)
	return nil
}

// GetFile downloads a file from a remote SMB share path to a local file.
func GetFile(session *smb.Connection, share, remotePath, localPath string) error {
	dst, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create local file: %w", err)
	}
	defer dst.Close()

	var received int64
	err = session.RetrieveFile(share, remotePath, 0, func(data []byte) (int, error) {
		n, writeErr := dst.Write(data)
		received += int64(n)
		return n, writeErr
	})
	if err != nil {
		os.Remove(localPath)
		return fmt.Errorf("RetrieveFile \\\\%s\\%s\\%s: %w", share, share, remotePath, err)
	}
	fmt.Printf("[+] Downloaded %d bytes -> %s\n", received, localPath)
	return nil
}

// DeleteRemoteFile deletes a file on a remote SMB share.
func DeleteRemoteFile(session *smb.Connection, share, remotePath string) error {
	if err := session.DeleteFile(share, remotePath); err != nil {
		return fmt.Errorf("DeleteFile \\\\%s\\%s\\%s: %w", share, share, remotePath, err)
	}
	fmt.Printf("[+] Deleted \\\\%s\\%s\\%s\n", share, share, remotePath)
	return nil
}

// ListDir lists files in a remote SMB share directory.
// pattern defaults to "*" when empty. Set recurse to list subdirectories.
func ListDir(session *smb.Connection, share, dir, pattern string, recurse bool) error {
	if pattern == "" {
		pattern = "*"
	}
	var files []smb.SharedFile
	var err error
	if recurse {
		files, err = session.ListRecurseDirectory(share, dir, pattern)
	} else {
		files, err = session.ListDirectory(share, dir, pattern)
	}
	if err != nil {
		return fmt.Errorf("ListDirectory \\\\%s\\%s\\%s: %w", share, share, dir, err)
	}
	fmt.Printf("[+] %d entries in \\\\%s\\%s\\%s\n\n", len(files), share, share, dir)
	fmt.Printf("%-6s %-20s %12s  %s\n", "Type", "Modified", "Size", "Name")
	fmt.Println(strings.Repeat("-", 60))
	for _, f := range files {
		kind := "file"
		if f.IsDir {
			kind = "dir"
		}
		// Convert Windows FILETIME (100-ns ticks since 1601-01-01) to Unix seconds.
		mtime := time.Unix(int64(f.LastWriteTime/10000000)-11644473600, 0).UTC().Format("2006-01-02 15:04")
		size := ""
		if !f.IsDir {
			size = fmt.Sprintf("%d", f.Size)
		}
		hidden := ""
		if f.IsHidden {
			hidden = " [H]"
		}
		fmt.Printf("%-6s %-20s %12s  %s%s\n", kind, mtime, size, f.Name, hidden)
	}
	return nil
}
