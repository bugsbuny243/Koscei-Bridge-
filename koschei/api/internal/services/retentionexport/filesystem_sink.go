package retentionexport

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FilesystemSink struct {
	root string
}

func NewFilesystemSink(root string) (*FilesystemSink, error) {
	root = strings.TrimSpace(root)
	if root == "" {
		return nil, fmt.Errorf("KOSCHEI_RADAR_ARCHIVE_EXPORT_FILESYSTEM_PATH is required")
	}
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0o750); err != nil {
		return nil, err
	}
	return &FilesystemSink{root: absolute}, nil
}

func (s *FilesystemSink) Name() string { return "filesystem" }

func (s *FilesystemSink) Put(ctx context.Context, key string, data []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	target, err := s.resolve(key)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return "", err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".retention-export-*.tmp")
	if err != nil {
		return "", err
	}
	temporaryName := temporary.Name()
	defer func() { _ = os.Remove(temporaryName) }()
	if err := temporary.Chmod(0o640); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return "", err
	}
	if err := temporary.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(temporaryName, target); err != nil {
		return "", err
	}
	return "filesystem://" + filepath.ToSlash(target), nil
}

func (s *FilesystemSink) Get(ctx context.Context, key string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	target, err := s.resolve(key)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(target)
}

func (s *FilesystemSink) resolve(key string) (string, error) {
	if s == nil || strings.TrimSpace(s.root) == "" {
		return "", fmt.Errorf("filesystem sink is not configured")
	}
	clean := filepath.Clean(filepath.FromSlash(strings.TrimSpace(key)))
	if clean == "." || filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid retention export key %q", key)
	}
	target := filepath.Join(s.root, clean)
	relative, err := filepath.Rel(s.root, target)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("retention export key escapes sink root")
	}
	return target, nil
}
