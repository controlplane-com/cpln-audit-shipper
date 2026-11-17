// Package filestore keeps checkpoints on a mounted volume, for a single-location GVC without a state bucket.
package filestore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
)

// Store implements objstore.Store on files. A version is the hash of the content, and every write is a temp
// file, fsync and rename, so a crash leaves either the old checkpoint or the new one.
type Store struct {
	Dir string
	mu  sync.Mutex
}

func (s *Store) path(key string) (string, error) {
	clean := filepath.Clean("/" + key)
	if clean == "/" || strings.Contains(key, "..") {
		return "", fmt.Errorf("invalid state key %q", key)
	}
	return filepath.Join(s.Dir, filepath.FromSlash(clean)), nil
}

func version(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:16])
}

func (s *Store) Get(_ context.Context, key string) ([]byte, string, error) {
	p, err := s.path(key)
	if err != nil {
		return nil, "", err
	}
	body, err := os.ReadFile(p)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, "", fmt.Errorf("%w: %s", objstore.ErrNotFound, p)
	case errors.Is(err, fs.ErrPermission):
		return nil, "", fmt.Errorf("%w: %v", objstore.ErrAccessDenied, err)
	case err != nil:
		return nil, "", err
	}
	return body, version(body), nil
}

func (s *Store) Put(_ context.Context, key string, body []byte, opts objstore.PutOptions) (string, error) {
	p, err := s.path(key)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if opts.IfMatch != "" || opts.IfNoneMatch {
		cur, err := os.ReadFile(p)
		exists := err == nil
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if opts.IfNoneMatch && exists {
			return "", fmt.Errorf("%w: %s exists", objstore.ErrPrecondition, p)
		}
		if opts.IfMatch != "" && (!exists || version(cur) != opts.IfMatch) {
			return "", fmt.Errorf("%w: %s changed", objstore.ErrPrecondition, p)
		}
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", wrapPerm(err)
	}
	tmp, err := os.CreateTemp(dir, ".checkpoint-*")
	if err != nil {
		return "", wrapPerm(err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return "", err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return version(body), nil
}

func wrapPerm(err error) error {
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("%w: %v (the volume must be writable by the container's group; see securityOptions.filesystemGroupId)", objstore.ErrAccessDenied, err)
	}
	return err
}

var (
	// ErrLocked means another process holds the lock.
	ErrLocked = errors.New("the state lock is held by another replica")
	// ErrLockUnsupported means the volume cannot lock files, so two replicas could not be kept apart.
	ErrLockUnsupported = errors.New("the state volume does not support file locks")
)

// Lock is an exclusive flock on a file in the state directory, held for the life of the process.
type Lock struct{ f *os.File }

func Acquire(dir string) (*Lock, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, wrapPerm(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o640)
	if err != nil {
		return nil, wrapPerm(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("%w: %v", ErrLockUnsupported, err)
	}
	return &Lock{f: f}, nil
}

func (l *Lock) Release() {
	if l != nil && l.f != nil {
		_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
		l.f.Close()
	}
}
