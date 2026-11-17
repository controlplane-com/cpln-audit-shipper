package filestore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/controlplane-com/cpln-audit-shipper/internal/objstore"
)

func TestConditionalWritesBehaveLikeTheBucket(t *testing.T) {
	ctx := context.Background()
	s := &Store{Dir: t.TempDir()}
	key := "state/org=acme/source=k8s-audit/cluster=c/sink=syslog/stream=default/checkpoint.json"
	if _, _, err := s.Get(ctx, key); !errors.Is(err, objstore.ErrNotFound) {
		t.Fatalf("missing checkpoint: %v", err)
	}
	v1, err := s.Put(ctx, key, []byte("one"), objstore.PutOptions{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, key, []byte("x"), objstore.PutOptions{IfNoneMatch: true}); !errors.Is(err, objstore.ErrPrecondition) {
		t.Fatalf("create over an existing checkpoint: %v", err)
	}
	v2, err := s.Put(ctx, key, []byte("two"), objstore.PutOptions{IfMatch: v1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, key, []byte("stale"), objstore.PutOptions{IfMatch: v1}); !errors.Is(err, objstore.ErrPrecondition) {
		t.Fatalf("write on a stale version: %v", err)
	}
	body, v, err := s.Get(ctx, key)
	if err != nil || string(body) != "two" || v != v2 {
		t.Fatalf("got %q %s %v, want two %s", body, v, err, v2)
	}
	left, _ := filepath.Glob(filepath.Join(filepath.Dir(filepath.Join(s.Dir, key)), ".checkpoint-*"))
	if len(left) != 0 {
		t.Fatalf("temp files left behind: %v", left)
	}
	if _, err := s.Put(ctx, "../escape", []byte("x"), objstore.PutOptions{}); err == nil {
		t.Fatal("a key outside the directory was accepted")
	}
}

func TestLockKeepsASecondHolderOut(t *testing.T) {
	dir := t.TempDir()
	a, err := Acquire(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Acquire(dir); !errors.Is(err, ErrLocked) {
		t.Fatalf("second acquire: %v, want ErrLocked", err)
	}
	a.Release()
	b, err := Acquire(dir)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	b.Release()
}

func TestUnwritableDirectoryIsAccessDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes anywhere")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	s := &Store{Dir: dir}
	if _, err := s.Put(context.Background(), "state/x.json", []byte("x"), objstore.PutOptions{}); !errors.Is(err, objstore.ErrAccessDenied) {
		t.Fatalf("err = %v, want ErrAccessDenied", err)
	}
}
