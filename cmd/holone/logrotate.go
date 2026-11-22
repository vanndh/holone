package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	defaultMaxLogBytes   = 10 << 20 // 10 MiB per log file
	defaultMaxLogBackups = 3
)

// rotatingLogWriter writes audit JSONL records to a 0600 file and rotates
// past maxBytes, retaining up to maxBackups older files (.1 .. .N).
type rotatingLogWriter struct {
	path       string
	maxBytes   int64
	maxBackups int

	mu   sync.Mutex
	file *os.File
	size int64
}

func openRotatingLog(path string, maxBytes int64, maxBackups int) (*rotatingLogWriter, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxLogBytes
	}
	if maxBackups < 0 {
		maxBackups = 0
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create log dir %q: %w", dir, err)
		}
	}
	w := &rotatingLogWriter{
		path:       path,
		maxBytes:   maxBytes,
		maxBackups: maxBackups,
	}
	if err := w.openLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingLogWriter) openLocked() error {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("open log %q: %w", w.path, err)
	}
	_ = f.Chmod(0o600)
	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}
	w.file = f
	w.size = size
	return nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.openLocked(); err != nil {
			return 0, err
		}
	}
	if w.maxBytes > 0 && w.size > 0 && w.size+int64(len(p)) > w.maxBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingLogWriter) rotateLocked() error {
	if w.file != nil {
		_ = w.file.Close()
		w.file = nil
	}
	if w.maxBackups > 0 {
		oldest := fmt.Sprintf("%s.%d", w.path, w.maxBackups)
		_ = os.Remove(oldest)
		for i := w.maxBackups - 1; i >= 1; i-- {
			src := fmt.Sprintf("%s.%d", w.path, i)
			dst := fmt.Sprintf("%s.%d", w.path, i+1)
			if _, err := os.Stat(src); err == nil {
				_ = os.Rename(src, dst)
			}
		}
		_ = os.Rename(w.path, fmt.Sprintf("%s.1", w.path))
	} else {
		_ = os.Remove(w.path)
	}
	return w.openLocked()
}

func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
