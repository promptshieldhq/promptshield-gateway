package policy

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
)

const debounceDuration = 200 * time.Millisecond

// Watcher reloads the policy file on change. Saves are debounced to collapse rapid writes.
type Watcher struct {
	path     string
	onChange func(*Policy, error)
	log      zerolog.Logger

	mu      sync.Mutex
	stopped bool
}

func NewWatcher(path string, log zerolog.Logger, onChange func(*Policy, error)) *Watcher {
	return &Watcher{path: path, log: log, onChange: onChange}
}

// Start watches the policy file and blocks until ctx is cancelled.
// Watches the parent directory to catch atomic editor renames.
func (w *Watcher) Start(ctx context.Context) {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		w.log.Warn().Err(err).Msg("policy watcher: failed to create fsnotify watcher — hot reload disabled")
		return
	}
	defer fw.Close()

	dir := filepath.Dir(w.path)
	base := filepath.Base(w.path)

	if err := fw.Add(dir); err != nil {
		w.log.Warn().Err(err).Str("dir", dir).Msg("policy watcher: failed to watch directory — hot reload disabled")
		return
	}

	w.log.Info().Str("path", w.path).Msg("policy watcher: watching for changes")

	var debounce *time.Timer

	for {
		select {
		case <-ctx.Done():
			w.markStopped()
			stopDebounceTimer(debounce)
			return

		case event, ok := <-fw.Events:
			if !ok {
				return
			}
			if !isPolicyFileEvent(event, base) {
				continue
			}
			debounce = w.scheduleReload(debounce)

		case err, ok := <-fw.Errors:
			if !ok {
				return
			}
			w.log.Warn().Err(err).Msg("policy watcher: fsnotify error")
		}
	}
}

func (w *Watcher) markStopped() {
	w.mu.Lock()
	w.stopped = true
	w.mu.Unlock()
}

func stopDebounceTimer(timer *time.Timer) {
	if timer != nil {
		timer.Stop()
	}
}

func isPolicyFileEvent(event fsnotify.Event, base string) bool {
	if filepath.Base(event.Name) != base {
		return false
	}
	// Rename is included because atomic writes (os.Rename) on some editors/Linux
	// emit only a Rename event for the destination file rather than Create.
	return event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename)
}

func (w *Watcher) scheduleReload(existing *time.Timer) *time.Timer {
	stopDebounceTimer(existing)

	return time.AfterFunc(debounceDuration, func() {
		if w.isStopped() {
			return
		}
		w.reloadPolicy()
	})
}

func (w *Watcher) isStopped() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.stopped
}

func (w *Watcher) reloadPolicy() {
	p, err := Load(w.path)
	if err != nil {
		w.log.Error().Err(err).Str("path", w.path).Msg("policy watcher: reload failed — keeping previous policy")
	} else {
		w.log.Info().Str("path", w.path).Msg("policy watcher: policy reloaded")
	}
	w.onChange(p, err)
}
