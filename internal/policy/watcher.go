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
			w.mu.Lock()
			w.stopped = true
			w.mu.Unlock()
			if debounce != nil {
				debounce.Stop()
			}
			return

		case event, ok := <-fw.Events:
			if !ok {
				return
			}
			if filepath.Base(event.Name) != base {
				continue
			}
			if !event.Has(fsnotify.Write) && !event.Has(fsnotify.Create) {
				continue
			}
			if debounce != nil {
				debounce.Stop()
			}
			debounce = time.AfterFunc(debounceDuration, func() {
				w.mu.Lock()
				if w.stopped {
					w.mu.Unlock()
					return
				}
				w.mu.Unlock()

				p, err := Load(w.path)
				if err != nil {
					w.log.Error().Err(err).Str("path", w.path).Msg("policy watcher: reload failed — keeping previous policy")
				} else {
					w.log.Info().Str("path", w.path).Msg("policy watcher: policy reloaded")
				}
				w.onChange(p, err)
			})

		case err, ok := <-fw.Errors:
			if !ok {
				return
			}
			w.log.Warn().Err(err).Msg("policy watcher: fsnotify error")
		}
	}
}
