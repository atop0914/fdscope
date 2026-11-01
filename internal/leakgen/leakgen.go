//go:build linux

package leakgen

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Kind is the resource the generator opens.
type Kind string

const (
	// KindFile opens an ordinary file and keeps it open. Several descriptors may
	// point at the same path (see Config.Paths), which is what a cache that
	// re-opens a file it already holds looks like from /proc.
	KindFile Kind = "file"
	// KindSocket opens a unix-domain listening socket: one real socket
	// descriptor, the shape a connection pool leaks in.
	KindSocket Kind = "socket"
	// KindDeleted opens a file, unlinks the path and keeps the descriptor. This
	// is the " (deleted)" shape: the space is not reclaimed and `du` cannot see
	// it, which is the case that motivates the whole project.
	KindDeleted Kind = "deleted"
)

// DefaultRate is the number of descriptors per second used when a Config leaves
// Rate unset.
const DefaultRate = 50

// MinInterval floors the spacing between two opens. Without it a rate of ten
// thousand per second would ask the ticker for a zero duration and panic.
const MinInterval = time.Millisecond

// Config describes what a Generator opens and how fast.
//
// The zero value is usable: 50 files per second, never closed, all pointing at
// one path.
type Config struct {
	// Rate is the number of descriptors opened per second. Zero means
	// DefaultRate; negative is rejected.
	Rate int
	// Kind selects the resource. Empty means KindFile; an unknown value is
	// rejected rather than silently treated as a file, because a typo that
	// quietly produced the wrong shape would make the test look like it covered
	// something it did not.
	Kind Kind
	// Lifetime is how long each descriptor stays open. Zero means "never", which
	// is what a leak is. A positive value produces a bounded population: the
	// reversal used to prove that the verdict is not simply always "leak".
	Lifetime time.Duration
	// Paths is how many distinct files are reused in round-robin. 1 means every
	// descriptor points at the same path (one growing fingerprint); a larger
	// number spreads the growth over several fingerprints, which is what a cache
	// over a working set looks like. Ignored for sockets and deleted files, which
	// need a unique name per descriptor.
	Paths int
	// Dir is where the files and sockets are created. Empty means a temporary
	// directory under the system temp dir, owned (and removed) by the Generator.
	Dir string
}

// normalize fills in defaults and rejects values that cannot mean what the
// caller wanted.
func (c Config) normalize() (Config, error) {
	if c.Rate < 0 {
		return Config{}, fmt.Errorf("leak rate must not be negative, got %d", c.Rate)
	}
	if c.Rate == 0 {
		c.Rate = DefaultRate
	}
	switch c.Kind {
	case "":
		c.Kind = KindFile
	case KindFile, KindSocket, KindDeleted:
	default:
		return Config{}, fmt.Errorf("unknown leak kind %q", string(c.Kind))
	}
	if c.Lifetime < 0 {
		return Config{}, fmt.Errorf("lifetime must not be negative, got %s", c.Lifetime)
	}
	if c.Paths < 0 {
		return Config{}, fmt.Errorf("path count must not be negative, got %d", c.Paths)
	}
	if c.Paths == 0 {
		c.Paths = 1
	}
	return c, nil
}

// resource is one descriptor the generator is holding.
type resource struct {
	closer io.Closer
	// path is the file to unlink when the descriptor closes: empty for ordinary
	// files (they stay for the next round) and for sockets it is the socket name.
	path string
	// closeAt is when a finite lifetime expires. The zero time means never.
	closeAt time.Time
}

// Generator holds open descriptors until it is closed.
//
// It is safe for concurrent use: Run appends from one goroutine and the counters
// are read from another.
type Generator struct {
	cfg      Config
	dir      string
	interval time.Duration
	// owned says whether Close removes dir. A directory the caller passed in is
	// the caller's to clean up.
	owned bool

	mu     sync.Mutex
	held   []*resource
	opened int
	seq    int
	err    error
}

// New creates a generator. It touches the filesystem only to make the working
// directory; no descriptor is opened until Run is called.
func New(cfg Config) (*Generator, error) {
	norm, err := cfg.normalize()
	if err != nil {
		return nil, err
	}
	dir := norm.Dir
	owned := false
	if dir == "" {
		dir, err = os.MkdirTemp("", "fdscope-leakgen-")
		if err != nil {
			return nil, fmt.Errorf("create leak directory: %w", err)
		}
		owned = true
	} else if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create leak directory %s: %w", dir, err)
	}
	interval := time.Second / time.Duration(norm.Rate)
	if interval < MinInterval {
		interval = MinInterval
	}
	return &Generator{cfg: norm, dir: dir, interval: interval, owned: owned}, nil
}

// Dir is the directory the descriptors are created in. Reports group by path, so
// a test asserting on fingerprints needs it.
func (g *Generator) Dir() string { return g.dir }

// Run opens descriptors until ctx is cancelled. It does not close what it opened:
// that is what Close is for, and a run that tidied up after itself would leave
// nothing for a sampler to find.
func (g *Generator) Run(ctx context.Context) {
	ticker := time.NewTicker(g.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			g.reap(now)
			g.openOne()
		}
	}
}

// Opened reports how many descriptors this generator has opened. It is a
// diagnostic, not evidence: a test that asserts on this number is asserting on
// the fixture's own bookkeeping, which is exactly the mistake the corpus under
// testdata/corpus exists to study. Read /proc instead.
func (g *Generator) Opened() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.opened
}

// Held reports how many descriptors the generator still holds. Diagnostic, with
// the same caveat as Opened.
func (g *Generator) Held() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.held)
}

// Err returns the first failure the run hit. Run has no error return - it runs
// until cancelled - so this is how a fixture reports that it could not open
// anything, instead of silently leaking nothing and letting the verdict be read
// as "no leak".
func (g *Generator) Err() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.err
}

// Close releases every descriptor and removes the directory if the generator
// created it.
func (g *Generator) Close() error {
	g.mu.Lock()
	held := g.held
	g.held = nil
	g.mu.Unlock()

	var first error
	for _, r := range held {
		if err := closeResource(r); err != nil && first == nil {
			first = err
		}
	}
	if g.owned {
		if err := os.RemoveAll(g.dir); err != nil && first == nil {
			first = fmt.Errorf("remove leak directory: %w", err)
		}
	}
	return first
}

// openOne opens a single descriptor. Failures are recorded rather than returned:
// the caller's loop has nowhere to put an error, and a fixture that died on the
// first EMFILE would look like a fixture that finished early.
func (g *Generator) openOne() {
	g.mu.Lock()
	defer g.mu.Unlock()

	seq := g.seq
	var r *resource
	var err error
	switch g.cfg.Kind {
	case KindSocket:
		r, err = g.openSocket(seq)
	case KindDeleted:
		r, err = g.openDeleted(seq)
	case KindFile:
		r, err = g.openFile(seq)
	}
	if err != nil {
		if g.err == nil {
			g.err = err
		}
		return
	}
	g.seq++
	if g.cfg.Lifetime > 0 {
		r.closeAt = time.Now().Add(g.cfg.Lifetime)
	}
	g.held = append(g.held, r)
	g.opened++
}

// openFile keeps an ordinary file open. The round-robin over Paths is what makes
// several descriptors share one fingerprint, which is the shape a cache over a
// working set produces.
func (g *Generator) openFile(seq int) (*resource, error) {
	name := filepath.Join(g.dir, fmt.Sprintf("leak-%d.dat", seq%g.cfg.Paths))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", name, err)
	}
	return &resource{closer: f}, nil
}

// openSocket opens a listening unix socket. The name must be unique: two sockets
// cannot bind the same path, so Paths does not apply here.
func (g *Generator) openSocket(seq int) (*resource, error) {
	name := filepath.Join(g.dir, fmt.Sprintf("leak-%d.sock", seq))
	ln, err := net.Listen("unix", name)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", name, err)
	}
	return &resource{closer: ln, path: name}, nil
}

// openDeleted creates a file, unlinks it, and keeps the descriptor: the only way
// to produce the " (deleted)" target /proc reports for an unlinked-but-held file.
func (g *Generator) openDeleted(seq int) (*resource, error) {
	name := filepath.Join(g.dir, fmt.Sprintf("gone-%d.tmp", seq))
	f, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create %s: %w", name, err)
	}
	if err := os.Remove(name); err != nil {
		// The descriptor is open but the path survived, so the target /proc shows
		// would not carry the " (deleted)" mark and the fixture would silently be
		// testing the ordinary-file shape.
		_ = f.Close()
		return nil, fmt.Errorf("unlink %s: %w", name, err)
	}
	return &resource{closer: f}, nil
}

// reap closes the descriptors whose finite lifetime has expired.
func (g *Generator) reap(now time.Time) {
	g.mu.Lock()
	kept := g.held[:0]
	var expired []*resource
	for _, r := range g.held {
		if !r.closeAt.IsZero() && !now.Before(r.closeAt) {
			expired = append(expired, r)
			continue
		}
		kept = append(kept, r)
	}
	g.held = kept
	g.mu.Unlock()

	for _, r := range expired {
		if err := closeResource(r); err != nil && g.Err() == nil {
			g.mu.Lock()
			if g.err == nil {
				g.err = err
			}
			g.mu.Unlock()
		}
	}
}

// closeResource releases one descriptor and any socket name it owned.
func closeResource(r *resource) error {
	err := r.closer.Close()
	if r.path != "" {
		if rmErr := os.Remove(r.path); rmErr != nil && !os.IsNotExist(rmErr) && err == nil {
			err = fmt.Errorf("remove %s: %w", r.path, rmErr)
		}
	}
	return err
}
