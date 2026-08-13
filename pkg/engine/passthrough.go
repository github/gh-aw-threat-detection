package engine

import (
	"io"
	"strings"
	"sync"

	"github.com/github/gh-aw-threat-detection/pkg/logsafe"
)

// PassthroughPrefix is prepended to every line of engine subprocess output that
// the detector forwards to its own standard error. The engine analyzes
// attacker-controlled artifacts, so its output is untrusted: without a frame,
// model-authored text containing a newline could impersonate a detector
// diagnostic (a THREAT_DETECTION_* marker) or a host workflow command. The
// prefix makes forwarded bytes distinguishable — for humans reading the job log
// and for tooling that scans it — while preserving real-time streaming.
//
// Consumers that scan the captured log for detector-attested markers MUST
// ignore lines carrying this prefix.
const PassthroughPrefix = "[engine] "

// maxPassthroughLineBytes bounds how much engine output is buffered while
// waiting for a line terminator. An engine that never emits a newline would
// otherwise grow the buffer without limit; past this many bytes the pending
// content is flushed as its own framed line.
const maxPassthroughLineBytes = 8192

// passthroughFramer forwards engine subprocess output to a destination writer,
// one framed line at a time. A single framer serves both the stdout and stderr
// streams of one subprocess: it owns the lock that keeps their interleaved
// writes from splicing into each other's lines.
type passthroughFramer struct {
	mu      sync.Mutex
	dst     io.Writer
	writers []*passthroughWriter
}

func newPassthroughFramer(dst io.Writer) *passthroughFramer {
	return &passthroughFramer{dst: dst}
}

// writer returns a new stream writer bound to this framer. It must be called
// before the subprocess starts, since the writer list is not itself guarded.
func (f *passthroughFramer) writer() io.Writer {
	w := &passthroughWriter{framer: f}
	f.writers = append(f.writers, w)
	return w
}

// Close flushes any partial line each stream left behind — output that ended
// without a trailing newline, which would otherwise be lost.
func (f *passthroughFramer) Close() {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.writers {
		w.flushLocked()
	}
}

// passthroughWriter accumulates one stream's bytes and emits a framed line each
// time a terminator is seen.
type passthroughWriter struct {
	framer    *passthroughFramer
	buf       []byte
	pendingCR bool
}

// Write never reports an error: forwarding is a diagnostic convenience, and
// failing the subprocess because the job log could not be written would turn a
// cosmetic problem into a detection outage.
func (w *passthroughWriter) Write(p []byte) (int, error) {
	f := w.framer
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range p {
		if w.pendingCR {
			w.pendingCR = false
			// A CR already terminated the line; swallow the LF of a CRLF pair
			// rather than emitting an empty line for it.
			if b == '\n' {
				continue
			}
		}
		switch b {
		case '\n':
			w.emitLocked()
		case '\r':
			// A bare CR is treated as a terminator too: the Actions runner
			// splits process output on CR as well as LF, so leaving one inline
			// would let engine output start a line the runner then parses.
			w.emitLocked()
			w.pendingCR = true
		default:
			w.buf = append(w.buf, b)
			if len(w.buf) >= maxPassthroughLineBytes {
				w.emitLocked()
			}
		}
	}
	return len(p), nil
}

func (w *passthroughWriter) emitLocked() {
	line := neutralizeWorkflowCommand(string(w.buf))
	w.buf = w.buf[:0]
	_, _ = io.WriteString(w.framer.dst, PassthroughPrefix+line+"\n")
}

func (w *passthroughWriter) flushLocked() {
	if len(w.buf) > 0 {
		w.emitLocked()
	}
}

// neutralizeWorkflowCommand defuses a line that tries to open a GitHub Actions
// workflow command, in both marker forms the runner accepts.
//
// The `::command::` form is only honored at the start of a line (after trimming
// leading whitespace), so the frame prefix already prevents the runner from
// seeing one; rewriting it is defense in depth for consumers that strip the
// prefix, and it keeps the intent visible in the log rather than silently
// dropping it.
//
// The legacy `##[command]` form is different in kind: the runner locates it
// anywhere within a line, so neither the frame prefix nor any indentation makes
// it inert. It must be broken up inside the value itself, exactly as the
// detector's own diagnostics do.
func neutralizeWorkflowCommand(line string) string {
	line = logsafe.EscapeLegacyCommandMarker(line)
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, "::") {
		return line
	}
	indent := line[:len(line)-len(trimmed)]
	return indent + "%3A%3A" + trimmed[2:]
}
