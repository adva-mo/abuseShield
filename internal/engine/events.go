package engine

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
)

// Signal represents a single fired detection rule — one entry per layer that
// produced a non-clean result. Multiple signals can fire on the same request
// (e.g. L1 burst + L2 sequence violation).
type Signal struct {
	Layer      string  `json:"layer"`      // "L1" | "L2"
	Reason     string  `json:"reason"`     // e.g. "burst_detected", "sequence_violation"
	Confidence float64 `json:"confidence"` // 0.0–1.0
}

// SecurityEvent is emitted for every request that passes through the detection
// engine. Decision/Reason/Confidence reflect the highest-priority signal.
// Signals lists every rule that fired so the client sees the full picture.
type SecurityEvent struct {
	Timestamp  string   `json:"timestamp"`   // RFC3339Nano
	EntityID   string   `json:"entity_id"`   // 16-char hex
	IP         string   `json:"ip"`          // /24 CIDR, e.g. "192.168.1.0/24"
	UserAgent  string   `json:"user_agent"`
	Path       string   `json:"path"`
	Method     string   `json:"method"`
	Decision   string   `json:"decision"`    // "ALLOW" | "BLOCK" | "SUSPICIOUS"
	Reason     string   `json:"reason"`      // primary reason (highest-priority signal)
	Confidence float64  `json:"confidence"`  // confidence of primary signal
	Signals    []Signal `json:"signals"`     // all fired signals across all layers
	ShadowMode bool     `json:"shadow_mode"` // true = detection only, request was forwarded regardless
	Blocked    bool     `json:"blocked"`     // true = request was rejected and NOT forwarded to upstream
}

// EventsDropped counts SecurityEvents that were silently dropped because the
// async buffer was full. Exported for use by metrics package.
var EventsDropped atomic.Int64

// Logger is an async SecurityEvent writer backed by a buffered channel.
// A background goroutine drains the channel and writes JSON lines to the
// configured io.Writer.
type Logger struct {
	ch  chan SecurityEvent
	enc *json.Encoder
	wg  sync.WaitGroup
}

// NewLogger creates a Logger with the given buffer size, writing JSON lines to w.
// The background drain goroutine starts immediately.
// Caller must call Close() during shutdown to flush remaining events.
func NewLogger(bufSize int, w io.Writer) *Logger {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // keep User-Agent strings readable in logs
	l := &Logger{
		ch:  make(chan SecurityEvent, bufSize),
		enc: enc,
	}
	l.wg.Add(1)
	go l.drain()
	return l
}

// Emit enqueues a SecurityEvent for async writing.
// Non-blocking: if the channel buffer is full the event is silently dropped
// and EventsDropped is incremented. The hot path is never blocked.
func (l *Logger) Emit(ev SecurityEvent) {
	select {
	case l.ch <- ev:
	default:
		EventsDropped.Add(1)
	}
}

// Close drains the remaining events and waits for the background writer to
// finish. Must be called once during graceful shutdown.
func (l *Logger) Close() {
	close(l.ch)
	l.wg.Wait()
}

// drain is the background goroutine that serializes events to JSON lines.
// It exits when the channel is closed and fully drained.
func (l *Logger) drain() {
	defer l.wg.Done()
	for ev := range l.ch {
		// Encoding errors (e.g. broken writer) are intentionally ignored —
		// the proxy must never stop serving traffic due to a logging failure.
		_ = l.enc.Encode(ev) //nolint:errcheck
	}
}
