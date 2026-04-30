package engine

// EntityID is a probabilistic fingerprint of a client, derived from IP/24
// prefix, User-Agent, and a TLS fingerprint placeholder.
// Using uint64 for fast map keying; String() for log output.
type EntityID uint64

const tlsFPPlaceholder = "tls_fp_placeholder"

// fnv1a64 computes a 64-bit FNV-1a hash of s with zero allocations.
// Iterates string bytes directly — no []byte conversion needed.
func fnv1a64(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// mixString feeds a string then a separator byte into a running FNV-1a64 state.
// Combines multiple inputs without string concatenation (zero allocations).
func mixString(h uint64, s string, sep byte) uint64 {
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= uint64(sep)
	h *= 1099511628211
	return h
}

// ip24prefix returns the /24 prefix of an IPv4 address string by dropping the
// last octet: "192.168.1.100" → "192.168.1".
// For IPv6 addresses or any string without a final dot, returns ip unchanged
// (acceptable degradation — still produces a stable EntityID).
func ip24prefix(ip string) string {
	// Find the last '.' in the string.
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i] == '.' {
			return ip[:i]
		}
	}
	return ip
}

// Compute derives an EntityID from the three input signals:
//   - ip:        client IP address (IPv4 dotted-decimal or IPv6)
//   - userAgent: value of the User-Agent request header
//
// The TLS fingerprint is a hardcoded placeholder for the MVP.
// Zero heap allocations: all hashing is done on the stack.
func Compute(ip, userAgent string) EntityID {
	prefix := ip24prefix(ip)
	h := fnv1a64(prefix)
	h = mixString(h, userAgent, '|')
	h = mixString(h, tlsFPPlaceholder, '|')
	return EntityID(h)
}

// hexChars is the lookup table for manual hex encoding.
const hexChars = "0123456789abcdef"

// String renders the EntityID as a 16-character lowercase hex string.
// Uses a stack-allocated [16]byte — no fmt, no strconv, no heap allocation.
func (e EntityID) String() string {
	var buf [16]byte
	v := uint64(e)
	for i := 15; i >= 0; i-- {
		buf[i] = hexChars[v&0xF]
		v >>= 4
	}
	return string(buf[:])
}
