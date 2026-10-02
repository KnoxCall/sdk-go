package knoxcall

import (
	"crypto/rand"
	"time"
)

// Crockford base32 (no I, L, O, U) — the canonical ULID alphabet.
const ulidAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// newULID returns a 26-character ULID (48-bit millisecond timestamp +
// 80 bits of crypto randomness). Used as the idempotency key for mutating
// management-API requests: generated once per logical request, stable
// across retries.
func newULID() string {
	var id [16]byte
	ms := uint64(time.Now().UnixMilli())
	id[0] = byte(ms >> 40)
	id[1] = byte(ms >> 32)
	id[2] = byte(ms >> 24)
	id[3] = byte(ms >> 16)
	id[4] = byte(ms >> 8)
	id[5] = byte(ms)
	if _, err := rand.Read(id[6:]); err != nil {
		panic("knoxcall: crypto/rand unavailable: " + err.Error())
	}

	// Canonical ULID base32 bit-packing.
	var dst [26]byte
	dst[0] = ulidAlphabet[(id[0]&224)>>5]
	dst[1] = ulidAlphabet[id[0]&31]
	dst[2] = ulidAlphabet[(id[1]&248)>>3]
	dst[3] = ulidAlphabet[((id[1]&7)<<2)|((id[2]&192)>>6)]
	dst[4] = ulidAlphabet[(id[2]&62)>>1]
	dst[5] = ulidAlphabet[((id[2]&1)<<4)|((id[3]&240)>>4)]
	dst[6] = ulidAlphabet[((id[3]&15)<<1)|((id[4]&128)>>7)]
	dst[7] = ulidAlphabet[(id[4]&124)>>2]
	dst[8] = ulidAlphabet[((id[4]&3)<<3)|((id[5]&224)>>5)]
	dst[9] = ulidAlphabet[id[5]&31]
	dst[10] = ulidAlphabet[(id[6]&248)>>3]
	dst[11] = ulidAlphabet[((id[6]&7)<<2)|((id[7]&192)>>6)]
	dst[12] = ulidAlphabet[(id[7]&62)>>1]
	dst[13] = ulidAlphabet[((id[7]&1)<<4)|((id[8]&240)>>4)]
	dst[14] = ulidAlphabet[((id[8]&15)<<1)|((id[9]&128)>>7)]
	dst[15] = ulidAlphabet[(id[9]&124)>>2]
	dst[16] = ulidAlphabet[((id[9]&3)<<3)|((id[10]&224)>>5)]
	dst[17] = ulidAlphabet[id[10]&31]
	dst[18] = ulidAlphabet[(id[11]&248)>>3]
	dst[19] = ulidAlphabet[((id[11]&7)<<2)|((id[12]&192)>>6)]
	dst[20] = ulidAlphabet[(id[12]&62)>>1]
	dst[21] = ulidAlphabet[((id[12]&1)<<4)|((id[13]&240)>>4)]
	dst[22] = ulidAlphabet[((id[13]&15)<<1)|((id[14]&128)>>7)]
	dst[23] = ulidAlphabet[(id[14]&124)>>2]
	dst[24] = ulidAlphabet[((id[14]&3)<<3)|((id[15]&224)>>5)]
	dst[25] = ulidAlphabet[id[15]&31]
	return string(dst[:])
}
