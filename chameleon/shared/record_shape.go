package shared

import (
	"crypto/rand"
	"encoding/binary"
)

const (
	RecordShapeHeader       = "X-Chameleon-Record-Shape"
	RecordShapeVersion      = "2"
	EpochAckHeader          = "X-Chameleon-Epoch-Ack"
	EpochAckVersion         = "1"
	BinaryFrameHeaderSize   = 4
	BinaryPaddingFrameFlag  = uint32(1 << 31)
	BinarySequenceFrameFlag = uint32(1 << 30)
	BinaryFrameLengthMask   = BinarySequenceFrameFlag - 1
	MaxRecordPadding        = 2 * 1024
)

// PacketPaddingStepUpBatchBytes decides how tunnel packets are padded. Each
// packet is padded to its size bucket; in a write carrying fewer packet bytes
// than this, the sizes of individual packets can show through the record
// sizes, so the bucket is also raised at random. In a larger write an observer
// only sees the write as a whole, whose length the record padding frame
// already varies: a random raise there costs up to a tenth of the bandwidth of
// bulk transfers and hides nothing.
const PacketPaddingStepUpBatchBytes = 4096

// PacketPaddingStepUp reports whether packets of a write carrying
// batchPacketBytes of raw packets get the random bucket raise.
func PacketPaddingStepUp(batchPacketBytes int) bool {
	return batchPacketBytes < PacketPaddingStepUpBatchBytes
}

// RecordPaddingBudget limits record shaping to roughly 8% for normal batches,
// with a small absolute allowance for sparse traffic and a hard 2 KiB ceiling.
func RecordPaddingBudget(payloadSize int) int {
	if payloadSize <= 0 {
		return 0
	}
	budget := payloadSize / 12
	if budget < 32 {
		budget = 32
	}
	if budget > MaxRecordPadding {
		budget = MaxRecordPadding
	}
	return budget
}

func recordPaddingLength(payloadSize int, entropy byte) int {
	budget := RecordPaddingBudget(payloadSize)
	if budget == 0 {
		return 0
	}
	padding := budget * (1 + int(entropy&7)) / 8
	if padding < 1 {
		padding = 1
	}
	return padding
}

// ShapeBinaryRecord appends one ignorable binary padding frame to a non-empty
// payload. It never emits a standalone record and therefore creates no traffic
// when the tunnel is idle.
func ShapeBinaryRecord(payload []byte) []byte {
	if len(payload) == 0 {
		return nil
	}
	var entropy [1]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return payload
	}
	return ShapeBinaryRecordWithEntropy(payload, entropy[0])
}

// ShapeBinaryRecordWithEntropy is the deterministic policy entry point used by
// evals. Padding contents remain cryptographically random before outer TLS.
func ShapeBinaryRecordWithEntropy(payload []byte, entropy byte) []byte {
	paddingLen := recordPaddingLength(len(payload), entropy)
	if paddingLen == 0 {
		return payload
	}

	out := make([]byte, len(payload)+BinaryFrameHeaderSize+paddingLen)
	copy(out, payload)
	headerOffset := len(payload)
	binary.BigEndian.PutUint32(
		out[headerOffset:headerOffset+BinaryFrameHeaderSize],
		BinaryPaddingFrameFlag|uint32(paddingLen),
	)
	_, _ = rand.Read(out[headerOffset+BinaryFrameHeaderSize:])
	return out
}
