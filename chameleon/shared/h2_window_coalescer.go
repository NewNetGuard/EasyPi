package shared

import (
	"bytes"
	"encoding/binary"
)

// Browsers return HTTP/2 flow-control credit rarely: Chromium sends a
// WINDOW_UPDATE once half of a receive window has been consumed. x/net/http2
// sends one for every 4 KiB read, on the client and on the server, which turns
// a long download into a dense stream of tiny records that a passive observer
// can tell apart from a browser.
//
// h2WindowCoalescer rewrites the outgoing plaintext HTTP/2 byte stream so
// credit is returned the browser way. Credit is only delayed, never dropped:
// a stream's credit is released once it reaches half of the advertised window,
// so the peer always keeps at least half a window to send into and cannot
// stall. Every other frame passes through byte for byte; DATA payloads are
// skipped without inspection.
const (
	h2SettingsFrameType      = 0x4
	h2SettingsAckFlag        = 0x1
	h2SettingsInitialWindow  = 0x4
	h2SettingsMaxFrameSize   = 0x5
	h2DefaultMaxFrameSize    = 16384
	h2SettingSize            = 6
	h2DefaultInitialWindow   = 65535
	h2MaxParsedSettingsBytes = 512
	h2WindowUpdateFrameSize  = h2FrameHeaderSize + h2WindowUpdateSize
	// Credit is held per stream; streams that end below the threshold are
	// released oldest-first so the table stays bounded. Peers ignore credit
	// for streams that are already closed.
	h2MaxHeldStreams = 128
)

type h2HeldCredit struct {
	credit int64
	order  uint64
}

type h2WindowCoalescer struct {
	prefaceChecked bool
	// client is set when the stream starts with the client preface; only the
	// client's opening SETTINGS are rewritten.
	client          bool
	openingSettings bool
	pending         []byte
	passRemaining   int
	streamWindow    int64
	connWindow      int64
	initialConnSeen bool
	held            map[uint32]*h2HeldCredit
	order           uint64
}

func newH2WindowCoalescer() *h2WindowCoalescer {
	return &h2WindowCoalescer{
		streamWindow: h2DefaultInitialWindow,
		connWindow:   h2DefaultInitialWindow,
		held:         make(map[uint32]*h2HeldCredit),
	}
}

// process consumes plaintext written by the HTTP/2 framer and returns the bytes
// to send now. Incomplete frame headers are kept until the next call; framers
// always complete a frame before flushing, so nothing waits on the network.
func (c *h2WindowCoalescer) process(input []byte) []byte {
	data := input
	if len(c.pending) > 0 {
		data = append(c.pending, input...)
		c.pending = nil
	}
	out := make([]byte, 0, len(data)+h2WindowUpdateFrameSize)

	if !c.prefaceChecked {
		size := min(len(data), len(h2ClientPreface))
		switch {
		case !bytes.Equal(data[:size], h2ClientPreface[:size]):
			// A server never sends the client preface; parse frames from byte 0.
			c.prefaceChecked = true
		case len(data) < len(h2ClientPreface):
			c.pending = append([]byte(nil), data...)
			return out
		default:
			out = append(out, data[:len(h2ClientPreface)]...)
			data = data[len(h2ClientPreface):]
			c.prefaceChecked = true
			c.client = true
		}
	}

	for len(data) > 0 {
		if c.passRemaining > 0 {
			size := min(c.passRemaining, len(data))
			out = append(out, data[:size]...)
			data = data[size:]
			c.passRemaining -= size
			continue
		}
		if len(data) < h2FrameHeaderSize {
			c.pending = append([]byte(nil), data...)
			break
		}
		length := int(data[0])<<16 | int(data[1])<<8 | int(data[2])
		frameType, flags := data[3], data[4]
		switch {
		case frameType == h2WindowUpdateFrameType && length == h2WindowUpdateSize:
			if len(data) < h2WindowUpdateFrameSize {
				c.pending = append([]byte(nil), data...)
				return out
			}
			out = c.windowUpdate(out, data[:h2WindowUpdateFrameSize])
			data = data[h2WindowUpdateFrameSize:]
		case frameType == h2SettingsFrameType && flags&h2SettingsAckFlag == 0 && length <= h2MaxParsedSettingsBytes:
			if len(data) < h2FrameHeaderSize+length {
				c.pending = append([]byte(nil), data...)
				return out
			}
			frame := data[:h2FrameHeaderSize+length]
			c.settings(frame[h2FrameHeaderSize:])
			if c.client && !c.openingSettings {
				c.openingSettings = true
				out = appendBrowserOpeningSettings(out, frame)
			} else {
				out = append(out, frame...)
			}
			data = data[h2FrameHeaderSize+length:]
		default:
			out = append(out, data[:h2FrameHeaderSize]...)
			data = data[h2FrameHeaderSize:]
			c.passRemaining = length
		}
	}
	return out
}

func (c *h2WindowCoalescer) settings(payload []byte) {
	for len(payload) >= 6 {
		identifier := binary.BigEndian.Uint16(payload[0:2])
		value := binary.BigEndian.Uint32(payload[2:6])
		if identifier == h2SettingsInitialWindow && value > 0 && value <= h2MaxWindow {
			c.streamWindow = int64(value)
		}
		payload = payload[6:]
	}
}

// appendBrowserOpeningSettings appends the client's opening SETTINGS frame
// without a SETTINGS_MAX_FRAME_SIZE entry that only repeats the protocol
// default. x/net/http2 always sends that entry; Chromium does not. The record
// carrying the preface is the first one after the outer handshake, so its size
// alone told the two apart (93 bytes against Chromium's 87). Dropping a default
// value changes nothing the server negotiates; any other value is kept.
func appendBrowserOpeningSettings(out, frame []byte) []byte {
	start := len(out)
	out = append(out, frame[:h2FrameHeaderSize]...)
	payload := frame[h2FrameHeaderSize:]
	for len(payload) >= h2SettingSize {
		identifier := binary.BigEndian.Uint16(payload[0:2])
		value := binary.BigEndian.Uint32(payload[2:6])
		if identifier != h2SettingsMaxFrameSize || value != h2DefaultMaxFrameSize {
			out = append(out, payload[:h2SettingSize]...)
		}
		payload = payload[h2SettingSize:]
	}
	// A malformed trailing fragment is passed on for the peer to reject.
	out = append(out, payload...)
	length := len(out) - start - h2FrameHeaderSize
	out[start], out[start+1], out[start+2] = byte(length>>16), byte(length>>8), byte(length)
	return out
}

const h2MaxWindow = 1<<31 - 1

func (c *h2WindowCoalescer) windowUpdate(out, frame []byte) []byte {
	streamID := binary.BigEndian.Uint32(frame[5:9]) & 0x7fffffff
	credit := int64(binary.BigEndian.Uint32(frame[9:13]) & 0x7fffffff)
	if credit == 0 {
		// A zero increment is a protocol error the peer must see unchanged.
		return append(out, frame...)
	}
	if streamID == 0 && !c.initialConnSeen {
		// The opening connection update advertises the connection window.
		c.initialConnSeen = true
		c.connWindow = min(h2DefaultInitialWindow+credit, h2MaxWindow)
		return append(out, frame...)
	}

	window := c.streamWindow
	if streamID == 0 {
		window = c.connWindow
	}
	threshold := max(window/2, 1)

	entry := c.held[streamID]
	if entry == nil {
		if streamID != 0 && c.heldStreams() >= h2MaxHeldStreams {
			out = c.releaseOldestStream(out)
		}
		entry = &h2HeldCredit{}
		c.held[streamID] = entry
	}
	entry.credit += credit
	c.order++
	entry.order = c.order
	if entry.credit >= threshold || entry.credit > h2MaxWindow-window {
		out = appendWindowUpdate(out, streamID, entry.credit)
		delete(c.held, streamID)
	}
	return out
}

func (c *h2WindowCoalescer) heldStreams() int {
	count := len(c.held)
	if _, ok := c.held[0]; ok {
		count--
	}
	return count
}

func (c *h2WindowCoalescer) releaseOldestStream(out []byte) []byte {
	var oldestID uint32
	var oldest *h2HeldCredit
	for streamID, entry := range c.held {
		if streamID != 0 && (oldest == nil || entry.order < oldest.order) {
			oldestID, oldest = streamID, entry
		}
	}
	if oldest == nil {
		return out
	}
	delete(c.held, oldestID)
	return appendWindowUpdate(out, oldestID, oldest.credit)
}

func appendWindowUpdate(out []byte, streamID uint32, credit int64) []byte {
	var frame [h2WindowUpdateFrameSize]byte
	frame[2] = h2WindowUpdateSize
	frame[3] = h2WindowUpdateFrameType
	binary.BigEndian.PutUint32(frame[5:9], streamID&0x7fffffff)
	binary.BigEndian.PutUint32(frame[9:13], uint32(credit)&0x7fffffff)
	return append(out, frame[:]...)
}
