package shared

// TrafficMode defines the type of traffic being analyzed.
type TrafficMode string

const (
	ModeBrowsing TrafficMode = "browsing"
	ModeVideo    TrafficMode = "video"
	ModeSystem   TrafficMode = "system"
	ModeIdle     TrafficMode = "idle"
)

// PacketType defines the type of payload.
type PacketType uint8

const (
	PacketTypeData    PacketType = 0x00 // Real VPN data
	PacketTypeCover   PacketType = 0x01 // Cover traffic (ignore)
	PacketTypePadding PacketType = 0x02 // Padding (ignore)
)

// BehaviorMode defines the client's activity level.
type BehaviorMode string

const (
	BehaviorActive     BehaviorMode = "Active"
	BehaviorBackground BehaviorMode = "Background"
	BehaviorIdle       BehaviorMode = "Idle"
)

// ConnectionStatus defines the current connection state.
type ConnectionStatus string

const (
	StatusConnected    ConnectionStatus = "connected"
	StatusDisconnected ConnectionStatus = "disconnected"
	StatusReconnecting ConnectionStatus = "reconnecting"
)

// PacketHeader represents the Chameleon protocol header.
// Magic field removed — authentication is now via HMAC prefix.
type PacketHeader struct {
	PacketID    uint32     // Unique packet ID
	ChunkIndex  uint16     // Index of this chunk
	TotalChunks uint16     // Total number of chunks for this packet
	PayloadLen  uint32     // Length of the payload data
	Type        PacketType // Type of the packet (Data, Cover, Padding)
	_           [3]byte    // Padding to align to 16 bytes
}

// HMACPrefixSize is the number of HMAC bytes prepended to each packet.
// We use the first 16 bytes of HMAC-SHA256(PSK, header||payload) as an
// implicit authenticator that replaces the old static magic number.
const HMACPrefixSize = 16

// HeaderSize is the total size of the Chameleon packet header in bytes
// (excluding the HMAC prefix which is prepended separately).
// 4 (PacketID) + 2 (ChunkIndex) + 2 (TotalChunks) + 4 (PayloadLen) + 1 (Type) + 3 (Pad) = 16
const HeaderSize = 16

// WireHeaderSize is HeaderSize + HMACPrefixSize — the total bytes before payload.
const WireHeaderSize = HMACPrefixSize + HeaderSize

// Endpoint path segments — combined with a per-deployment RoutePrefix at runtime.
// e.g. "/<RoutePrefix>" + EndpointSuffixPush → "/aBc3f1Xy/push"
const (
	EndpointSuffixPush   = "/push"
	EndpointSuffixPoll   = "/poll"
	EndpointSuffixStream = "/stream" // persistent downlink stream over HTTP/2
	EndpointSuffixUpload = "/upload" // persistent uplink stream over HTTP/2
	EndpointSuffixSync   = "/sync"
	EndpointSuffixDNS    = "/dns" // DNS tunnel — raw DNS query/response over HTTPS

	ConnectCarrierHeader  = "X-Chameleon-Connect"
	ConnectCarrierVersion = "1"
	ClientInstanceHeader  = "X-Chameleon-Instance"
)
