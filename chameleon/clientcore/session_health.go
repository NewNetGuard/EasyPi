package clientcore

import (
	"net/http"
	"time"
)

// A server that restarted or expired the session answers every authenticated
// request with 401 (seen as 404 through nginx) while the client still holds
// the old keys. The transport
// records when such a run of rejections began; any accepted authenticated
// response ends it. Network errors and other statuses leave it unchanged, so
// only a confirmed session rejection can make the owner renegotiate.

// sessionRejectedStatus reports whether an answer on an authenticated tunnel
// route means the server does not accept the session. The server answers 401;
// the nginx front end deliberately rewrites 401 (and 403/405) to 404 so the
// tunnel path looks like any missing page. The tunnel routes always exist on a
// working server, so a 404 there carries the same meaning as the 401.
func sessionRejectedStatus(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusNotFound
}

func (t *Transport) noteSessionRejected() {
	if t == nil {
		return
	}
	t.sessionRejectedSince.CompareAndSwap(0, time.Now().UnixNano())
}

func (t *Transport) noteSessionAccepted() {
	if t == nil {
		return
	}
	t.sessionRejectedSince.Store(0)
}

// SessionRejectedFor reports how long the server has rejected this transport's
// session without accepting any request since; zero while the session is valid.
func (t *Transport) SessionRejectedFor() time.Duration {
	if t == nil {
		return 0
	}
	since := t.sessionRejectedSince.Load()
	if since == 0 {
		return 0
	}
	return time.Since(time.Unix(0, since))
}

// SessionRejectedFor reports how long the server has rejected the active
// session; zero while it is accepted or no transport exists.
func (c *Connection) SessionRejectedFor() time.Duration {
	c.transportMu.RLock()
	transport := c.transport
	c.transportMu.RUnlock()
	return transport.SessionRejectedFor()
}
