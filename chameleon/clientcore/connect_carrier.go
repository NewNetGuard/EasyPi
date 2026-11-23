package clientcore

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"chameleon/shared"
)

// connectLoop carries both directions through one authenticated HTTP/2 CONNECT
// stream while retaining Chameleon's encrypted binary framing and epoch ACKs.
func (t *Transport) connectLoop() {
	reconnectDelay := 120 * time.Millisecond

	for {
		if t.ctx.Err() != nil {
			return
		}
		select {
		case drain := <-t.uploadDrain:
			drain.result <- nil
			select {
			case <-drain.release:
			case <-t.ctx.Done():
				return
			}
			continue
		default:
		}

		client, epochCtx, _ := t.currentStreamEpoch()
		if client == nil || epochCtx == nil {
			time.Sleep(reconnectDelay)
			continue
		}

		reqCtx, cancel := context.WithCancel(epochCtx)
		pr, pw := io.Pipe()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodConnect, t.serverURL, pr)
		if err != nil {
			cancel()
			_ = pr.Close()
			_ = pw.Close()
			time.Sleep(reconnectDelay)
			continue
		}
		t.addConnectHeaders(req)

		resp, err := client.Do(req)
		if err != nil {
			cancel()
			_ = pw.CloseWithError(err)
			_ = pr.Close()
			atomic.StoreInt32(&t.streamLive, 0)
			atomic.StoreInt32(&t.uplinkLive, 0)
			time.Sleep(reconnectDelay)
			if reconnectDelay < 2*time.Second {
				reconnectDelay *= 2
			}
			continue
		}

		if sessionRejectedStatus(resp.StatusCode) {
			t.noteSessionRejected()
		}
		if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK ||
			resp.Header.Get(shared.ConnectCarrierHeader) != shared.ConnectCarrierVersion {
			_ = resp.Body.Close()
			cancel()
			_ = pw.Close()
			_ = pr.Close()
			LogRateLimitedEvent("transport", "CONNECT carrier rejected")
			time.Sleep(reconnectDelay)
			if reconnectDelay < 2*time.Second {
				reconnectDelay *= 2
			}
			continue
		}

		responseDone := make(chan error, 1)
		go func() {
			responseDone <- t.parseBinaryStream(resp.Body)
		}()

		reconnectDelay = 120 * time.Millisecond
		t.noteSessionAccepted()
		atomic.StoreInt32(&t.streamLive, 1)
		atomic.StoreInt32(&t.uplinkLive, 1)
		t.onRequest()

		var writeErr error
		responseConsumed := false
		ackBatcher := newDownlinkAckBatcher(t, pw)
		if err := ackBatcher.flush(downlinkAckWriteForced); err != nil {
			writeErr = err
		}

	loop:
		for writeErr == nil {
			select {
			case <-reqCtx.Done():
				writeErr = reqCtx.Err()
				break loop
			case drain := <-t.uploadDrain:
				drainErr := ackBatcher.flush(downlinkAckWriteForced)
				if drainErr == nil {
					drainErr = t.flushQueuedUplink(pw)
				}
				if drainErr == nil {
					drainErr = pw.Close()
				}
				if drainErr == nil {
					select {
					case drainErr = <-responseDone:
						responseConsumed = true
					case <-drain.ctx.Done():
						drainErr = drain.ctx.Err()
					case <-reqCtx.Done():
						drainErr = reqCtx.Err()
					}
				}
				drain.result <- drainErr
				select {
				case <-drain.release:
				case <-t.ctx.Done():
					writeErr = t.ctx.Err()
				}
				if writeErr == nil {
					writeErr = drainErr
				}
				break loop
			case err := <-responseDone:
				responseConsumed = true
				if err == nil {
					err = io.EOF
				}
				writeErr = err
				break loop
			case <-t.downlinkAckNotify:
				if err := ackBatcher.notify(); err != nil {
					writeErr = err
					break loop
				}
			case <-ackBatcher.timerChannel():
				if err := ackBatcher.flush(downlinkAckWriteTimer); err != nil {
					writeErr = err
					break loop
				}
			case framedBatch := <-t.uplinkFrames:
				if len(framedBatch) == 0 {
					continue
				}
				if err := ackBatcher.writeBatch(framedBatch, downlinkAckWritePiggyback); err != nil {
					writeErr = err
					break loop
				}
			}
		}

		ackBatcher.close()
		atomic.StoreInt32(&t.streamLive, 0)
		atomic.StoreInt32(&t.uplinkLive, 0)
		_ = pw.CloseWithError(writeErr)
		_ = pr.Close()
		cancel()
		_ = resp.Body.Close()
		if !responseConsumed {
			select {
			case <-responseDone:
			case <-time.After(250 * time.Millisecond):
			}
		}

		if t.ctx.Err() != nil {
			return
		}
		time.Sleep(reconnectDelay)
		if reconnectDelay < 2*time.Second {
			reconnectDelay *= 2
		}
	}
}
