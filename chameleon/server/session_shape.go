package main

import (
	"context"
	mathrand "math/rand/v2"
	"time"
)

// Every carrier connection opens with the session setup exchange (challenge,
// establishment, sync). The backend used to answer it instantly with bodies
// of nearly constant size, so nginx sent the answer in the same burst as its
// session tickets and SETTINGS, and the client's SETTINGS acknowledgement
// always followed the answer: one request, a fixed-size flight, one tiny
// record. TLS-in-TLS classifiers look for exactly that shape.
//
// A short random processing time, as any dynamic web backend has, lets the
// acknowledgement go out before the answer, and random
// padding removes the constant body sizes. Nothing about authentication or
// the session keys changes.
var (
	// The delay before a session setup answer is drawn from
	// [sessionThinkTimeMin, sessionThinkTimeMax). The minimum covers the time
	// a slow client (an ARM gateway) needs to read the server's opening flight
	// and acknowledge its SETTINGS; an answer arriving sooner still overtook
	// that acknowledgement on the Raspberry Pi.
	sessionThinkTimeMin = 4 * time.Millisecond
	sessionThinkTimeMax = 44 * time.Millisecond
	// sessionPaddingMax bounds the padding field added to its JSON body.
	sessionPaddingMax = 640
)

const sessionPaddingAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// sessionThinkTime waits a random time in [sessionThinkTimeMin,
// sessionThinkTimeMax), or until the request is cancelled.
func sessionThinkTime(ctx context.Context) {
	if sessionThinkTimeMax <= sessionThinkTimeMin {
		return
	}
	delay := sessionThinkTimeMin + time.Duration(mathrand.Int64N(int64(sessionThinkTimeMax-sessionThinkTimeMin)))
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// sessionPadding returns a random string of random length in
// [0, sessionPaddingMax]. Clients ignore the field it is sent in.
func sessionPadding() string {
	if sessionPaddingMax <= 0 {
		return ""
	}
	padding := make([]byte, mathrand.IntN(sessionPaddingMax+1))
	for i := range padding {
		padding[i] = sessionPaddingAlphabet[mathrand.IntN(len(sessionPaddingAlphabet))]
	}
	return string(padding)
}
