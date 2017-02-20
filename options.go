// Copyright (c) 2016 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package arachne

import "github.com/uber/arachne/config"

// Option wraps a function to configure GlobalConfig.
type Option func(*config.Global) Option

// apply sets the options specified. It also returns an option to
// restore the arguments' previous values, if needed.
func apply(c *config.Global, opts ...Option) []Option {
	prevs := make([]Option, len(opts))
	for i, opt := range opts {
		prevs[i] = opt(c)
	}
	return prevs
}

// ReceiverOnlyMode sets receiver-only mode to `b`.
// To set this option temporarily and have it reverted, do:
//     prevRxOnlyMode := apply(&gl, ReceiverOnlyMode(true))
//     DoSomeDebugging()
//     apply(prevRxOnlyMode)
func ReceiverOnlyMode(b bool) Option {
	return func(gl *config.Global) Option {
		previous := *gl.CLI.ReceiverOnlyMode
		*gl.CLI.ReceiverOnlyMode = b
		return ReceiverOnlyMode(previous)
	}
}

// SenderOnlyMode sets sender-only mode to `b.`
func SenderOnlyMode(b bool) Option {
	return func(gl *config.Global) Option {
		previous := *gl.CLI.ReceiverOnlyMode
		*gl.CLI.SenderOnlyMode = b
		return SenderOnlyMode(previous)
	}
}
