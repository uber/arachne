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

package metrics

import (
	"time"

	"go.uber.org/zap"
)

// Opt is an interface for config unmarshaled in local configuration files.
type Opt interface {
	UnmarshalConfig(data []byte, fname string, logger *zap.Logger) (Config, error)
}

// Config is an interface for creating metrics-specific stats reporters.
type Config interface {
	NewReporter(logger *zap.Logger) (Reporter, error)
}

// Tags is an alias of map[string]string, a type for tags associated with a statistic.
type Tags map[string]string

// Reporter is an interface for stats reporting functions. Its methods take optional
// tag dictionaries which may be ignored by concrete implementations.
type Reporter interface {
	// ReportCounter reports a counter value
	ReportCounter(name string, tags Tags, value int64)

	// ReportGauge reports a gauge value
	ReportGauge(name string, tags Tags, value int64)

	// RecordTimer
	RecordTimer(name string, tags Tags, d time.Duration)

	// Flush is expected to be called by a Scope when it completes a round or reporting
	Flush()

	// Close conducts a clean exit for the stats reporting.
	Close() error
}
