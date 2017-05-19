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
	"fmt"
	"time"

	"github.com/DataDog/datadog-go/statsd"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"gopkg.in/validator.v2"
	"gopkg.in/yaml.v2"
)

// StatsdConfiger implements metrics.Opt.
type StatsdConfiger struct{}

// StatsdConfig implements metrics.Config.
type StatsdConfig struct {
	Metrics struct {
		Statsd *statsdFileConfig `yaml:"statsd"`
	} `yaml:"metrics"`
}

type statsdFileConfig struct {
	// The host and port of the statsd server
	HostPort string `yaml:"hostPort" validate:"nonzero"`

	// The prefix to use in reporting to statsd
	Prefix string `yaml:"prefix" validate:"nonzero"`

	// FlushInterval is the maximum interval for sending packets.
	// If it is not specified, it defaults to 1 second.
	FlushInterval time.Duration `yaml:"flushInterval"`

	// FlushBytes specifies the maximum udp packet size you wish to send.
	// If FlushBytes is unspecified, it defaults  to 1432 bytes, which is
	// considered safe for local traffic.
	FlushBytes int `yaml:"flushBytes"`
}

// statsdReporter is a backend to report metrics to.
type statsdReporter struct {
	client *statsd.Client
}

// Assert that we continue to implement the required interfaces.
var (
	_ Opt    = (*StatsdConfiger)(nil)
	_ Config = (*StatsdConfig)(nil)
)

// UnmarshalConfig fetches the configuration file from local path.
func (c StatsdConfiger) UnmarshalConfig(data []byte, fname string, logger *zap.Logger) (Config, error) {

	cfg := new(StatsdConfig)
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling the statsd section in the "+
			"configuration file %s", fname)
	}
	// Validate on the merged config at the end
	if err := validator.Validate(cfg); err != nil {
		return nil, errors.Wrapf(err, "invalid info in the statsd section in the "+
			"configuration file %s", fname)
	}

	return Config(cfg), nil
}

// NewReporter creates a new metrics backend talking to Statsd.
func (c StatsdConfig) NewReporter(logger *zap.Logger) (Reporter, error) {
	s, err := statsd.New(c.Metrics.Statsd.HostPort)
	if err != nil {
		return nil, err
	}
	// add service as prefix
	s.Namespace = fmt.Sprintf("%s.", "arachne")
	logger.Info("Statsd Metrics configuration", zap.String("object", fmt.Sprintf("%+v", s)))

	return &statsdReporter{client: s}, nil
}

func (b *statsdReporter) ReportCounter(name string, tags Tags, value int64) {
	t := make([]string, 0, len(tags))
	for k, v := range tags {
		t = append(t, fmt.Sprintf("%s:%s", k, v))
	}
	b.client.Count(name, value, t, 1.0)
}

func (b *statsdReporter) ReportGauge(name string, tags Tags, value int64) {
	t := make([]string, 0, len(tags))
	for k, v := range tags {
		t = append(t, fmt.Sprintf("%s:%s", k, v))
	}
	b.client.Gauge(name, float64(value), t, 1.0)
}

func (b *statsdReporter) RecordTimer(name string, tags Tags, d time.Duration) {
	t := make([]string, 0, len(tags))
	for k, v := range tags {
		t = append(t, fmt.Sprintf("%s:%s", k, v))
	}
	b.client.TimeInMilliseconds(name, d.Seconds()*1000, t, 1.0)
}

func (b *statsdReporter) Flush() {
}

func (b *statsdReporter) Close() error {
	return nil
}
