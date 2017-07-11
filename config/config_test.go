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

package config

import (
	"io/ioutil"
	coreLog "log"
	"runtime"
	"testing"

	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/internal/util"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
)

func TestReadConfig(t *testing.T) {
	assert := assert.New(t)
	var (
		err                error
		gl                 Global
		testConfigFilePath string
	)

	l, err := zap.NewDevelopment()
	if err != nil {
		coreLog.Fatal(err)
	}
	logger := &log.Logger{
		Logger:    l,
		PIDPath:   "",
		RemovePID: util.RemovePID,
	}

	gl.RemoteConfig = new(RemoteConfig)
	remotes := make(RemoteStore, defines.MaxNumRemoteTargets)

	switch runtime.GOOS {
	case "linux":
		testConfigFilePath = defines.ArachneTestConfigFilePathLinux
	case "darwin":
		testConfigFilePath = defines.ArachneTestConfigFilePathDarwin
	default:
		t.Fatalf("unsupported OS for testing: " + runtime.GOOS)
	}

	raw, err := ioutil.ReadFile(testConfigFilePath)
	if err != nil {
		t.Errorf("File error: %v. Exiting...\n", err)
	}
	err = readRemoteList(raw, gl.RemoteConfig, remotes, defines.MaxNumSrcTCPPorts, defines.MinBatchInterval,
		logger)
	assert.NoError(err, "error parsing YAML test configuration file: %v", err)

	assert.Equal("us-west", gl.RemoteConfig.Location,
		"error parsing 'location' from YAML test configuration file")
	assert.Equal(44111, int(gl.RemoteConfig.TargetTCPPort),
		"error parsing 'listen_tcp_port' from YAML test configuration file")
	assert.Equal(31000, int(gl.RemoteConfig.SrcTCPPortRange[0]),
		"error parsing 'base_src_tcp_port' from YAML test configuration file")
	if !assert.Equal(int64(10000000000), int64(gl.RemoteConfig.BatchInterval)) {
		t.Error("error parsing 'batch_interval' from YAML test configuration file")
	}

	assert.False(gl.RemoteConfig.QoSEnabled, "error parsing QoS from YAML test configuration file")
	assert.True(gl.RemoteConfig.ResolveDNS, "error parsing resolve_dns from YAML test configuration file")

	if r1, ok := remotes["10.10.39.31"]; !ok {
		t.Errorf("Remotes are %+v in %s", remotes, testConfigFilePath)
		t.Error("failed to parse a remote target")
	} else {
		assert.Equal("us-west", r1.Location,
			"error parsing location of an 'internal' target from YAML test configuration file")
	}

	assert.Equal(int64(10500000000000), int64(gl.RemoteConfig.PollOrchestratorInterval.Success),
		"error parsing 'poll_orchestrator_interval_success' from YAML test configuration file")
	assert.Equal(int64(60000000000), int64(gl.RemoteConfig.PollOrchestratorInterval.Failure),
		"error parsing 'poll_orchestrator_interval_failure' from YAML test configuration file")
}

func TestDownloadTargetFileFromOrchestrator(t *testing.T) {

	t.Parallel()

	l, err := zap.NewDevelopment()
	if err != nil {
		coreLog.Fatal(err)
	}
	logger := &log.Logger{
		Logger:    l,
		PIDPath:   "",
		RemovePID: util.RemovePID,
	}

	const timeout = defines.HTTPResponseHeaderTimeout
	client := createHTTPClient(timeout, true)
	RESTUrl := ""
	if _, _, err := fetchRemoteListFromOrchestrator(client, RESTUrl, logger); err == nil {
		t.Errorf("Configuration file downloaded without URL of Orchestrator provided")
	}
}
