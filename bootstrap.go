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

import (
	coreLog "log"
	"os"
	"sync"
	"time"

	"github.com/uber/arachne/collector"
	"github.com/uber/arachne/config"
	d "github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/ip"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/internal/tcp"
	"github.com/uber/arachne/internal/util"

	"go.uber.org/zap"
)

// Run is the entry point for initiating any Arachne service.
func Run(ec *config.Extended, opts ...Option) {
	var (
		gl  config.Global
		err error
	)

	bl, err := zap.NewProduction()
	if err != nil {
		coreLog.Fatal(err)
	}
	bootstrapLogger := &log.Logger{
		Logger:    bl,
		PIDPath:   "",
		RemovePID: util.RemovePID,
	}

	util.PrintBanner()

	gl.CLI = config.ParseCliArgs(bootstrapLogger, d.ArachneService, d.ArachneVersion)
	apply(&gl, opts...)
	gl.App, err = config.Get(gl.CLI, ec, bootstrapLogger)
	if err != nil {
		bootstrapLogger.Error("error reading the configuration file",
			zap.String("file", *gl.CLI.ConfigFile),
			zap.Error(err))
		os.Exit(1)
	}

	logger, err := log.CreateLogger(gl.App.Logging, gl.App.PIDPath, util.RemovePID)
	if err != nil {
		bootstrapLogger.Fatal("unable to initialize Arachne Logger", zap.Error(err))
		os.Exit(1)
	}

	// Channel to be informed if Unix signal has been received.
	sigC := make(chan struct{}, 1)
	util.UnixSignals(sigC, logger)

	// Check if another Arachne process is already running.
	// Pass bootstrapLogger so that the arachne PID file is not removed.
	if err := util.CheckPID(gl.App.PIDPath, bootstrapLogger); err != nil {
		os.Exit(1)
	}

	sr, err := gl.App.Metrics.NewReporter(logger.Logger)
	if err != nil {
		logger.Error("error initializing stats", zap.Error(err))
	}

	// Hold raw socket connection for IPv4 packets
	var connIPv4 *ip.Conn

	logger.Info("Starting up arachne")

	for {
		var (
			err                 error
			currentDSCP         ip.DSCPValue
			dnsWg               sync.WaitGroup
			finishedCycleUpload sync.WaitGroup
		)

		// Channels to tell goroutines to terminate
		killC := new(util.KillChannels)

		// If Orchestrator mode enabled, fetch JSON configuration file, otherwise try
		// to retrieve default local file
		err = config.FetchRemoteList(&gl, d.MaxNumRemoteTargets, d.MaxNumSrcTCPPorts,
			d.MinBatchInterval, d.HTTPResponseHeaderTimeout, d.OrchestratorRESTConf, sigC, logger)
		if err != nil {
			break
		}
		logger.Debug("Global JSON configuration", zap.Any("configuration", gl.RemoteConfig))

		if len(gl.Remotes) == 0 {
			logger.Debug("No targets to be echoed have been specified")
			apply(&gl, ReceiverOnlyMode(true))
		}

		configRefresh := time.NewTicker(gl.RemoteConfig.PollOrchestratorInterval.Success)

		if gl.RemoteConfig.ResolveDNS && !*gl.CLI.ReceiverOnlyMode {
			// Refresh DNS resolutions
			dnsRefresh := time.NewTicker(d.DNSRefreshInterval)
			dnsWg.Add(1)
			killC.DNSRefresh = make(chan struct{})
			config.ResolveDNSTargets(gl.Remotes, gl.RemoteConfig, dnsRefresh, &dnsWg,
				killC.DNSRefresh, logger)
			dnsWg.Wait()
			logger.Debug("Remotes after DNS resolution include",
				zap.Int("count", len(gl.Remotes)),
				zap.Any("remotes", gl.Remotes))
		}

		// Channels for Collector to receive Probes and Responses from.
		sentC := make(chan tcp.Message, d.ChannelOutBufferSize)
		rcvdC := make(chan tcp.Message, d.ChannelInBufferSize)

		// Connection for IPv4 packets
		if connIPv4 == nil {
			connIPv4 = ip.NewConn(
				d.AfInet,
				gl.RemoteConfig.TargetTCPPort,
				gl.RemoteConfig.InterfaceName,
				gl.RemoteConfig.SrcAddress,
				logger)
		}

		// Actual echoing is a percentage of the total configured batch cycle duration.
		realBatchInterval := time.Duration(float32(gl.RemoteConfig.BatchInterval) *
			d.BatchIntervalEchoingPerc)
		uploadBatchInterval := time.Duration(float32(gl.RemoteConfig.BatchInterval) *
			d.BatchIntervalUploadStats)
		batchEndCycle := time.NewTicker(uploadBatchInterval)
		completeCycleUpload := make(chan bool, 1)

		if !*gl.CLI.SenderOnlyMode && !*gl.CLI.ReceiverOnlyMode {
			// Start gathering and reporting results.
			killC.Collector = make(chan struct{})
			collector.Run(&gl, sentC, rcvdC, gl.Remotes, &currentDSCP, sr, completeCycleUpload,
				&finishedCycleUpload, killC.Collector, logger)
		}

		if !*gl.CLI.SenderOnlyMode {
			// Listen for responses or probes from other IPv4 arachne agents.
			killC.Receiver = make(chan struct{})
			err = tcp.Receiver(connIPv4, sentC, rcvdC, killC.Receiver, logger)
			if err != nil {
				logger.Fatal("IPv4 receiver failed to start", zap.Error(err))
			}
			logger.Debug("IPv4 receiver now ready...")
			//TODO IPv6 receiver
		}

		if !*gl.CLI.ReceiverOnlyMode {
			logger.Debug("Echoing...")
			// Start echoing all targets.
			killC.Echo = make(chan struct{})
			tcp.EchoTargets(gl.Remotes, connIPv4, gl.RemoteConfig.TargetTCPPort,
				gl.RemoteConfig.SrcTCPPortRange, gl.RemoteConfig.QoSEnabled, &currentDSCP,
				realBatchInterval, batchEndCycle, sentC, *gl.CLI.SenderOnlyMode,
				completeCycleUpload, &finishedCycleUpload, killC.Echo, logger)
		}

		select {
		case <-configRefresh.C:
			util.CleanUpRefresh(killC, *gl.CLI.ReceiverOnlyMode,
				*gl.CLI.SenderOnlyMode, gl.RemoteConfig.ResolveDNS)
			log.ResetLogFiles(gl.App.Logging.OutputPaths, d.LogFileSizeMaxMB, d.LogFileSizeKeepKB, logger)
			logger.Info("Refreshing target list file, if needed")
			configRefresh.Stop()
		case <-sigC:
			logger.Debug("Received SIG")
			configRefresh.Stop()
			util.CleanUpAll(killC, *gl.CLI.ReceiverOnlyMode, *gl.CLI.SenderOnlyMode,
				gl.RemoteConfig.ResolveDNS, connIPv4, gl.App.PIDPath, sr, logger)
			logger.Info("Exiting")
			os.Exit(0)
		}
	}
}
