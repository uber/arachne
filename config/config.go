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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/uber/arachne/defines"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/internal/network"
	"github.com/uber/arachne/internal/tcp"
	"github.com/uber/arachne/metrics"

	"github.com/google/gopacket/layers"
	cli "github.com/jawher/mow.cli"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/validator.v2"
	"gopkg.in/yaml.v2"
)

const defaultConfigFile = "/usr/local/etc/arachne/arachne.yaml"

// BasicConfig holds the basic parameter configurations for the application.
type BasicConfig struct {
	Logging log.Config           `yaml:"logging"`
	Arachne ArachneConfiguration `yaml:"arachne"`
}

// ArachneConfiguration contains specific configuration to Arachne.
type ArachneConfiguration struct {
	PIDPath                string             `yaml:"pidPath"`
	Orchestrator           OrchestratorConfig `yaml:"orchestrator"`
	StandaloneTargetConfig string             `yaml:"standaloneTargetConfig"`
}

// OrchestratorConfig contains configuration for the Arachne Orchestrator.
type OrchestratorConfig struct {
	Enabled     bool   `yaml:"enabled"`
	AddrPort    string `yaml:"addrport"`
	RESTVersion string `yaml:"restVersion"`
}

// Extended holds the parameter configurations implemented by outside callers.
type Extended struct {
	Metrics metrics.Opt
}

// RemoteStore holds all Remotes.
type RemoteStore map[string]Remote

// Remote holds the info for every target to be echoed.
type Remote struct {
	IP       net.IP
	AF       string
	Hostname string
	Location string
	External bool
}

type target struct {
	HostName string `json:"host_name"`
	IP       string `json:"ip"`
	Location string
}

// RemoteFileConfig needed for the JSON decoder to know which fields to expect and parse.
type RemoteFileConfig struct {
	Local struct {
		Location                        string         `json:"location"`
		HostName                        string         `json:"host_name"`
		SrcAddress                      string         `json:"src_address"`
		InterfaceName                   string         `json:"interface_name"`
		TargetTCPPort                   layers.TCPPort `json:"target_tcp_port"`
		Timeout                         string         `json:"timeout"`
		BaseSrcTCPPort                  layers.TCPPort `json:"base_src_tcp_port"`
		NumSrcTCPPorts                  uint16         `json:"num_src_tcp_ports"`
		BatchInterval                   string         `json:"batch_interval"`
		QoSEnabled                      string         `json:"qos"`
		ResolveDNS                      string         `json:"resolve_dns"`
		DNSServersAlt                   string         `json:"dns_servers_alternate"`
		PollOrchestratorIntervalSuccess string         `json:"poll_orchestrator_interval_success"`
		PollOrchestratorIntervalFailure string         `json:"poll_orchestrator_interval_failure"`
	} `json:"local"`
	Internal []target `json:"internal"`
	External []target `json:"external"`
}

// AppConfig holds the info parsed from the local YAML config file.
type AppConfig struct {
	Logging                *zap.Config
	Verbose                bool
	PIDPath                string
	Orchestrator           OrchestratorConfig
	StandaloneTargetConfig string
	Metrics                metrics.Config
}

// CLIConfig holds the info parsed from CLI.
type CLIConfig struct {
	ConfigFile       *string
	Foreground       *bool
	ReceiverOnlyMode *bool
	SenderOnlyMode   *bool
}

// RemoteConfig holds the info parsed from the JSON config file.
type RemoteConfig struct {
	Location                 string
	HostName                 string
	SrcAddress               net.IP
	SrcTCPPortRange          tcp.PortRange
	InterfaceName            string
	TargetTCPPort            layers.TCPPort
	Timeout                  time.Duration
	BatchInterval            time.Duration
	QoSEnabled               bool
	ResolveDNS               bool
	DNSServersAlt            []net.IP
	PollOrchestratorInterval pollInterval
}

// pollInterval holds the polling interval info.
type pollInterval struct {
	Success time.Duration
	Failure time.Duration
}

// Global holds the global application info.
type Global struct {
	App          *AppConfig
	CLI          *CLIConfig
	RemoteConfig *RemoteConfig
	Remotes      RemoteStore
}

func localFileReadable(path string) error {
	if _, err := ioutil.ReadFile(path); err != nil {
		return err
	}
	return nil
}

// ParseCliArgs provides the usage and help menu, and parses the actual arguments.
func ParseCliArgs(logger *log.Logger, service string, version string) *CLIConfig {
	args := new(CLIConfig)

	app := cli.App(service, "Utility to echo the DC and Cloud Infrastructure")

	app.Version("v version", "Arachne "+version)
	app.Spec = "[--foreground] [-c=<config_file>] [--receiver_only] [--sender_only]"

	args.Foreground = app.BoolOpt("foreground", false, "Force foreground mode")
	args.ConfigFile = app.StringOpt("c config_file", defaultConfigFile,
		fmt.Sprintf("Agent's primary yaml configuration file (by default: %s)", defaultConfigFile))
	args.ReceiverOnlyMode = app.BoolOpt("receiver_only", false, "Force TCP receiver-only mode")
	args.SenderOnlyMode = app.BoolOpt("sender_only", false, "Force TCP sender-only mode")

	app.Action = func() {
		logger.Debug("Command line arguments parsed")
	}

	app.Run(os.Args)
	return args
}

// Get fetches the configuration file from local path.
func Get(cc *CLIConfig, ec *Extended, logger *log.Logger) (*AppConfig, error) {

	data, err := ioutil.ReadFile(*cc.ConfigFile)
	if err != nil {
		return nil, err
	}

	b, err := unmarshalBasicConfig(data, *cc.ConfigFile)
	if err != nil {
		return nil, err
	}

	mc, err := ec.Metrics.UnmarshalConfig(data, *cc.ConfigFile, logger.Logger)
	if err != nil {
		return nil, err
	}

	output := []string{"stderr"}
	if b.Logging.StdOut || *cc.Foreground {
		output = []string{"stdout"}
	}
	if b.Logging.LogSink != "" {
		logger.Info("Log file path provided", zap.String("path", b.Logging.LogSink))
		output = append(output, b.Logging.LogSink)
	}

	osHostname, _ := GetHostname(logger)
	initialFields := map[string]interface{}{
		"service_name": defines.ArachneService,
		"hostname":     osHostname,
		"PID":          os.Getpid(),
	}

	var level zapcore.Level
	if err := level.Set(b.Logging.Level); err != nil {
		logger.Error("Log level provided", zap.Error(err))
	}

	zc := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		DisableCaller:    true,
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		Encoding:         "json",
		ErrorOutputPaths: []string{"stdout"},
		OutputPaths:      output,
		InitialFields:    initialFields,
	}

	cfg := AppConfig{
		Logging:                &zc,
		PIDPath:                b.Arachne.PIDPath,
		Orchestrator:           b.Arachne.Orchestrator,
		StandaloneTargetConfig: b.Arachne.StandaloneTargetConfig,
		Metrics:                mc,
	}

	if !cfg.Orchestrator.Enabled && cfg.StandaloneTargetConfig == "" {
		return nil, errors.New("the standalone-mode target configuration file has not been specified")
	}

	return &cfg, nil
}

// unmarshalBasicConfig fetches the configuration file from local path.
func unmarshalBasicConfig(data []byte, fname string) (*BasicConfig, error) {

	cfg := new(BasicConfig)
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, errors.Wrapf(err, "error unmarshaling the configuration file %s", fname)
	}
	// Validate on the merged config at the end
	if err := validator.Validate(cfg); err != nil {
		return nil, errors.Wrapf(err, "invalid info in configuration file %s", fname)
	}

	return cfg, nil
}

// FetchRemoteList fetches the configuration file from local path or, remotely, from Arachne Orchestrator.
func FetchRemoteList(
	gl *Global,
	maxNumRemoteTargets int,
	maxNumSrcTCPPorts uint16,
	minBatchInterval time.Duration,
	HTTPResponseHeaderTimeout time.Duration,
	orchestratorRESTConf string,
	kill chan struct{},
	logger *log.Logger,
) error {

	gl.RemoteConfig = new(RemoteConfig)
	// Map of all remote targets found in JSON configuration file
	remotes := make(RemoteStore, maxNumRemoteTargets)

	// Standalone (non-Orchestrator) mode
	if !gl.App.Orchestrator.Enabled {
		logger.Debug("Orchestrator mode disabled, using static target config file.",
			zap.String("path", gl.App.StandaloneTargetConfig))

		if err := localFileReadable(gl.App.StandaloneTargetConfig); err != nil {
			logger.Fatal("unable to retrieve local target configuration file",
				zap.String("file", gl.App.StandaloneTargetConfig),
				zap.Error(err))
		}
		logger.Info("Configuration file", zap.String("file", gl.App.StandaloneTargetConfig))

		raw, err := ioutil.ReadFile(gl.App.StandaloneTargetConfig)
		if err != nil {
			return errors.Wrap(err, "file error")
		}
		if err := readRemoteList(raw, gl.RemoteConfig, remotes, maxNumSrcTCPPorts, minBatchInterval,
			logger); err != nil {
			logger.Fatal("error parsing default target list file",
				zap.String("file", gl.App.StandaloneTargetConfig),
				zap.Error(err))
		}
		gl.Remotes = remotes
		return nil
	}

	// Orchestrator mode
	logger.Info("Orchestrator mode enabled")
	// Initial value before JSON file has been parsed
	gl.RemoteConfig.PollOrchestratorInterval = pollInterval{
		Success: 2 * time.Hour,
		Failure: 2 * time.Minute,
	}
	err := refreshRemoteList(gl, remotes, maxNumSrcTCPPorts, minBatchInterval, HTTPResponseHeaderTimeout,
		orchestratorRESTConf, kill, logger)
	return err
}

// createHTTPClient returns an HTTP client to connect to remote server.
func createHTTPClient(timeout time.Duration, disableKeepAlives bool) *http.Client {
	client := &http.Client{
		Transport: &http.Transport{
			ResponseHeaderTimeout: timeout,
			Dial: (&net.Dialer{
				Timeout: timeout,
			}).Dial,
			DisableKeepAlives: disableKeepAlives,
		},
	}

	return client
}

// GetHostname returns the hostname.
func GetHostname(logger *log.Logger) (string, error) {
	host, err := os.Hostname()
	if err != nil {
		logger.Warn("Failed to extract hostname from OS", zap.Error(err))
		return "unknown", err
	}
	return host, nil
}

// refreshRemoteList checks with Arachne Orchestrator if new a config file should be fetched.
func refreshRemoteList(
	gl *Global,
	remotes RemoteStore,
	maxNumSrcTCPPorts uint16,
	minBatchInterval time.Duration,
	HTTPResponseHeaderTimeout time.Duration,
	orchestratorRESTConf string,
	kill chan struct{},
	logger *log.Logger,
) error {

	client := createHTTPClient(HTTPResponseHeaderTimeout, true)
	retryTime := gl.RemoteConfig.PollOrchestratorInterval.Failure

	for {
		hostname, _ := GetHostname(logger)
		RESTReq := fmt.Sprintf("http://%s/%s/%s?hostname=%s",
			gl.App.Orchestrator.AddrPort,
			gl.App.Orchestrator.RESTVersion,
			orchestratorRESTConf,
			hostname)
		logger.Debug("Sending HTTP request to Orchestrator", zap.String("request", RESTReq))
		respCode, raw, err := fetchRemoteListFromOrchestrator(client, RESTReq, logger)
		if err == nil {
			switch respCode {
			case http.StatusOK:
				logger.Info("Target list downloaded successfully from Orchestrator",
					zap.String("addrport", gl.App.Orchestrator.AddrPort))
				err = readRemoteList(raw, gl.RemoteConfig, remotes, maxNumSrcTCPPorts,
					minBatchInterval, logger)
				if err != nil {
					logger.Error("error parsing downloaded configuration file",
						zap.Error(err))
					goto contError
				}
				gl.Remotes = remotes
				logger.Info("Will poll Orchestrator again later",
					zap.String("retry_time",
						gl.RemoteConfig.PollOrchestratorInterval.Success.String()))
				return nil

			case http.StatusNotFound:
				retryTime = gl.RemoteConfig.PollOrchestratorInterval.Success
				goto stayIdle
			}
		}
		logger.Info("Failed to download configuration file", zap.Error(err))

	contError:
		if len(gl.Remotes) != 0 {
			logger.Debug("last successfully fetched target list will be re-used")
			return nil

		}
	stayIdle:
		// Do not proceed until we have attempted to download the config file at least once.
		logger.Info("Retrying configuration download", zap.String("retry_time", retryTime.String()))
		confRetry := time.NewTicker(retryTime)
		defer confRetry.Stop()

		select {
		case <-confRetry.C:
			continue
		case <-kill:
			logger.Debug("Requested to exit while trying to fetch configuration file.")
			return errors.New("received SIG")
		}
	}

}

func fetchRemoteListFromOrchestrator(
	client *http.Client,
	url string,
	logger *log.Logger,
) (int, []byte, error) {

	var bResp []byte

	// Build the request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		logger.Warn("NewRequest", zap.Error(err))
		return 0, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Warn("HTTP fetch failure", zap.Error(err))
		return 0, nil, err
	}
	defer resp.Body.Close()

	logger.Logger = logger.With(zap.String("status_text", http.StatusText(resp.StatusCode)),
		zap.Int("status_code", resp.StatusCode))

	switch resp.StatusCode {
	case http.StatusOK:
		logger.Debug("HTTP response status code from Orchestrator")
		bResp, err = ioutil.ReadAll(resp.Body)
	case http.StatusNotFound:
		err = errors.New("HTTP response from Orchestrator: 'Idle mode'")
	case http.StatusBadRequest:
		err = errors.New("HTTP response from Orchestrator: 'Please specify hostname or DC!'")
	case http.StatusInternalServerError:
		logger.Warn("HTTP response from Orchestrator: Error opening requested configuration file")
	default:
		err = errors.New("unhandled HTTP response from Orchestrator")
	}

	return resp.StatusCode, bResp, err
}

func isTrue(s string) bool {
	l := strings.ToLower(s)
	return l == "enabled" || l == "true"
}

// readRemoteList decodes the Arachne JSON config file that includes information
// about all the hosts to be tested and validates all IP addresses.
func readRemoteList(
	raw []byte,
	glRC *RemoteConfig,
	remotes RemoteStore,
	maxNumSrcTCPPorts uint16,
	minBatchInterval time.Duration,
	logger *log.Logger,
) error {
	c := new(RemoteFileConfig)

	if err := json.Unmarshal(raw, c); err != nil {
		return errors.Wrap(err, "configuration file parse error")
	}

	// Populate global variables
	glRC.Location = strings.ToLower(c.Local.Location)
	if glRC.Location == "" {
		logger.Warn("Location not provided in config file")
	}

	glRC.HostName = strings.ToLower(c.Local.HostName)
	if glRC.HostName == "" {
		logger.Debug("Hostname not provided in config file")
		glRC.HostName, _ = GetHostname(logger)
	} else {
		logger.Info("Remotely assigned hostname for metrics uploading",
			zap.String("metrics_hostname", glRC.HostName))
	}

	glRC.InterfaceName = strings.ToLower(c.Local.InterfaceName)
	switch {
	case runtime.GOOS == "linux" && strings.Contains(glRC.InterfaceName, "en"),
		runtime.GOOS == "darwin" && strings.Contains(glRC.InterfaceName, "eth"):
		logger.Warn("Specified interface may not be applicable to actual OS",
			zap.String("interface", glRC.InterfaceName),
			zap.String("OS", runtime.GOOS))
	}

	srcIP, err := network.GetSourceAddr("ip4", strings.ToLower(c.Local.SrcAddress),
		glRC.HostName, glRC.InterfaceName, logger)
	if err != nil {
		srcIP, err = network.GetSourceAddr("ip6", strings.ToLower(c.Local.SrcAddress),
			glRC.HostName, glRC.InterfaceName, logger)
		if err != nil {
			return errors.Wrap(err, "could not retrieve an IPv4 or IPv6 source address")
		}
	}
	glRC.SrcAddress = *srcIP
	logger.Debug("Arachne agent's source IP address", zap.Any("address", glRC.SrcAddress))

	glRC.TargetTCPPort = c.Local.TargetTCPPort
	if glRC.Timeout, err = time.ParseDuration(c.Local.Timeout); err != nil {
		return errors.Wrap(err, "failed to parse the timeout")
	}
	glRC.SrcTCPPortRange[0] = c.Local.BaseSrcTCPPort
	if c.Local.NumSrcTCPPorts > maxNumSrcTCPPorts {
		return errors.Errorf("not more than %d ephemeral source TCP ports may be used",
			maxNumSrcTCPPorts)
	}
	if c.Local.NumSrcTCPPorts == 0 {
		return errors.New("cannot specify zero source TCP ports")
	}
	glRC.SrcTCPPortRange[1] = c.Local.BaseSrcTCPPort + layers.TCPPort(c.Local.NumSrcTCPPorts) - 1
	if glRC.SrcTCPPortRange.Contains(glRC.TargetTCPPort) {
		return errors.Errorf("the listen TCP port cannot reside in the range of the ephemeral TCP "+
			"source ports [%d-%d]", glRC.SrcTCPPortRange[0], glRC.SrcTCPPortRange[1])
	}
	if glRC.BatchInterval, err = time.ParseDuration(c.Local.BatchInterval); err != nil {
		return errors.Wrap(err, "failed to parse the batch interval")
	}
	if glRC.BatchInterval < minBatchInterval {
		return errors.Errorf("the batch cycle interval cannot be shorter than %v", minBatchInterval)
	}
	if glRC.PollOrchestratorInterval.Success, err =
		time.ParseDuration(c.Local.PollOrchestratorIntervalSuccess); err != nil {
		return errors.Wrap(err, "failed to parse the Orchestrator poll interval for success")
	}
	if glRC.PollOrchestratorInterval.Failure, err =
		time.ParseDuration(c.Local.PollOrchestratorIntervalFailure); err != nil {
		return errors.Wrap(err, "failed to parse the Orchestrator poll interval for failure")
	}

	glRC.QoSEnabled = isTrue(c.Local.QoSEnabled)
	glRC.ResolveDNS = isTrue(c.Local.ResolveDNS)

	DNSInput := strings.Split(c.Local.DNSServersAlt, ",")
	for _, server := range DNSInput {
		currDNSIP := net.ParseIP(strings.TrimSpace(server))
		if currDNSIP == nil {
			return errors.Errorf("configuration file parse error: "+
				"invalid IP address for DNS server: %v", currDNSIP)
		}
		glRC.DNSServersAlt = append(glRC.DNSServersAlt, currDNSIP)

	}
	logger.Debug("Alternate DNS servers configured", zap.Any("servers", glRC.DNSServersAlt))

	walkTargets(glRC, c.Internal, false, remotes, logger)
	walkTargets(glRC, c.External, true, remotes, logger)

	for key, r := range remotes {
		logger.Debug("Remote", zap.String("key", key), zap.Any("object", r))
	}

	return nil
}

// Validate and create map of ipv4 and ipv6 addresses with string as their key.
func walkTargets(grc *RemoteConfig, ts []target, ext bool, remotes RemoteStore, logger *log.Logger) {

	for _, t := range ts {
		if grc.ResolveDNS && t.HostName != "" {
			addrs, err := net.LookupHost(t.HostName)
			if err != nil {
				logger.Error("failed to DNS resolve hostname", zap.Error(err))
				continue
			}
			t.IP = addrs[0]
		}

		// Validate address string
		currIP := net.ParseIP(t.IP)
		if currIP == nil {
			logger.Error("configuration file parse error",
				zap.String("err", "invalid IP address for host %s"),
				zap.String("hostname", t.HostName))
		}
		if currIP.Equal(grc.SrcAddress) {
			logger.Debug("Local server's address not added in remote target list",
				zap.String("JSON_source_address", grc.SrcAddress.String()),
				zap.String("target", currIP.String()))
			continue
		}
		remotes[currIP.String()] = Remote{currIP, network.Family(&currIP),
			t.HostName, t.Location, ext}
	}
}

// ResolveDNSTargets resolves the DNS names of the IP addresses of all echo targets and the localhost.
func ResolveDNSTargets(
	remotes RemoteStore,
	grc *RemoteConfig,
	DNSRefresh *time.Ticker,
	wg *sync.WaitGroup,
	kill chan struct{},
	logger *log.Logger,
) {
	go func() {
		// Resolve
		if localHost, err := network.ResolveIP(grc.SrcAddress.String(),
			grc.DNSServersAlt, logger); err == nil {
			if grc.HostName == "" {
				grc.HostName = localHost
			} else if grc.HostName != strings.ToLower(localHost) {
				logger.Warn("DNS-resolved local hostname is different from "+
					"configured local hostname",
					zap.String("DNS-resolved_hostname", localHost),
					zap.String("configured_hostname", grc.HostName))
			}
		}

		for {
			for addressKey := range remotes {
				hostname := remotes[addressKey].Hostname
				// Do not update hostname for external targets
				if !remotes[addressKey].External {
					//hostname = addressKey
					if grc.ResolveDNS {
						if h, err := network.ResolveIP(addressKey, grc.DNSServersAlt,
							logger); err == nil {
							hostname = h
							logger.Debug("DNS resolution",
								zap.String("address", addressKey),
								zap.String("hostname", hostname))

						}
					}
				}

				currIP := net.ParseIP(addressKey)
				remotes[addressKey] = Remote{currIP, network.Family(&currIP), hostname,
					remotes[addressKey].Location, remotes[addressKey].External,
				}
			}
			wg.Done()

			select {
			case <-DNSRefresh.C:
				continue
			case <-kill:
				DNSRefresh.Stop()
				logger.Debug("ResolveDNSTargets goroutine returning")
				return
			}
		}
	}()
}
