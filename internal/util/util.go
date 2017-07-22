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

package util

import (
	"bufio"
	"io/ioutil"
	"os"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"time"

	"github.com/uber/arachne/internal/ip"
	"github.com/uber/arachne/internal/log"
	"github.com/uber/arachne/metrics"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

const bannerText = `
____________________________________________________________/\\\______________________________________
 ___________________________________________________________\/\\\______________________________________
  ___________________________________________________________\/\\\______________________________________
   __/\\\\\\\\\_____/\\/\\\\\\\___/\\\\\\\\\________/\\\\\\\\_\/\\\__________/\\/\\\\\\_______/\\\\\\\\__
    _\////////\\\___\/\\\/////\\\_\////////\\\_____/\\\//////__\/\\\\\\\\\\__\/\\\////\\\____/\\\/////\\\_
     ___/\\\\\\\\\\__\/\\\___\///____/\\\\\\\\\\___/\\\_________\/\\\/////\\\_\/\\\__\//\\\__/\\\\\\\\\\\__
      __/\\\/////\\\__\/\\\__________/\\\/////\\\__\//\\\________\/\\\___\/\\\_\/\\\___\/\\\_\//\\///////___
       _\//\\\\\\\\/\\_\/\\\_________\//\\\\\\\\/\\__\///\\\\\\\\_\/\\\___\/\\\_\/\\\___\/\\\__\//\\\\\\\\\\_
        __\////////\//__\///___________\////////\//_____\////////__\///____\///__\///____\///____\//////////__

`

// KillChannels includes all channels to tell goroutines to terminate.
type KillChannels struct {
	Receiver   chan struct{}
	Echo       chan struct{}
	Collector  chan struct{}
	DNSRefresh chan struct{}
}

// PrintBanner prints the binary's banner.
func PrintBanner() {

	color.Set(color.FgHiYellow, color.Bold)
	defer color.Unset()

	f := bufio.NewWriter(os.Stdout)
	defer f.Flush()
	f.Write([]byte(bannerText))
}

// UnixSignals handles the UNIX signals received.
func UnixSignals(sigC chan struct{}, logger *log.Logger) {
	// Set up channel on which to send signal notifications.
	// We must use a buffered channel or risk missing the signal
	// if we're not ready to receive when the signal is sent.
	sigc := make(chan os.Signal, 1)

	signal.Notify(sigc, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGTERM,
		syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGHUP, os.Interrupt)

	go func() {
		sigType := <-sigc
		switch sigType {
		//TODO Handle following cases
		case os.Interrupt:
		//handle SIGINT
		case syscall.SIGHUP:
			logger.Info("got Hangup/SIGHUP - portable number 1")
		case syscall.SIGINT:
			logger.Info("got Terminal interrupt signal/SIGINT - portable number 2")
		case syscall.SIGQUIT:
			logger.Fatal("got Terminal quit signal/SIGQUIT - portable number 3 - will core dump")
		case syscall.SIGABRT:
			logger.Fatal("got Process abort signal/SIGABRT - portable number 6 - will core dump")
		case syscall.SIGKILL:
			logger.Info("got Kill signal/SIGKILL - portable number 9")
		case syscall.SIGALRM:
			logger.Fatal("got Alarm clock signal/SIGALRM - portable number 14")
		case syscall.SIGTERM:
			logger.Info("got Termination signal/SIGTERM - portable number 15")
		case syscall.SIGUSR1:
			logger.Info("got User-defined signal 1/SIGUSR1")
		case syscall.SIGUSR2:
			logger.Info("got User-defined signal 2/SIGUSR2")
		default:
			logger.Fatal("unhandled Unix signal", zap.Any("sig_type", sigType))

		}
		sigC <- struct{}{}
		return
	}()
}

// CheckPID checks if another Arachne process is already running.
func CheckPID(fname string, logger *log.Logger) error {

	if _, err := os.Stat(fname); os.IsNotExist(err) {
		return savePID(fname, os.Getpid(), logger)

	}

	content, err := ioutil.ReadFile(fname)
	if err != nil {
		logger.Error("unable to read PID file", zap.String("file", fname), zap.Error(err))
		return err
	}
	readPID, err := strconv.Atoi(string(content))
	if err != nil {
		logger.Error("invalid content inside PID file", zap.String("file", fname), zap.Error(err))
		return savePID(fname, os.Getpid(), logger)

	}

	// Sending the signal 0 to a given PID just checks if any process with the given PID is running
	// and you have the permission to send a signal to it.
	if err = syscall.Kill(readPID, 0); err == nil {
		logger.Error("Arachne already running and different from self PID",
			zap.Int("other_PID", readPID),
			zap.Int("self_PID", os.Getpid()))
		return errors.New("Arachne already running and different from self PID")
	}
	return savePID(fname, os.Getpid(), logger)
}

func savePID(fname string, pid int, logger *log.Logger) error {

	if err := os.MkdirAll(path.Dir(fname), 0777); err != nil {
		logger.Error("failed to create PID directory", zap.String("path", path.Dir(fname)), zap.Error(err))
		return err
	}
	if err := ioutil.WriteFile(fname, []byte(strconv.Itoa(pid)), 0644); err != nil {
		logger.Error("failed to create PID file", zap.String("file", fname), zap.Error(err))
		return err
	}

	logger.Debug("Created PID file", zap.String("name", fname), zap.Int("PID", pid))
	return nil
}

// RemovePID removes the PID file.
func RemovePID(fname string, logger *log.Logger) {
	if err := os.Remove(fname); err != nil {
		logger.Error("failed to remove PID file", zap.String("name", fname), zap.Error(err))
	} else {
		logger.Debug("PID file removed", zap.String("name", fname))
	}
}

// CleanUpRefresh removes state of past refresh.
func CleanUpRefresh(killC *KillChannels, receiverOnlyMode bool, senderOnlyMode bool, resolveDNS bool) {
	// Close all the channels
	if !receiverOnlyMode {
		close(killC.Echo)
	}
	if !senderOnlyMode {
		close(killC.Receiver)
		time.Sleep(500 * time.Millisecond)
	}
	if !receiverOnlyMode && !senderOnlyMode {
		close(killC.Collector)
		time.Sleep(50 * time.Millisecond)
	}
	if resolveDNS {
		close(killC.DNSRefresh)
	}
}

// CleanUpAll conducts a clean exit.
func CleanUpAll(
	killC *KillChannels,
	receiverOnlyMode bool,
	senderOnlyMode bool,
	resolveDNS bool,
	conn *ip.Conn,
	PIDPath string,
	sr metrics.Reporter,
	logger *log.Logger,
) {

	CleanUpRefresh(killC, receiverOnlyMode, senderOnlyMode, resolveDNS)

	conn.Close(logger)

	sr.Close()

	RemovePID(PIDPath, logger)
}
