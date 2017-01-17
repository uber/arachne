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

package log

import (
	"io/ioutil"
	"os"

	"github.com/uber-go/zap"
)

type removePIDfunc func(fname string, logger zap.Logger)

// PIDRemoverLogger embeds a zap.Logger instance, and extends its Fatal
// and Panic methods to first remove the pid file.
type PIDRemoverLogger struct {
	zap.Logger
	PIDPath   string
	RemovePID removePIDfunc
}

// Config contains configuration for logging.
type Config struct {
	Level   zap.Level `yaml:"level"`
	StdOut  bool      `yaml:"stdout"`
	LogSink string    `yaml:"logSink"`
}

// Fatal extends the zap Fatal to also remove the PID file
func (log PIDRemoverLogger) Fatal(msg string, fields ...zap.Field) {
	log.RemovePID(log.PIDPath, log.Logger)
	log.Logger.Fatal(msg, fields...)
}

// Panic extends the zap Panic to also remove the PID file
func (log PIDRemoverLogger) Panic(msg string, fields ...zap.Field) {
	log.RemovePID(log.PIDPath, log.Logger)
	log.Logger.Fatal(msg, fields...)
}

// CreateLogger creates a zap logger
func CreateLogger(
	c *Config,
	service string,
	hostname string,
	pidPath string,
	removePIDfunc removePIDfunc,
	foreground bool,
	bootstrapLogger zap.Logger,
) (zap.Logger, error) {

	output := zap.Output(os.Stdout)
	if c.LogSink != "" {
		sink, err := os.OpenFile(c.LogSink, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return nil, err
		}
		bootstrapLogger.Info("Log file path provided", zap.String("path", c.LogSink))
		if c.StdOut || foreground {
			output = zap.Output(zap.MultiWriteSyncer(os.Stdout, sink))
		} else {
			output = zap.Output(sink)
		}
	}

	fields := zap.Fields(
		zap.String("service_name", service),
		zap.String("hostname", hostname),
		zap.Int("PID", os.Getpid()),
	)

	logger := PIDRemoverLogger{
		Logger: zap.New(
			zap.NewJSONEncoder(),
			c.Level,
			fields,
			output),
		PIDPath:   pidPath,
		RemovePID: removePIDfunc,
	}

	return logger, nil
}

// ResetLogFile keeps the last 'LogFileSizeKeepKB' KB of the log file if the size of the log file
// has exceeded 'LogFileSizeMaxMB' MB within the last 'PollOrchestratorIntervalSuccess' hours
func ResetLogFile(logFilePath string, fileSizeMaxMB int, fileSizeKeepKB int, logger zap.Logger) error {
	file, err := os.Open(logFilePath)
	if err != nil {
		logger.Error("failed to open existing log file", zap.String("file", logFilePath), zap.Error(err))
		return err
	}
	defer file.Close()

	// Get the file size
	stat, err := file.Stat()
	if err != nil {
		logger.Error("failed to read the FileInfo structure of the log file",
			zap.String("file", logFilePath),
			zap.Error(err))
		return err
	}
	fileSize := int(stat.Size())

	if fileSize > fileSizeMaxMB*1024*1024 {
		logger.Debug("Size of log file is larger than maximum allowed. Resetting.",
			zap.String("file", logFilePath),
			zap.Int("current_size_MB", fileSize),
			zap.Int("maximum_allowed_size_MB", fileSizeMaxMB))

		buf := make([]byte, fileSizeKeepKB*1024)
		start := stat.Size() - int64(fileSizeKeepKB*1024)
		if _, err = file.ReadAt(buf, start); err != nil {
			logger.Error("failed to read existing log file",
				zap.String("file", logFilePath),
				zap.Error(err))
			return err
		}
		if err = ioutil.WriteFile(logFilePath, buf, 0644); err != nil {
			logger.Error("failed to reset log file", zap.String("file", logFilePath), zap.Error(err))
			return err
		}
	}

	return nil
}
