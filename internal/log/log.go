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
	"errors"
	"io/ioutil"
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type removePIDfunc func(fname string, logger *Logger)

// Logger embeds a zap.Logger instance, and extends its Fatal
// and Panic methods to first remove the pid file.
type Logger struct {
	*zap.Logger
	PIDPath   string
	RemovePID removePIDfunc
}

// Fatal extends the zap Fatal to also remove the PID file.
func (log *Logger) Fatal(msg string, fields ...zapcore.Field) {
	log.RemovePID(log.PIDPath, log)
	log.Logger.Fatal(msg, fields...)
}

// Panic extends the zap Panic to also remove the PID file.
func (log *Logger) Panic(msg string, fields ...zapcore.Field) {
	log.RemovePID(log.PIDPath, log)
	log.Logger.Panic(msg, fields...)
}

// Config contains configuration for logging.
type Config struct {
	Level   string `yaml:"level"`
	StdOut  bool   `yaml:"stdout"`
	LogSink string `yaml:"logSink"`
}

// CreateLogger creates a zap logger.
func CreateLogger(
	c *Config,
	service string,
	hostname string,
	pidPath string,
	removePIDfunc removePIDfunc,
	foreground bool,
	bootstrapLogger *Logger,
) (*Logger, error) {

	var output []string
	if c.LogSink != "" {
		_, err := os.OpenFile(c.LogSink, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0644)
		if err != nil {
			return nil, err
		}
		bootstrapLogger.Info("Log file path provided", zap.String("path", c.LogSink))
		if c.StdOut || foreground {
			output = append(output, "stdout")
		}
		output = append(output, c.LogSink)

	}

	initialFields := map[string]interface{}{
		"service_name": service,
		"hostname":     hostname,
		"PID":          os.Getpid(),
	}

	var level zapcore.Level
	if err := level.Set(c.Level); err != nil {
		bootstrapLogger.Error("Log level provided", zap.Error(err))
	}

	config := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      false,
		DisableCaller:    true,
		EncoderConfig:    zap.NewProductionEncoderConfig(),
		Encoding:         "json",
		ErrorOutputPaths: []string{"stdout"},
		OutputPaths:      output,
		InitialFields:    initialFields,
	}

	l, err := config.Build()
	if err != nil {
		return nil, errors.New("failed to create logger")
	}
	pl := Logger{
		Logger:    l,
		PIDPath:   pidPath,
		RemovePID: removePIDfunc,
	}

	return &pl, nil
}

// ResetLogFile keeps the last 'LogFileSizeKeepKB' KB of the log file if the size of the log file
// has exceeded 'LogFileSizeMaxMB' MB within the last 'PollOrchestratorIntervalSuccess' hours.
func ResetLogFile(logFilePath string, fileSizeMaxMB int, fileSizeKeepKB int, logger *Logger) error {
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
