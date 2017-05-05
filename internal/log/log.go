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

	"github.com/pkg/errors"
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
func CreateLogger(c *zap.Config, pidPath string, removePIDfunc removePIDfunc) (*Logger, error) {

	l, err := c.Build()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create logger")
	}
	pl := Logger{
		Logger:    l,
		PIDPath:   pidPath,
		RemovePID: removePIDfunc,
	}

	return &pl, nil
}

// ResetLogFiles keeps the last 'LogFileSizeKeepKB' KB of the log file if the size of the log file
// has exceeded 'LogFileSizeMaxMB' MB within the last 'PollOrchestratorIntervalSuccess' hours.
func ResetLogFiles(paths []string, fileSizeMaxMB int, fileSizeKeepKB int, logger *Logger) {

	var fileSize int

	for _, path := range paths {
		switch path {
		case "stdout":
			fallthrough
		case "stderr":
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			logger.Error("failed to open existing log file",
				zap.String("file", path),
				zap.Error(err))
			continue
		}

		// Get the file size
		stat, err := file.Stat()
		if err != nil {
			logger.Error("failed to read the FileInfo structure of the log file",
				zap.String("file", path),
				zap.Error(err))
			goto close
		}

		fileSize = int(stat.Size())
		if fileSize > fileSizeMaxMB*1024*1024 {
			logger.Debug("Size of log file is larger than maximum allowed. Resetting.",
				zap.String("file", path),
				zap.Int("current_size_MB", fileSize),
				zap.Int("maximum_allowed_size_MB", fileSizeMaxMB))

			buf := make([]byte, fileSizeKeepKB*1024)
			start := stat.Size() - int64(fileSizeKeepKB*1024)
			if _, err = file.ReadAt(buf, start); err != nil {
				logger.Error("failed to read existing log file",
					zap.String("file", path),
					zap.Error(err))
			} else if err = ioutil.WriteFile(path, buf, 0644); err != nil {
				logger.Error("failed to reset log file",
					zap.String("file", path),
					zap.Error(err))
			}
		}

		// Avoid possible leaks because of using `defer`
	close:
		file.Close()

	}
}
