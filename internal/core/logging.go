package core

import (
	"log"
	"os"

	"gopkg.in/natefinch/lumberjack.v2"
)

var logFileWriter *lumberjack.Logger

func InitFileLogging(path string) error {
	logFileWriter = &lumberjack.Logger{
		Filename:   path,
		MaxSize:    20,
		MaxBackups: 3,
		MaxAge:     30,
		Compress:   true,
	}
	log.SetOutput(logFileWriter)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	return nil
}

func CloseFileLogging() {
	if logFileWriter != nil {
		_ = logFileWriter.Close()
	}
	log.SetOutput(os.Stdout)
}
