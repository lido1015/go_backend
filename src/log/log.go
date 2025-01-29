package log

import (
	"fmt"
	"log"
	"os"
)

var (
	logErr  *log.Logger
	logInfo *log.Logger
)

func init() {
	logErr = log.New(os.Stdout, "ERROR ", log.LstdFlags|log.Lmsgprefix)
	logInfo = log.New(os.Stdout, "INFO ", log.LstdFlags|log.Lmsgprefix)
}

// Err ...
func Err(message, module string) {
	logErr.Println(fmt.Sprintf("%s %s", module, message))
}

// Info ...
func Info(message, module string) {
	logInfo.Println(fmt.Sprintf("%s %s", module, message))
}
