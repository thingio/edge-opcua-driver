package main

import (
	"github.com/thingio/edge-device-driver/pkg/startup"
	"github.com/thingio/edge-opcua-driver/driver"
)

func main() {
	startup.Startup(driver.Opcua, driver.NewOpcuaTwin)
}
