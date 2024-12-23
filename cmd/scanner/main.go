package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/bakins/bleclient"
)

func main() {
	var address string
	flag.StringVar(&address, "address", "", "dbus address")

	flag.Parse()

	if err := run(address); err != nil {
		log.Fatal(err)
	}
}

func run(address string) error {
	adapter, err := bleclient.NewAdapter(bleclient.WithDbusAddress(address))
	if err != nil {
		return err
	}

	defer adapter.Close()

	return adapter.Scan(
		context.Background(),
		func(adapter *bleclient.Adapter, device bleclient.ScanResult) {
			fmt.Println("found device:", device.Address.String(), device.RSSI, device.LocalName())
		})
}
