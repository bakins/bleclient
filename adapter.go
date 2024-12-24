// Some documentation for the BlueZ D-Bus interface:
// https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/doc

package bleclient

import (
	"errors"
	"fmt"

	"github.com/godbus/dbus/v5"
)

const defaultAdapter = "hci0"

type Adapter struct {
	id             string
	scanCancelChan chan struct{}
	bus            *dbus.Conn
	bluez          dbus.BusObject // object at /
	adapter        dbus.BusObject // object at /org/bluez/hciX
	address        string
	connectHandler func(device Device, connected bool)
}

type adapterOptions struct {
	dbusAddress string
	device      string
}

type AdapterOption interface {
	apply(*adapterOptions)
}

type adapterOptionFunc func(*adapterOptions)

func (f adapterOptionFunc) apply(o *adapterOptions) {
	f(o)
}

func WithDevice(device string) AdapterOption {
	return adapterOptionFunc(func(o *adapterOptions) {
		o.device = device
	})
}

func WithDbusAddress(address string) AdapterOption {
	return adapterOptionFunc(func(o *adapterOptions) {
		o.dbusAddress = address
	})
}

func NewAdapter(options ...AdapterOption) (*Adapter, error) {
	opts := adapterOptions{
		device: defaultAdapter,
	}

	for _, o := range options {
		o.apply(&opts)
	}

	var err error
	var bus *dbus.Conn

	if opts.dbusAddress == "" {
		bus, err = dbus.ConnectSystemBus()
	} else {
		bus, err = dbus.Connect(opts.dbusAddress, dbus.WithAuth(dbus.AuthAnonymous()))
	}

	if err != nil {
		return nil, err
	}

	a := &Adapter{
		id: opts.device,
		connectHandler: func(device Device, connected bool) {
		},
	}

	a.bus = bus
	a.bluez = a.bus.Object("org.bluez", dbus.ObjectPath("/"))
	a.adapter = a.bus.Object("org.bluez", dbus.ObjectPath("/org/bluez/"+a.id))
	addr, err := a.adapter.GetProperty("org.bluez.Adapter1.Address")
	if err != nil {
		if err, ok := err.(dbus.Error); ok && err.Name == "org.freedesktop.DBus.Error.UnknownObject" {
			return nil, fmt.Errorf("bluetooth: adapter %s does not exist", a.adapter.Path())
		}
		return nil, fmt.Errorf("could not activate BlueZ adapter: %w", err)
	}

	if err := addr.Store(&a.address); err != nil {
		return nil, err
	}

	return a, nil
}

func (a *Adapter) Close() error {
	return a.bus.Close()
}

func (a *Adapter) Address() (MACAddress, error) {
	if a.address == "" {
		return MACAddress{}, errors.New("adapter not enabled")
	}
	mac, err := ParseMAC(a.address)
	if err != nil {
		return MACAddress{}, err
	}
	return MACAddress{MAC: mac}, nil
}
