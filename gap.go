package bleclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sync/errgroup"
)

// Address contains a Bluetooth MAC address.
type Address struct {
	MACAddress
}

func (a *Adapter) Scan(ctx context.Context, callback func(*Adapter, ScanResult)) error {
	if a.scanCancelChan != nil {
		return errScanning
	}

	// Channel that will be closed when the scan is stopped.
	// Detecting whether the scan is stopped can be done by doing a non-blocking
	// read from it. If it succeeds, the scan is stopped.
	cancelChan := make(chan struct{})
	a.scanCancelChan = cancelChan

	// This appears to be necessary to receive any BLE discovery results at all.
	defer a.adapter.Call("org.bluez.Adapter1.SetDiscoveryFilter", 0)
	err := a.adapter.CallWithContext(ctx, "org.bluez.Adapter1.SetDiscoveryFilter", 0, map[string]interface{}{
		"Transport": "le",
	}).Err
	if err != nil {
		return err
	}

	signal := make(chan *dbus.Signal)
	a.bus.Signal(signal)
	defer a.bus.RemoveSignal(signal)

	propertiesChangedMatchOptions := []dbus.MatchOption{dbus.WithMatchInterface("org.freedesktop.DBus.Properties")}
	if err := a.bus.AddMatchSignal(propertiesChangedMatchOptions...); err != nil {
		return err
	}
	defer func() {
		_ = a.bus.RemoveMatchSignal(propertiesChangedMatchOptions...)
	}()

	newObjectMatchOptions := []dbus.MatchOption{dbus.WithMatchInterface("org.freedesktop.DBus.ObjectManager")}
	if err := a.bus.AddMatchSignal(newObjectMatchOptions...); err != nil {
		return err
	}
	defer func() {
		_ = a.bus.RemoveMatchSignal(newObjectMatchOptions...)
	}()

	// Go through all connected devices and present the connected devices as
	// scan results. Also save the properties so that the full list of
	// properties is known on a PropertiesChanged signal. We can't present the
	// list of cached devices as scan results as devices may be cached for a
	// long time, long after they have moved out of range.
	var deviceList map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	err = a.bluez.CallWithContext(ctx, "org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&deviceList)
	if err != nil {
		return err
	}
	devices := make(map[dbus.ObjectPath]map[string]dbus.Variant)
	for path, v := range deviceList {
		device, ok := v["org.bluez.Device1"]
		if !ok {
			continue // not a device
		}
		if !strings.HasPrefix(string(path), string(a.adapter.Path())) {
			continue // not part of our adapter
		}
		if device["Connected"].Value().(bool) {
			callback(a, makeScanResult(device))
			select {
			case <-cancelChan:
				return nil
			default:
			}
		}
		devices[path] = device
	}

	// Instruct BlueZ to start discovering.
	err = a.adapter.CallWithContext(ctx, "org.bluez.Adapter1.StartDiscovery", 0).Err
	if err != nil {
		return err
	}

	for {
		// Check whether the scan is stopped. This is necessary to avoid a race
		// condition between the signal channel and the cancelScan channel when
		// the callback calls StopScan() (no new callbacks may be called after
		// StopScan is called).
		select {
		case <-cancelChan:
			return a.adapter.Call("org.bluez.Adapter1.StopDiscovery", 0).Err
		default:
		}

		select {
		case sig := <-signal:
			// This channel receives anything that we watch for, so we'll have
			// to check for signals that are relevant to us.
			switch sig.Name {
			case "org.freedesktop.DBus.ObjectManager.InterfacesAdded":
				objectPath := sig.Body[0].(dbus.ObjectPath)
				interfaces := sig.Body[1].(map[string]map[string]dbus.Variant)
				rawprops, ok := interfaces["org.bluez.Device1"]
				if !ok {
					continue
				}
				devices[objectPath] = rawprops
				callback(a, makeScanResult(rawprops))
			case "org.freedesktop.DBus.Properties.PropertiesChanged":
				interfaceName := sig.Body[0].(string)
				if interfaceName != "org.bluez.Device1" {
					continue
				}
				changes := sig.Body[1].(map[string]dbus.Variant)
				device, ok := devices[sig.Path]
				if !ok {
					// This shouldn't happen, but protect against it just in
					// case.
					continue
				}
				for k, v := range changes {
					device[k] = v
				}
				callback(a, makeScanResult(device))
			}
		case <-cancelChan:
			continue
		}
	}
}

// StopScan stops any in-progress scan. It can be called from within a Scan
// callback to stop the current scan. If no scan is in progress, an error will
// be returned.
func (a *Adapter) StopScan() error {
	if a.scanCancelChan == nil {
		return errNotScanning
	}
	close(a.scanCancelChan)
	a.scanCancelChan = nil
	return nil
}

// makeScanResult creates a ScanResult from a raw DBus device.
func makeScanResult(props map[string]dbus.Variant) ScanResult {
	// Assume the Address property is well-formed.
	addr, _ := ParseMAC(props["Address"].Value().(string))

	// Create a list of UUIDs.
	var serviceUUIDs []UUID
	for _, uuid := range props["UUIDs"].Value().([]string) {
		// Assume the UUID is well-formed.
		parsedUUID, _ := ParseUUID(uuid)
		serviceUUIDs = append(serviceUUIDs, parsedUUID)
	}

	a := Address{MACAddress{MAC: addr}}
	a.SetRandom(props["AddressType"].Value().(string) == "random")

	var manufacturerData []ManufacturerDataElement
	if mdata, ok := props["ManufacturerData"].Value().(map[uint16]dbus.Variant); ok {
		for k, v := range mdata {
			manufacturerData = append(manufacturerData, ManufacturerDataElement{
				CompanyID: k,
				Data:      v.Value().([]byte),
			})
		}
	}

	// Get optional properties.
	localName, _ := props["Name"].Value().(string)
	rssi, _ := props["RSSI"].Value().(int16)

	var serviceData []ServiceDataElement
	if sdata, ok := props["ServiceData"].Value().(map[string]dbus.Variant); ok {
		for k, v := range sdata {
			uuid, err := ParseUUID(k)
			if err != nil {
				continue
			}
			serviceData = append(serviceData, ServiceDataElement{
				UUID: uuid,
				Data: v.Value().([]byte),
			})
		}
	}

	return ScanResult{
		RSSI:    rssi,
		Address: a,
		AdvertisementPayload: &advertisementFields{
			AdvertisementFields{
				LocalName:        localName,
				ServiceUUIDs:     serviceUUIDs,
				ManufacturerData: manufacturerData,
				ServiceData:      serviceData,
			},
		},
	}
}

// Device is a connection to a remote peripheral.
type Device struct {
	Address Address        // the MAC address of the device
	device  dbus.BusObject // bluez device interface
	adapter *Adapter       // the adapter that was used to form this device connection
}

// Connect starts a connection attempt to the given peripheral device address.
func (a *Adapter) Connect(ctx context.Context, address Address) (Device, error) {
	devicePath := dbus.ObjectPath(string(a.adapter.Path()) + "/dev_" + strings.Replace(address.MAC.String(), ":", "_", -1))
	device := Device{
		Address: address,
		device:  a.bus.Object("org.bluez", devicePath),
		adapter: a,
	}

	// Already start watching for property changes. We do this before reading
	// the Connected property below to avoid a race condition: if the device
	// were connected between the two calls the signal wouldn't be picked up.
	signal := make(chan *dbus.Signal)
	a.bus.Signal(signal)
	defer a.bus.RemoveSignal(signal)
	propertiesChangedMatchOptions := []dbus.MatchOption{dbus.WithMatchInterface("org.freedesktop.DBus.Properties")}
	if err := a.bus.AddMatchSignal(propertiesChangedMatchOptions...); err != nil {
		return Device{}, err
	}
	defer func() {
		_ = a.bus.RemoveMatchSignal(propertiesChangedMatchOptions...)
	}()

	// Read whether this device is already connected.
	connected, err := device.device.GetProperty("org.bluez.Device1.Connected")
	if err != nil {
		return Device{}, err
	}

	// Connect to the device, if not already connected.
	if !connected.Value().(bool) {
		err := device.device.CallWithContext(ctx, "org.bluez.Device1.Connect", 0).Err
		if err != nil {
			return Device{}, fmt.Errorf("bluetooth: failed to connect: %w", err)
		}

		eg, ctx := errgroup.WithContext(ctx)
		eg.Go(func() error {
			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case sig, ok := <-signal:
					if !ok {
						return errors.New("did not receive connected signal")
					}
					switch sig.Name {
					case "org.freedesktop.DBus.Properties.PropertiesChanged":
						interfaceName := sig.Body[0].(string)
						if interfaceName != "org.bluez.Device1" {
							continue
						}
						if sig.Path != device.device.Path() {
							continue
						}
						changes := sig.Body[1].(map[string]dbus.Variant)
						if connected, ok := changes["Connected"].Value().(bool); ok && connected {
							return nil
						}
					}
				}
			}
		})

		if err := eg.Wait(); err != nil {
			return Device{}, err
		}
	}

	return device, nil
}

// Disconnect from the BLE device. This method is non-blocking and does not
// wait until the connection is fully gone.
func (d Device) Disconnect() error {
	// how to wait until is disconnected?
	return d.device.Call("org.bluez.Device1.Disconnect", 0).Err
}

var (
	errScanning    = errors.New("bluetooth: a scan is already in progress")
	errNotScanning = errors.New("bluetooth: there is no scan in progress")
)

// MACAddress contains a Bluetooth address which is a MAC address.
type MACAddress struct {
	// MAC address of the Bluetooth device.
	MAC

	isRandom bool
}

// IsRandom if the address is randomly created.
func (mac MACAddress) IsRandom() bool {
	return mac.isRandom
}

// SetRandom if is a random address.
func (mac *MACAddress) SetRandom(val bool) {
	mac.isRandom = val
}

// Set the address
func (mac *MACAddress) Set(val string) {
	m, err := ParseMAC(val)
	if err != nil {
		return
	}

	mac.MAC = m
}

// AdvertisementOptions configures an advertisement instance. More options may
// be added over time.
type AdvertisementOptions struct {
	// The (complete) local name that will be advertised. Optional, omitted if
	// this is a zero-length string.
	LocalName string

	// ServiceUUIDs are the services (16-bit or 128-bit) that are broadcast as
	// part of the advertisement packet, in data types such as "complete list of
	// 128-bit UUIDs".
	ServiceUUIDs []UUID

	// Interval in BLE-specific units. Create an interval by using NewDuration.
	Interval Duration

	// ManufacturerData stores Advertising Data.
	ManufacturerData []ManufacturerDataElement

	// ServiceData stores Advertising Data.
	ServiceData []ServiceDataElement
}

// Manufacturer data that's part of an advertisement packet.
type ManufacturerDataElement struct {
	// The company ID, which must be one of the assigned company IDs.
	// The full list is in here:
	// https://www.bluetooth.com/specifications/assigned-numbers/
	// The list can also be viewed here:
	// https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/company_identifiers/company_identifiers.yaml
	// The value 0xffff can also be used for testing.
	CompanyID uint16

	// The value, which can be any value but can't be very large.
	Data []byte
}

// ServiceDataElement strores a uuid/byte-array pair used as ServiceData advertisment elements
type ServiceDataElement struct {
	// Service UUID.
	// The list can also be viewed here:
	// https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/service_uuids.yaml
	UUID UUID
	// the data byte array
	Data []byte
}

// Duration is the unit of time used in BLE, in 0.625µs units. This unit of time
// is used throughout the BLE stack.
type Duration uint16

// NewDuration returns a new Duration, in units of 0.625µs. It is used both for
// advertisement intervals and for connection parameters.
func NewDuration(interval time.Duration) Duration {
	// Convert an interval to units of 0.625µs.
	return Duration(uint64(interval / (625 * time.Microsecond)))
}

func (d Duration) AsTimeDuration() time.Duration {
	return time.Duration(d) * (625 * time.Microsecond)
}

// Connection is a numeric identifier that indicates a connection handle.
type Connection uint16

// ScanResult contains information from when an advertisement packet was
// received. It is passed as a parameter to the callback of the Scan method.
type ScanResult struct {
	// Bluetooth address of the scanned device.
	Address Address

	// Signal strength of the  advertisement packet.
	RSSI int16

	// The data obtained from the advertisement data, which may contain many
	// different properties.
	// Warning: this data may only stay valid until the next event arrives. If
	// you need any of the fields to stay alive until after the callback
	// returns, copy them.
	AdvertisementPayload
}

// AdvertisementPayload contains information obtained during a scan (see
// ScanResult). It is provided as an interface as there are two possible
// implementations: an implementation that works with raw data (usually on
// low-level BLE stacks) and an implementation that works with structured data.
type AdvertisementPayload interface {
	// LocalName is the (complete or shortened) local name of the device.
	// Please note that many devices do not broadcast a local name, but may
	// broadcast other data (e.g. manufacturer data or service UUIDs) with which
	// they may be identified.
	LocalName() string

	// HasServiceUUID returns true whether the given UUID is present in the
	// advertisement payload as a Service Class UUID. It checks both 16-bit
	// UUIDs and 128-bit UUIDs.
	HasServiceUUID(UUID) bool

	// Bytes returns the raw advertisement packet, if available. It returns nil
	// if this data is not available.
	Bytes() []byte

	// ManufacturerData returns a slice with all the manufacturer data present in the
	// advertising. It may be empty.
	ManufacturerData() []ManufacturerDataElement

	// ServiceData returns a slice with all the service data present in the
	// advertising. It may be empty.
	ServiceData() []ServiceDataElement
}

// AdvertisementFields contains advertisement fields in structured form.
type AdvertisementFields struct {
	// The LocalName part of the advertisement (either the complete local name
	// or the shortened local name).
	LocalName string

	// ServiceUUIDs are the services (16-bit or 128-bit) that are broadcast as
	// part of the advertisement packet, in data types such as "complete list of
	// 128-bit UUIDs".
	ServiceUUIDs []UUID

	// ManufacturerData is the manufacturer data of the advertisement.
	ManufacturerData []ManufacturerDataElement

	// ServiceData is the service data of the advertisement.
	ServiceData []ServiceDataElement
}

// advertisementFields wraps AdvertisementFields to implement the
// AdvertisementPayload interface. The methods to implement the interface (such
// as LocalName) cannot be implemented on AdvertisementFields because they would
// conflict with field names.
type advertisementFields struct {
	AdvertisementFields
}

// LocalName returns the underlying LocalName field.
func (p *advertisementFields) LocalName() string {
	return p.AdvertisementFields.LocalName
}

// HasServiceUUID returns true whether the given UUID is present in the
// advertisement payload as a Service Class UUID.
func (p *advertisementFields) HasServiceUUID(uuid UUID) bool {
	for _, u := range p.AdvertisementFields.ServiceUUIDs {
		if u == uuid {
			return true
		}
	}
	return false
}

// Bytes returns nil, as structured advertisement data does not have the
// original raw advertisement data available.
func (p *advertisementFields) Bytes() []byte {
	return nil
}

// ManufacturerData returns the underlying ManufacturerData field.
func (p *advertisementFields) ManufacturerData() []ManufacturerDataElement {
	return p.AdvertisementFields.ManufacturerData
}

// ServiceData returns the underlying ServiceData field.
func (p *advertisementFields) ServiceData() []ServiceDataElement {
	return p.AdvertisementFields.ServiceData
}
