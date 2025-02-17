package bleclient

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// UUIDWrapper is a type alias for UUID so we ensure no conflicts with
// struct method of the same name.
type uuidWrapper = UUID

// DeviceService is a BLE service on a connected peripheral device.
type DeviceService struct {
	uuidWrapper
	adapter     *Adapter
	servicePath string
}

// UUID returns the UUID for this DeviceService.
func (s DeviceService) UUID() UUID {
	return s.uuidWrapper
}

// DiscoverServices starts a service discovery procedure. Pass a list of service
// UUIDs you are interested in to this function. Either a slice of all services
// is returned (of the same length as the requested UUIDs and in the same
// order), or if some services could not be discovered an error is returned.
//
// Passing a nil slice of UUIDs will return a complete list of
// services.
//
// On Linux with BlueZ, this just waits for the ServicesResolved signal (if
// services haven't been resolved yet) and uses this list of cached services.
func (d *Device) DiscoverServices(ctx context.Context, uuids []UUID) ([]*DeviceService, error) {
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()

RESOLVED:
	for {
		select {
		case <-ticker.C:
			resolved, err := d.device.GetProperty("org.bluez.Device1.ServicesResolved")
			if err != nil {
				return nil, err
			}
			if resolved.Value().(bool) {
				break RESOLVED
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	services := []*DeviceService{}
	uuidServices := make(map[UUID]struct{})
	servicesFound := 0

	// Iterate through all objects managed by BlueZ, hoping to find the services
	// we're looking for.
	var list map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	err := d.adapter.bluez.CallWithContext(ctx, "org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&list)
	if err != nil {
		return nil, err
	}
	objects := make([]string, 0, len(list))
	for objectPath := range list {
		objects = append(objects, string(objectPath))
	}
	sort.Strings(objects)
	for _, objectPath := range objects {
		if !strings.HasPrefix(objectPath, string(d.device.Path())+"/service") {
			continue
		}
		properties, ok := list[dbus.ObjectPath(objectPath)]["org.bluez.GattService1"]
		if !ok {
			continue
		}

		serviceUUID, _ := ParseUUID(properties["UUID"].Value().(string))

		if len(uuids) > 0 {
			found := false
			for _, uuid := range uuids {
				if uuid == serviceUUID {
					// One of the services we're looking for.
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if _, ok := uuidServices[serviceUUID]; ok {
			// There is more than one service with the same UUID?
			// Don't overwrite it, to keep the servicesFound count correct.
			continue
		}

		ds := DeviceService{
			uuidWrapper: serviceUUID,
			adapter:     d.adapter,
			servicePath: objectPath,
		}

		services = append(services, &ds)
		servicesFound++
		uuidServices[serviceUUID] = struct{}{}
	}

	if servicesFound < len(uuids) {
		return nil, errors.New("bluetooth: could not find some services")
	}

	return services, nil
}

// DeviceCharacteristic is a BLE characteristic on a connected peripheral
// device.
type DeviceCharacteristic struct {
	uuidWrapper
	adapter        *Adapter
	characteristic dbus.BusObject
}

// UUID returns the UUID for this DeviceCharacteristic.
func (c DeviceCharacteristic) UUID() UUID {
	return c.uuidWrapper
}

// DiscoverCharacteristics discovers characteristics in this service. Pass a
// list of characteristic UUIDs you are interested in to this function. Either a
// list of all requested services is returned, or if some services could not be
// discovered an error is returned. If there is no error, the characteristics
// slice has the same length as the UUID slice with characteristics in the same
// order in the slice as in the requested UUID list.
//
// Passing a nil slice of UUIDs will return a complete
// list of characteristics.
func (s *DeviceService) DiscoverCharacteristics(ctx context.Context, uuids []UUID) ([]*DeviceCharacteristic, error) {
	var chars []*DeviceCharacteristic
	if len(uuids) > 0 {
		// The caller wants to get a list of characteristics in a specific
		// order.
		chars = make([]*DeviceCharacteristic, len(uuids))
	}

	// Iterate through all objects managed by BlueZ, hoping to find the
	// characteristic we're looking for.
	var list map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	err := s.adapter.bluez.CallWithContext(ctx, "org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&list)
	if err != nil {
		return nil, err
	}
	objects := make([]string, 0, len(list))
	for objectPath := range list {
		objects = append(objects, string(objectPath))
	}
	sort.Strings(objects)
	for _, objectPath := range objects {
		if !strings.HasPrefix(objectPath, s.servicePath+"/char") {
			continue
		}
		properties, ok := list[dbus.ObjectPath(objectPath)]["org.bluez.GattCharacteristic1"]
		if !ok {
			continue
		}
		cuuid, _ := ParseUUID(properties["UUID"].Value().(string))
		char := &DeviceCharacteristic{
			uuidWrapper:    cuuid,
			adapter:        s.adapter,
			characteristic: s.adapter.bus.Object("org.bluez", dbus.ObjectPath(objectPath)),
		}

		if len(uuids) > 0 {
			// The caller wants to get a list of characteristics in a specific
			// order. Check whether this is one of those.
			for i, uuid := range uuids {
				if chars[i] != nil {
					// To support multiple identical characteristics, we need to
					// ignore the characteristics that are already found. See:
					// https://github.com/tinygo-org/bluetooth/issues/131
					continue
				}
				if cuuid == uuid {
					// one of the characteristics we're looking for.
					chars[i] = char
					break
				}
			}
		} else {
			// The caller wants to get all characteristics, in any order.
			chars = append(chars, char)
		}
	}

	// Check that we have found all characteristics.
	for _, char := range chars {
		if char == nil {
			return nil, errors.New("bluetooth: could not find some characteristics")
		}
	}

	return chars, nil
}

// WriteWithoutResponse replaces the characteristic value with a new value. The
// call will return before all data has been written. A limited number of such
// writes can be in flight at any given time. This call is also known as a
// "write command" (as opposed to a write request).
func (c *DeviceCharacteristic) WriteWithoutResponse(ctx context.Context, p []byte) (int, error) {
	err := c.characteristic.CallWithContext(
		ctx,
		"org.bluez.GattCharacteristic1.WriteValue",
		0,
		p,
		map[string]dbus.Variant{
			"type": dbus.MakeVariant("command"),
		},
	).Err
	if err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *DeviceCharacteristic) HandleNotifications(ctx context.Context, callback func(buf []byte)) error {
	// needs to be buffered?
	property := make(chan *dbus.Signal, 4)
	defer close(property)

	c.adapter.bus.Signal(property)
	defer c.adapter.bus.RemoveSignal(property)

	propertiesChangedMatchOption := dbus.WithMatchInterface("org.freedesktop.DBus.Properties")

	if err := c.adapter.bus.AddMatchSignal(propertiesChangedMatchOption); err != nil {
		return err
	}

	defer func() {
		_ = c.adapter.bus.RemoveMatchSignal(propertiesChangedMatchOption)
	}()

	err := c.characteristic.CallWithContext(ctx, "org.bluez.GattCharacteristic1.StartNotify", 0).Err
	if err != nil {
		return err
	}

	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()
		_ = c.characteristic.CallWithContext(ctx, "org.bluez.GattCharacteristic1.StopNotify", 0).Err
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig, ok := <-property:
			if !ok {
				return nil
			}
			if sig.Name != "org.freedesktop.DBus.Properties.PropertiesChanged" {
				continue
			}

			interfaceName := sig.Body[0].(string)

			if interfaceName != "org.bluez.GattCharacteristic1" {
				continue
			}

			if sig.Path != c.characteristic.Path() {
				continue
			}
			changes := sig.Body[1].(map[string]dbus.Variant)

			if value, ok := changes["Value"].Value().([]byte); ok {
				callback(value)
			}
		}
	}
}

// GetMTU returns the MTU for the characteristic.
func (c *DeviceCharacteristic) GetMTU() (uint16, error) {
	mtu, err := c.characteristic.GetProperty("org.bluez.GattCharacteristic1.MTU")
	if err != nil {
		return uint16(0), err
	}
	return mtu.Value().(uint16), nil
}

// Read reads the current characteristic value.
func (c *DeviceCharacteristic) Read(data []byte) (int, error) {
	options := make(map[string]interface{})
	var result []byte
	err := c.characteristic.Call("org.bluez.GattCharacteristic1.ReadValue", 0, options).Store(&result)
	if err != nil {
		return 0, err
	}
	copy(data, result)
	return len(result), nil
}
