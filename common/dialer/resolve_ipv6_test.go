package dialer

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

func TestUsableDirectAddresses(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")
	privateIPv6 := netip.MustParseAddr("fd00::1")
	ipv4 := netip.MustParseAddr("192.0.2.1")
	addresses := []netip.Addr{ipv6, privateIPv6, ipv4}

	if got := usableDirectAddresses(addresses); !slices.Equal(got, []netip.Addr{privateIPv6, ipv4}) {
		t.Fatalf("got %v, want private IPv6 and IPv4 candidates", got)
	}
	if !slices.Equal(addresses, []netip.Addr{ipv6, privateIPv6, ipv4}) {
		t.Fatalf("original address list was modified: %v", addresses)
	}
	onlyIPv6 := []netip.Addr{ipv6}
	if got := usableDirectAddresses(onlyIPv6); !slices.Equal(got, onlyIPv6) {
		t.Fatalf("got %v, want %v", got, onlyIPv6)
	}
}

type ipv6TestNetworkManager struct {
	adapter.NetworkManager
	interfaces []adapter.NetworkInterface
	monitor    *ipv6TestInterfaceMonitor
}

func (m *ipv6TestNetworkManager) NetworkInterfaces() []adapter.NetworkInterface { return m.interfaces }

func (m *ipv6TestNetworkManager) InterfaceMonitor() tun.DefaultInterfaceMonitor { return m.monitor }

type ipv6TestInterfaceMonitor struct {
	tun.DefaultInterfaceMonitor
	active *control.Interface
}

func (m *ipv6TestInterfaceMonitor) DefaultInterface() *control.Interface { return m.active }

func (m *ipv6TestInterfaceMonitor) MyInterfaces() []string { return nil }

func TestOutboundIPv6UnavailableFollowsSelectedInterfaces(t *testing.T) {
	wifi := adapter.NetworkInterface{
		Interface:            control.Interface{Name: "en0", Index: 1},
		IPv6RouteUnavailable: true,
	}
	cellular := adapter.NetworkInterface{
		Interface: control.Interface{Name: "pdp_ip0", Index: 2},
	}
	manager := &ipv6TestNetworkManager{
		interfaces: []adapter.NetworkInterface{wifi, cellular},
		monitor:    &ipv6TestInterfaceMonitor{active: &wifi.Interface},
	}
	defaultStrategy := C.NetworkStrategyDefault
	dialer := &DefaultDialer{networkManager: manager, networkStrategy: &defaultStrategy}
	if !dialer.outboundIPv6Unavailable(nil, nil, nil) {
		t.Fatal("default Wi-Fi has no IPv6 route")
	}
	fallbackStrategy := C.NetworkStrategyFallback
	if dialer.outboundIPv6Unavailable(&fallbackStrategy, nil, nil) {
		t.Fatal("cellular fallback may have an IPv6 route")
	}
	manager.monitor.active = &cellular.Interface
	if dialer.outboundIPv6Unavailable(nil, nil, nil) {
		t.Fatal("cellular is now the default and may have an IPv6 route")
	}
	manager.monitor.active = &wifi.Interface
	manager.interfaces[0].IPv6RouteUnavailable = false
	if dialer.outboundIPv6Unavailable(nil, nil, nil) {
		t.Fatal("the same Wi-Fi interface acquired an IPv6 route")
	}
}
