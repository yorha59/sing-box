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

	if got := usableDirectAddresses(addresses, false, true); !slices.Equal(got, []netip.Addr{privateIPv6, ipv4}) {
		t.Fatalf("got %v, want private IPv6 and IPv4 candidates", got)
	}
	if !slices.Equal(addresses, []netip.Addr{ipv6, privateIPv6, ipv4}) {
		t.Fatalf("original address list was modified: %v", addresses)
	}
	onlyIPv6 := []netip.Addr{ipv6}
	if got := usableDirectAddresses(onlyIPv6, false, true); !slices.Equal(got, onlyIPv6) {
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

func TestOutboundIPRoutesUnavailableFollowsSelectedInterfaces(t *testing.T) {
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
	if ipv4, ipv6 := dialer.outboundIPRoutesUnavailable(nil, nil, nil); ipv4 || !ipv6 {
		t.Fatal("default Wi-Fi has no IPv6 route")
	}
	fallbackStrategy := C.NetworkStrategyFallback
	if ipv4, ipv6 := dialer.outboundIPRoutesUnavailable(&fallbackStrategy, nil, nil); ipv4 || ipv6 {
		t.Fatal("cellular fallback may have an IPv6 route")
	}
	manager.monitor.active = &cellular.Interface
	manager.interfaces[1].IPv4RouteUnavailable = true
	if ipv4, ipv6 := dialer.outboundIPRoutesUnavailable(nil, nil, nil); !ipv4 || ipv6 {
		t.Fatal("cellular is now the default and has no IPv4 route")
	}
	manager.monitor.active = &wifi.Interface
	manager.interfaces[0].IPv6RouteUnavailable = false
	if _, ipv6 := dialer.outboundIPRoutesUnavailable(nil, nil, nil); ipv6 {
		t.Fatal("the same Wi-Fi interface acquired an IPv6 route")
	}
}

func TestUsableDirectAddressesOnIPv6OnlyRoute(t *testing.T) {
	ipv4 := netip.MustParseAddr("192.0.2.1")
	mappedIPv4 := netip.MustParseAddr("::ffff:192.0.2.2")
	privateIPv4 := netip.MustParseAddr("192.168.1.1")
	nat64 := netip.MustParseAddr("64:ff9b::c000:201")
	addresses := []netip.Addr{ipv4, mappedIPv4, privateIPv4, nat64}
	if got := usableDirectAddresses(addresses, true, false); !slices.Equal(got, []netip.Addr{privateIPv4, nat64}) {
		t.Fatalf("got %v, want private IPv4 and DNS64 candidates", got)
	}
	for _, input := range [][]netip.Addr{{ipv4, mappedIPv4}, {nat64}} {
		if got := usableDirectAddresses(input, true, false); !slices.Equal(got, input) {
			t.Fatalf("single-family input %v changed to %v", input, got)
		}
	}
}
