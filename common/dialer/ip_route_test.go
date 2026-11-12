package dialer

import (
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
)

type routeTestMonitor struct{ tun.DefaultInterfaceMonitor }

func (*routeTestMonitor) MyInterfaces() []string               { return []string{"utun0"} }
func (*routeTestMonitor) DefaultInterface() *control.Interface { return &control.Interface{Index: 1} }

type routeTestNetwork struct {
	adapter.NetworkManager
	interfaces []adapter.NetworkInterface
}

func (n *routeTestNetwork) NetworkInterfaces() []adapter.NetworkInterface { return n.interfaces }
func (*routeTestNetwork) InterfaceMonitor() tun.DefaultInterfaceMonitor   { return &routeTestMonitor{} }

func TestIPRouteUnavailableTracksInterfaces(t *testing.T) {
	strategy := C.NetworkStrategyDefault
	n := &routeTestNetwork{interfaces: []adapter.NetworkInterface{{Interface: control.Interface{Index: 1, Name: "en0"}, IPv6RouteUnavailable: true}}}
	d := &DefaultDialer{networkManager: n, networkStrategy: &strategy}
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"2001:db8::1", true}, {"192.0.2.1", false}, {"fd00::1", false}, {"fe80::1", false}, {"::1", false}, {"::ffff:192.0.2.1", false},
	} {
		if got := d.IPRouteUnavailable(netip.MustParseAddr(tc.address), nil, nil, nil); got != tc.want {
			t.Errorf("%s: %v", tc.address, got)
		}
	}
	// A path refresh must take effect without recreating the dialer.
	n.interfaces[0].IPv6RouteUnavailable = false
	n.interfaces[0].IPv4RouteUnavailable = true
	if d.IPRouteUnavailable(netip.MustParseAddr("2001:db8::1"), nil, nil, nil) {
		t.Fatal("stale IPv6 status")
	}
	if !d.IPRouteUnavailable(netip.MustParseAddr("::ffff:192.0.2.1"), nil, nil, nil) {
		t.Fatal("IPv4-only failure not detected")
	}
	n.interfaces = nil
	if d.IPRouteUnavailable(netip.MustParseAddr("192.0.2.1"), nil, nil, nil) {
		t.Fatal("unknown interface rejected")
	}
	n.interfaces = []adapter.NetworkInterface{
		{Interface: control.Interface{Index: 1}, IPv6RouteUnavailable: true},
		{Interface: control.Interface{Index: 2}},
	}
	hybrid := C.NetworkStrategyHybrid
	if d.IPRouteUnavailable(netip.MustParseAddr("2001:db8::1"), &hybrid, nil, nil) {
		t.Fatal("usable alternate interface rejected")
	}
}
