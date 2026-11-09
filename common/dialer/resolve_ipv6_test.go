package dialer

import (
	"errors"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"testing"
)

func TestUsableDirectAddressesAcrossNetworkChanges(t *testing.T) {
	ipv6 := netip.MustParseAddr("2001:db8::1")
	ipv4 := netip.MustParseAddr("192.0.2.1")
	addresses := []netip.Addr{ipv6, ipv4}
	var routeError error
	checkRoute := func(address netip.Addr) error {
		if address != ipv6 {
			t.Fatalf("unexpected route check for %v", address)
		}
		return routeError
	}

	for _, scenario := range []struct {
		err  error
		want []netip.Addr
	}{
		{&net.OpError{Op: "dial", Net: "udp6", Err: syscall.EHOSTUNREACH}, []netip.Addr{ipv4}},
		{nil, addresses},
		{syscall.ENETUNREACH, []netip.Addr{ipv4}},
		{errors.New("unknown path"), addresses},
	} {
		routeError = scenario.err
		if got := usableDirectAddresses(addresses, checkRoute); !slices.Equal(got, scenario.want) {
			t.Fatalf("route %v: got %v, want %v", scenario.err, got, scenario.want)
		}
	}
	if !slices.Equal(addresses, []netip.Addr{ipv6, ipv4}) {
		t.Fatalf("original address list was modified: %v", addresses)
	}
	onlyIPv6 := []netip.Addr{ipv6}
	if got := usableDirectAddresses(onlyIPv6, func(netip.Addr) error {
		t.Fatal("IPv6-only destinations must keep their original address")
		return nil
	}); !slices.Equal(got, onlyIPv6) {
		t.Fatalf("got %v, want %v", got, onlyIPv6)
	}
}
