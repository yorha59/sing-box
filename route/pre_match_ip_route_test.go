package route

import (
	"context"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type preRouteOutbound struct {
	adapter.Outbound
	unavailable bool
	calls       int
	strategy    *C.NetworkStrategy
}

func (*preRouteOutbound) Network() []string { return []string{N.NetworkTCP} }
func (o *preRouteOutbound) RouteUnavailable(m *adapter.InboundContext) bool {
	o.calls++
	o.strategy = m.NetworkStrategy
	return o.unavailable
}

type preRouteManager struct {
	adapter.OutboundManager
	selected adapter.Outbound
}

func (m *preRouteManager) Default() adapter.Outbound                { return m.selected }
func (m *preRouteManager) Outbound(string) (adapter.Outbound, bool) { return m.selected, true }

type preRouteDNS struct{ adapter.DNSRouter }

func (*preRouteDNS) LookupReverseMapping(netip.Addr) (string, bool) { return "", false }

type preRouteTransport struct{ adapter.DNSTransportManager }

func (*preRouteTransport) FakeIP() adapter.FakeIPTransport { return nil }

type preRouteRule struct {
	adapter.Rule
	action adapter.RuleAction
}

func (*preRouteRule) Match(*adapter.InboundContext) bool { return true }
func (*preRouteRule) String() string                     { return "" }
func (r *preRouteRule) Action() adapter.RuleAction       { return r.action }

func TestPreMatchRejectBeforeTCPAccept(t *testing.T) {
	o := &preRouteOutbound{unavailable: true}
	r := &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), outbound: &preRouteManager{selected: o}, dns: &preRouteDNS{}, dnsTransport: &preRouteTransport{}}
	source := netip.MustParseAddrPort("[fd00::1]:12345")
	destination := netip.MustParseAddrPort("[2001:db8::1]:443")
	verdict := adapter.JudgeFlow(r, adapter.InboundContext{Inbound: "tun", InboundType: C.TypeTun}, uint8(header.TCPProtocolNumber), source, destination, nil)
	if verdict.Action != tun.ActionReject {
		t.Fatalf("got %v, want reject before stack accepts SYN", verdict.Action)
	}
	o.unavailable = false
	if v := adapter.JudgeFlow(r, adapter.InboundContext{Inbound: "tun", InboundType: C.TypeTun}, uint8(header.TCPProtocolNumber), source, destination, nil); v.Action != tun.ActionAccept {
		t.Fatalf("available route: %v", v.Action)
	}
	// Sniff must remain a barrier; a later IP rule cannot override SNI routing.
	o.unavailable = true
	o.calls = 0
	r.rules = []adapter.Rule{&preRouteRule{action: &R.RuleActionSniff{}}}
	if v := adapter.JudgeFlow(r, adapter.InboundContext{Inbound: "tun", InboundType: C.TypeTun}, uint8(header.TCPProtocolNumber), source, destination, nil); v.Action != tun.ActionAccept || o.calls != 0 {
		t.Fatal("premature rejection before sniff")
	}
	// Explicit per-rule interface selection must reach the route checker.
	strategy := C.NetworkStrategyHybrid
	r.rules = []adapter.Rule{&preRouteRule{action: &R.RuleActionRoute{RuleActionRouteOptions: R.RuleActionRouteOptions{NetworkStrategy: &strategy}}}}
	r.PreMatch(adapter.InboundContext{Network: N.NetworkTCP, Destination: M.SocksaddrFromNetIP(destination)}, nil)
	if o.strategy != &strategy {
		t.Fatal("route network strategy lost")
	}
}

// Proxy outbounds do not implement the physical-route checker.
type preRouteProxy struct{ adapter.Outbound }

func (*preRouteProxy) Network() []string { return []string{N.NetworkTCP} }
func TestPreMatchProxyRemainsAccepted(t *testing.T) {
	r := &Router{ctx: context.Background(), logger: log.NewNOPFactory().Logger(), outbound: &preRouteManager{selected: &preRouteProxy{}}}
	metadata := adapter.InboundContext{InboundType: C.TypeTun, Network: N.NetworkTCP, Destination: M.ParseSocksaddr("[2001:db8::1]:443")}
	if got := r.preMatchFlow(r.ctx, &metadata, metadata.Destination, nil, ""); got.Action != adapter.PreMatchContinue {
		t.Fatalf("proxy changed: %v", got.Action)
	}
}
