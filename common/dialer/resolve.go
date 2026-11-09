package dialer

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

var (
	_ N.Dialer                = (*resolveDialer)(nil)
	_ ParallelInterfaceDialer = (*resolveParallelNetworkDialer)(nil)
)

type ResolveDialer interface {
	N.Dialer
	QueryOptions() adapter.DNSQueryOptions
}

type ParallelInterfaceResolveDialer interface {
	ParallelInterfaceDialer
	QueryOptions() adapter.DNSQueryOptions
}

type resolveDialer struct {
	transport     adapter.DNSTransportManager
	router        adapter.DNSRouter
	dialer        N.Dialer
	parallel      bool
	server        string
	initOnce      sync.Once
	initErr       error
	queryOptions  adapter.DNSQueryOptions
	fallbackDelay time.Duration
}

func NewResolveDialer(ctx context.Context, dialer N.Dialer, parallel bool, server string, queryOptions adapter.DNSQueryOptions, fallbackDelay time.Duration) ResolveDialer {
	if parallelDialer, isParallel := dialer.(ParallelInterfaceDialer); isParallel {
		return &resolveParallelNetworkDialer{
			resolveDialer{
				transport:     service.FromContext[adapter.DNSTransportManager](ctx),
				router:        service.FromContext[adapter.DNSRouter](ctx),
				dialer:        dialer,
				parallel:      parallel,
				server:        server,
				queryOptions:  queryOptions,
				fallbackDelay: fallbackDelay,
			},
			parallelDialer,
			false,
		}
	}
	return &resolveDialer{
		transport:     service.FromContext[adapter.DNSTransportManager](ctx),
		router:        service.FromContext[adapter.DNSRouter](ctx),
		dialer:        dialer,
		parallel:      parallel,
		server:        server,
		queryOptions:  queryOptions,
		fallbackDelay: fallbackDelay,
	}
}

type resolveParallelNetworkDialer struct {
	resolveDialer
	dialer         ParallelInterfaceDialer
	checkIPv6Route bool
}

func (d *resolveDialer) initialize() error {
	d.initOnce.Do(d.initServer)
	return d.initErr
}

func (d *resolveDialer) initServer() {
	if d.server == "" {
		return
	}
	transport, loaded := d.transport.Transport(d.server)
	if !loaded {
		d.initErr = E.New("domain resolver not found: " + d.server)
		return
	}
	d.queryOptions.Transport = transport
}

func (d *resolveDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	if d.parallel {
		return N.DialParallel(ctx, d.dialer, network, destination, addresses, addresses[0].Is6(), d.fallbackDelay)
	} else {
		return N.DialSerial(ctx, d.dialer, network, destination, addresses)
	}
}

func (d *resolveDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	conn, destinationAddress, err := N.ListenSerial(ctx, d.dialer, destination, addresses)
	if err != nil {
		return nil, err
	}
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *resolveDialer) QueryOptions() adapter.DNSQueryOptions {
	return d.queryOptions
}

func (d *resolveDialer) Upstream() any {
	return d.dialer
}

func (d *resolveParallelNetworkDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if d.checkIPv6Route && destination.IsDomain() {
		return d.DialParallelInterface(ctx, network, destination, nil, nil, nil, 0)
	}
	return d.resolveDialer.DialContext(ctx, network, destination)
}

func (d *resolveParallelNetworkDialer) DialParallelInterface(ctx context.Context, network string, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.Conn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.DialContext(ctx, network, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	addresses = d.directAddresses(ctx, destination, addresses, strategy, interfaceType, fallbackInterfaceType)
	if fallbackDelay == 0 {
		fallbackDelay = d.fallbackDelay
	}
	if d.parallel {
		return DialParallelNetwork(ctx, d.dialer, network, destination, addresses, addresses[0].Is6(), strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	} else {
		return DialSerialNetwork(ctx, d.dialer, network, destination, addresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	}
}

func (d *resolveParallelNetworkDialer) ListenSerialInterfacePacket(ctx context.Context, destination M.Socksaddr, strategy *C.NetworkStrategy, interfaceType []C.InterfaceType, fallbackInterfaceType []C.InterfaceType, fallbackDelay time.Duration) (net.PacketConn, error) {
	err := d.initialize()
	if err != nil {
		return nil, err
	}
	if !destination.IsDomain() {
		return d.dialer.ListenPacket(ctx, destination)
	}
	ctx = log.ContextWithOverrideLevel(ctx, log.LevelDebug)
	addresses, err := d.router.Lookup(ctx, destination.Fqdn, d.queryOptions)
	if err != nil {
		return nil, err
	}
	addresses = d.directAddresses(ctx, destination, addresses, strategy, interfaceType, fallbackInterfaceType)
	if fallbackDelay == 0 {
		fallbackDelay = d.fallbackDelay
	}
	conn, destinationAddress, err := ListenSerialNetworkPacket(ctx, d.dialer, destination, addresses, strategy, interfaceType, fallbackInterfaceType, fallbackDelay)
	if err != nil {
		return nil, err
	}
	return bufio.NewNATPacketConn(bufio.NewPacketConn(conn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
}

func (d *resolveParallelNetworkDialer) directAddresses(ctx context.Context, destination M.Socksaddr, addresses []netip.Addr, strategy *C.NetworkStrategy, interfaceType, fallbackInterfaceType []C.InterfaceType) []netip.Addr {
	dialer, ok := d.dialer.(*DefaultDialer)
	if !d.checkIPv6Route || !ok || !destination.IsDomain() || !dialer.outboundIPv6Unavailable(strategy, interfaceType, fallbackInterfaceType) {
		return addresses
	}
	filtered := usableDirectAddresses(addresses)
	if len(filtered) != len(addresses) {
		if factory := service.FromContext[log.Factory](ctx); factory != nil {
			factory.Logger().DebugContext(ctx, "direct: skipped IPv6 addresses without an outbound route for ", destination.Fqdn)
		}
	}
	return filtered
}

func usableDirectAddresses(addresses []netip.Addr) []netip.Addr {
	if !slices.ContainsFunc(addresses, func(address netip.Addr) bool { return address.Unmap().Is4() }) {
		return addresses
	}
	isPublicIPv6 := func(address netip.Addr) bool {
		return address.Is6() && !address.Is4In6() && address.IsGlobalUnicast() && !address.IsPrivate()
	}
	if !slices.ContainsFunc(addresses, isPublicIPv6) {
		return addresses
	}
	return slices.DeleteFunc(slices.Clone(addresses), isPublicIPv6)
}

func (d *resolveParallelNetworkDialer) QueryOptions() adapter.DNSQueryOptions {
	return d.queryOptions
}

func (d *resolveParallelNetworkDialer) Upstream() any {
	return d.dialer
}
