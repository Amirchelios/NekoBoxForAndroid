// libbox/dns.go

package libcore

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"syscall"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/task"

	mDNS "github.com/miekg/dns"
)

var rawQueryFunc func(networkHandle int64, request []byte) ([]byte, error)

type LocalDNSTransport interface {
	Raw() bool
	NetworkHandle() int64
	Lookup(ctx *ExchangeContext, network string, domain string) error
	Exchange(ctx *ExchangeContext, message []byte) error
}

var gLocalDNSTransport *platformLocalDNSTransport = nil

type platformLocalDNSTransport struct {
	dns.TransportAdapter
	iif LocalDNSTransport
	raw bool
}

func newPlatformTransport(iif LocalDNSTransport, tag string, options option.LocalDNSServerOptions) *platformLocalDNSTransport {
	return &platformLocalDNSTransport{
		TransportAdapter: dns.NewTransportAdapterWithLocalOptions(constant.DNSTypeLocal, tag, options),
		iif:              iif,
		raw:              iif.Raw(),
	}
}

func (p *platformLocalDNSTransport) Start(stage adapter.StartStage) error {
	return nil
}

func (p *platformLocalDNSTransport) Close() error {
	return nil
}

func (p *platformLocalDNSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if message == nil {
		return nil, E.New("empty dns message")
	}
	if len(message.Question) == 0 {
		return nil, E.New("empty dns question")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if p.raw && rawQueryFunc != nil {
		// Raw - Android 10 及以上才有

		messageBytes, err := message.Pack()
		if err != nil {
			return nil, err
		}
		msg, err := rawQueryFunc(p.iif.NetworkHandle(), messageBytes)
		if err != nil {
			return nil, err
		}
		responseMessage := new(mDNS.Msg)
		err = responseMessage.Unpack(msg)
		if err != nil {
			return nil, err
		}
		return responseMessage, nil
	} else {
		// Lookup - Android 10 以下

		question := message.Question[0]
		var network string
		switch question.Qtype {
		case mDNS.TypeA:
			network = "ip4"
		case mDNS.TypeAAAA:
			network = "ip6"
		default:
			return nil, E.New("only IP queries are supported by current version of Android")
		}

		done := make(chan struct{})
		response := &ExchangeContext{
			context: ctx,
			done: sync.OnceFunc(func() {
				close(done)
			}),
		}

		var responseAddrs []netip.Addr
		var group task.Group
		group.Append0(func(ctx context.Context) error {
			err := p.iif.Lookup(response, network, question.Name)
			if err != nil {
				return err
			}
			select {
			case <-done:
			case <-ctx.Done():
				return context.Canceled
			}
			if response.error != nil {
				return response.error
			}
			responseAddrs = response.addresses
			return nil
		})
		err := group.Run(ctx)
		if err != nil {
			return nil, err
		}
		return dns.FixedResponse(message.Id, question, responseAddrs, constant.DefaultDNSTTL), nil
	}
}

type Func interface {
	Invoke() error
}

type ExchangeContext struct {
	context   context.Context
	message   mDNS.Msg
	addresses []netip.Addr
	error     error
	done      func()
}

func (c *ExchangeContext) OnCancel(callback Func) {
	go func() {
		<-c.context.Done()
		callback.Invoke()
	}()
}

func (c *ExchangeContext) Success(result string) {
	lines := common.Filter(strings.Split(result, "\n"), func(it string) bool {
		return !common.IsEmpty(it)
	})
	addrs := make([]netip.Addr, 0, len(lines))
	for _, line := range lines {
		addr, ok := parseLookupAddress(line)
		if ok {
			addrs = append(addrs, addr)
		}
	}
	c.addresses = addrs
	if c.done != nil {
		c.done()
	}
}

func parseLookupAddress(raw string) (netip.Addr, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return netip.Addr{}, false
	}

	parseHost := func(host string) (netip.Addr, bool) {
		host = strings.TrimSpace(strings.Trim(host, "[]"))
		if host == "" {
			return netip.Addr{}, false
		}
		// IPv6 zone suffix should not be passed to netip.ParseAddr.
		if i := strings.IndexByte(host, '%'); i > 0 {
			host = host[:i]
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return netip.Addr{}, false
		}
		return addr, true
	}

	if addr, ok := parseHost(s); ok {
		return addr, true
	}

	if host, _, err := net.SplitHostPort(s); err == nil {
		if addr, ok := parseHost(host); ok {
			return addr, true
		}
	}

	if u, err := url.Parse(s); err == nil && u.Host != "" {
		host := u.Hostname()
		if addr, ok := parseHost(host); ok {
			return addr, true
		}
	}

	return netip.Addr{}, false
}

func (c *ExchangeContext) RawSuccess(result []byte) {
	err := c.message.Unpack(result)
	if err != nil {
		c.error = E.Cause(err, "parse response")
	}
	if c.done != nil {
		c.done()
	}
}

func (c *ExchangeContext) ErrorCode(code int32) {
	c.error = dns.RcodeError(code)
	if c.done != nil {
		c.done()
	}
}

func (c *ExchangeContext) ErrnoCode(code int32) {
	c.error = syscall.Errno(code)
	if c.done != nil {
		c.done()
	}
}
