package cdydnsupd

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/michaelrommel/ldnsupd"
)

// Provider lets Caddy read and manipulate DNS records hosted by this DNS provider.
type Provider struct{ *ldnsupd.Provider }

func init() {
	caddy.RegisterModule(Provider{})
}

// CaddyModule returns the Caddy module information.
func (Provider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.cdydnsupd",
		New: func() caddy.Module { return &Provider{new(ldnsupd.Provider)} },
	}
}

// This is the minimum information needed to construct the TSIG signed 
// DNS update packets. Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.Provider.TSIGKeyName = caddy.NewReplacer().ReplaceAll(p.Provider.TSIGKeyName, "")
	p.Provider.TSIGSecret = caddy.NewReplacer().ReplaceAll(p.Provider.TSIGSecret, "")
	p.Provider.TSIGAlgorithm = caddy.NewReplacer().ReplaceAll(p.Provider.TSIGAlgorithm, "")
	p.Provider.DNSServer = caddy.NewReplacer().ReplaceAll(p.Provider.DNSServer, "")
	return nil
}

// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
// dns cdydnsupd {
//     tsig_key_name <keyname>
//     tsig_secret <secret>
//     tsig_algorithm <algorithm>
//     dns_server <server>
// }
func (p *Provider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "tsig_key_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if p.Provider.TSIGKeyName != "" {
					return d.Err("TSIG keyname already set")
				}
				p.Provider.TSIGKeyName = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "tsig_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if p.Provider.TSIGSecret != "" {
					return d.Err("TSIG secret already set")
				}
				p.Provider.TSIGSecret = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "tsig_algorithm":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if p.Provider.TSIGAlgorithm != "" {
					return d.Err("TSIG algorithm already set")
				}
				p.Provider.TSIGAlgorithm = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			case "dns_server":
				if !d.NextArg() {
					return d.ArgErr()
				}
				if p.Provider.DNSServer != "" {
					return d.Err("DNS server already set")
				}
				p.Provider.DNSServer = d.Val()
				if d.NextArg() {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}
	if p.Provider.TSIGKeyName == "" || 
	   p.Provider.TSIGSecret == "" || 
	   p.Provider.TSIGAlgorithm == "" || 
	   p.Provider.DNSServer == "" {
		return d.Err("missing parameters")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)

