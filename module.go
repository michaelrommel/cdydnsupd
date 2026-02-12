package cdydnsupd

import (
	// "fmt"
	// "context"
	// "os/exec"

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

// TODO: This is just an example. Useful to allow env variable placeholders; update accordingly.
// Provision sets up the module. Implements caddy.Provisioner.
func (p *Provider) Provision(ctx caddy.Context) error {
	p.Provider.TSIGKeyName = caddy.NewReplacer().ReplaceAll(p.Provider.TSIGKeyName, "")
	p.Provider.TSIGSecret = caddy.NewReplacer().ReplaceAll(p.Provider.TSIGSecret, "")
	p.Provider.DNSServer = caddy.NewReplacer().ReplaceAll(p.Provider.DNSServer, "")
	return nil
}

// func (p *Provider) Present(ctx context.Context, domain, token, key string) error {
// 	cmd := exec.Command(p.ScriptPath, "create", domain, token, key)
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		return fmt.Errorf("script failed: %v\n%s", err, string(output))
// 	}
// 	p.Logger.Info("DNS challenge created", zap.String("domain", domain))
// 	return nil
// }

// func (p *Provider) CleanUp(ctx context.Context, domain, token, key string) error {
// 	cmd := exec.Command(p.ScriptPath, "delete", domain, token, key)
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		return fmt.Errorf("script failed: %v\n%s", err, string(output))
// 	}
// 	p.Logger.Info("DNS challenge cleaned up", zap.String("domain", domain))
// 	return nil
// }

// TODO: This is just an example. Update accordingly.
// UnmarshalCaddyfile sets up the DNS provider from Caddyfile tokens. Syntax:
//
// providername {
//     tsig_key_name <keyname>
//     tsig_secret <secret>
//     dns_server <server>
// }
//
// **THIS IS JUST AN EXAMPLE AND NEEDS TO BE CUSTOMIZED.**
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
	if p.Provider.TSIGKeyName == "" || p.Provider.TSIGSecret == "" || p.Provider.DNSServer == "" {
		return d.Err("missing parameters")
	}
	return nil
}

// Interface guards
var (
	_ caddyfile.Unmarshaler = (*Provider)(nil)
	_ caddy.Provisioner     = (*Provider)(nil)
)

