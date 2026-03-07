// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package security

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/greenpau/caddy-security/pkg/util"
	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
)

const (
	msgPrefix = "security.messaging"
)

// parseCaddyfileCredentials parses messaging configuration.
//
// Syntax:
//
//	messaging email provider <name> {
//	  address <address>
//	  protocol smtp
//	  credentials <credential_name>
//	  sender <email_address> [name]
//	  template password_recovery <path>
//	  template registration_confirmation <path>
//	  template registration_ready <path>
//	  template registration_verdict <path>
//	  template mfa_otp <path>
//	  bcc <email_address_1> <email_address2>
//	}
//
//	messaging file provider <name> {
//	  rootdir <path>
//	}
func parseCaddyfileMessaging(d *caddyfile.Dispenser, cfg *authcrunch.Config) error {
	args := d.RemainingArgs()
	if len(args) != 3 {
		return d.ArgErr()
	}
	if args[1] != "provider" {
		return d.ArgErr()
	}

	switch args[0] {
	case "email":
		c := &messaging.EmailProvider{
			Name: args[2],
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			v := d.RemainingArgs()
			switch k {
			case "address":
				if len(v) != 1 {
					return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
				}
				c.Address = v[0]
			case "protocol":
				if len(v) != 1 {
					return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
				}
				c.Protocol = v[0]
			case "credentials":
				if len(v) != 1 {
					return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
				}
				c.Credentials = v[0]
			case "sender":
				if len(v) < 1 {
					return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
				}
				c.SenderEmail = v[0]
				if len(v) > 1 {
					c.SenderName = v[1]
				}
			case "template":
				if len(v) != 2 {
					return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
				}
				if c.Templates == nil {
					c.Templates = make(map[string]string)
				}
				c.Templates[v[0]] = v[1]
			case "passwordless":
				c.Passwordless = true
			case "bcc":
				for _, r := range v {
					c.BlindCarbonCopy = append(c.BlindCarbonCopy, r)
				}
			default:
				return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
			}
		}
		if err := cfg.AddMessagingProvider(c); err != nil {
			return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], args[1]}, err)
		}
	case "file":
		p := &messaging.FileProvider{
			Name: args[2],
		}
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			k := d.Val()
			v := d.RemainingArgs()
			if len(v) != 1 {
				return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
			}
			switch k {
			case "rootdir":
				p.RootDir = v[0]
			default:
				return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], k}, v)
			}
		}
		if err := cfg.AddMessagingProvider(p); err != nil {
			return errors.ErrMalformedDirective.WithArgs([]string{msgPrefix, args[0], args[1]}, err)
		}
	default:
		return errors.ErrMalformedDirective.WithArgs(msgPrefix, args)
	}
	return nil
}

func cloneResolvedMessagingConfig(cfg *messaging.Config, repl *caddy.Replacer) (*messaging.Config, error) {
	if cfg == nil {
		return nil, nil
	}

	clone := &messaging.Config{}
	if len(cfg.EmailProviders) > 0 {
		clone.EmailProviders = make([]*messaging.EmailProvider, 0, len(cfg.EmailProviders))
		for _, provider := range cfg.EmailProviders {
			resolvedProvider, err := cloneResolvedEmailProvider(provider, repl)
			if err != nil {
				return nil, err
			}
			clone.EmailProviders = append(clone.EmailProviders, resolvedProvider)
		}
	}
	if len(cfg.FileProviders) > 0 {
		clone.FileProviders = make([]*messaging.FileProvider, 0, len(cfg.FileProviders))
		for _, provider := range cfg.FileProviders {
			resolvedProvider, err := cloneResolvedFileProvider(provider, repl)
			if err != nil {
				return nil, err
			}
			clone.FileProviders = append(clone.FileProviders, resolvedProvider)
		}
	}

	return clone, nil
}

func cloneResolvedEmailProvider(cfg *messaging.EmailProvider, repl *caddy.Replacer) (*messaging.EmailProvider, error) {
	if cfg == nil {
		return nil, nil
	}

	name := util.FindReplace(repl, cfg.Name)
	address := util.FindReplace(repl, cfg.Address)
	protocol := util.FindReplace(repl, cfg.Protocol)
	credentialsName := util.FindReplace(repl, cfg.Credentials)
	senderEmail := util.FindReplace(repl, cfg.SenderEmail)
	senderName := util.FindReplace(repl, cfg.SenderName)
	templates := cloneReplacedStringMap(cfg.Templates, repl)
	bcc := util.FindReplaceAll(repl, cfg.BlindCarbonCopy)

	return &messaging.EmailProvider{
		Name:            name,
		Address:         address,
		Protocol:        protocol,
		Credentials:     credentialsName,
		SenderEmail:     senderEmail,
		SenderName:      senderName,
		Templates:       templates,
		Passwordless:    cfg.Passwordless,
		BlindCarbonCopy: bcc,
	}, nil
}

func cloneResolvedFileProvider(cfg *messaging.FileProvider, repl *caddy.Replacer) (*messaging.FileProvider, error) {
	if cfg == nil {
		return nil, nil
	}

	name := util.FindReplace(repl, cfg.Name)
	rootDir := util.FindReplace(repl, cfg.RootDir)
	templates := cloneReplacedStringMap(cfg.Templates, repl)

	return &messaging.FileProvider{
		Name:      name,
		RootDir:   rootDir,
		Templates: templates,
	}, nil
}
