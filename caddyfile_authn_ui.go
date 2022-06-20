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
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"io/ioutil"
	"strings"
)

func parseCaddyfileAuthPortalUI(h *caddyfile.Dispenser, repl *caddy.Replacer, portal *authn.PortalConfig, rootDirective string) error {
	for nesting := h.Nesting(); h.NextBlock(nesting); {
		subDirective := h.Val()
		switch subDirective {
		case "template":
			hargs := util.FindReplaceAll(repl, h.RemainingArgs())
			switch {
			case len(hargs) == 2:
				portal.UI.Templates[hargs[0]] = hargs[1]
			default:
				args := strings.Join(h.RemainingArgs(), " ")
				return h.Errf("%s directive %q is invalid", rootDirective, args)
			}
		case "theme":
			if !h.NextArg() {
				return h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
			}
			portal.UI.Theme = h.Val()
		case "logo":
			hargs := util.FindReplaceAll(repl, h.RemainingArgs())
			args := strings.Join(hargs, " ")
			args = strings.TrimSpace(args)
			switch {
			case strings.HasPrefix(args, "url"):
				portal.UI.LogoURL = strings.ReplaceAll(args, "url ", "")
			case strings.HasPrefix(args, "description"):
				portal.UI.LogoDescription = strings.ReplaceAll(args, "description ", "")
			case args == "":
				return h.Errf("%s %s directive has no value", rootDirective, subDirective)
			default:
				return h.Errf("%s directive %q is unsupported", rootDirective, args)
			}
		case "meta":
			hargs := util.FindReplaceAll(repl, h.RemainingArgs())
			args := strings.Join(hargs, " ")
			args = strings.TrimSpace(args)
			switch {
			case strings.HasPrefix(args, "title"):
				portal.UI.MetaAuthor = strings.ReplaceAll(args, "title ", "")
			case strings.HasPrefix(args, "author"):
				portal.UI.MetaAuthor = strings.ReplaceAll(args, "author ", "")
			case strings.HasPrefix(args, "description"):
				portal.UI.MetaDescription = strings.ReplaceAll(args, "description ", "")
			case args == "":
				return h.Errf("%s %s directive has no value", rootDirective, subDirective)
			default:
				return h.Errf("%s directive %q is unsupported", rootDirective, args)
			}
		case "auto_redirect_url":
			if !h.NextArg() {
				return h.Errf("%s %s subdirective has no value", rootDirective, subDirective)
			}
			portal.UI.AutoRedirectURL = util.FindReplace(repl, h.Val())
		case "links":
			for subNesting := h.Nesting(); h.NextBlock(subNesting); {
				title := h.Val()
				args := util.FindReplaceAll(repl, h.RemainingArgs())
				if len(args) == 0 {
					return h.Errf("auth backend %s subdirective %s has no value", subDirective, title)
				}
				privateLink := ui.Link{
					Title: title,
					Link:  args[0],
				}
				if len(args) == 1 {
					portal.UI.PrivateLinks = append(portal.UI.PrivateLinks, privateLink)
					continue
				}
				argp := 1
				disabledLink := false
				for argp < len(args) {
					switch args[argp] {
					case "target_blank":
						privateLink.Target = "_blank"
						privateLink.TargetEnabled = true
					case "icon":
						argp++
						if argp < len(args) {
							privateLink.IconName = args[argp]
							privateLink.IconEnabled = true
						}
					case "disabled":
						disabledLink = true
					default:
						return h.Errf("auth backend %s subdirective %s has unsupported key %s", subDirective, title, args[argp])
					}
					argp++
				}
				if disabledLink {
					continue
				}
				portal.UI.PrivateLinks = append(portal.UI.PrivateLinks, privateLink)
			}
		case "custom":
			args := strings.Join(util.FindReplaceAll(repl, h.RemainingArgs()), " ")
			args = strings.TrimSpace(args)
			switch {
			case strings.HasPrefix(args, "css path"):
				portal.UI.CustomCSSPath = strings.ReplaceAll(args, "css path ", "")
			case strings.HasPrefix(args, "css"):
				portal.UI.CustomCSSPath = strings.ReplaceAll(args, "css ", "")
			case strings.HasPrefix(args, "js path"):
				portal.UI.CustomJsPath = strings.ReplaceAll(args, "js path ", "")
			case strings.HasPrefix(args, "js"):
				portal.UI.CustomJsPath = strings.ReplaceAll(args, "js ", "")
			case strings.HasPrefix(args, "html header path"):
				args = strings.ReplaceAll(args, "html header path ", "")
				b, err := ioutil.ReadFile(args)
				if err != nil {
					return h.Errf("%s %s subdirective: %s %v", rootDirective, subDirective, args, err)
				}
				for k, v := range ui.PageTemplates {
					headIndex := strings.Index(v, "<meta name=\"description\"")
					if headIndex < 1 {
						continue
					}
					v = v[:headIndex] + string(b) + v[headIndex:]
					ui.PageTemplates[k] = v
				}
			case args == "":
				return h.Errf("%s %s directive has no value", rootDirective, subDirective)
			default:
				return h.Errf("%s directive %q is unsupported", rootDirective, args)
			}
		case "static_asset":
			args := util.FindReplaceAll(repl, h.RemainingArgs())
			if len(args) != 3 {
				return h.Errf("auth backend %s subdirective %s is malformed", rootDirective, subDirective)
			}
			prefix := "assets/"
			assetURI := args[0]
			assetContentType := args[1]
			assetPath := args[2]
			if !strings.HasPrefix(assetURI, prefix) {
				return h.Errf("auth backend %s subdirective %s URI must be prefixed with %s, got %s",
					rootDirective, subDirective, prefix, assetURI)
			}
			if err := ui.StaticAssets.AddAsset(assetURI, assetContentType, assetPath); err != nil {
				return h.Errf("auth backend %s subdirective %s failed: %s", rootDirective, subDirective, err)
			}
		case "disable":
			args := util.FindReplaceAll(repl, h.RemainingArgs())
			if err := portal.UI.DisablePage(args); err != nil {
				return h.Errf("auth backend %s subdirective %s is malformed: %v", rootDirective, subDirective, err)
			}
		default:
			return h.Errf("unsupported subdirective for %s: %s", rootDirective, subDirective)
		}
	}

	return nil
}
