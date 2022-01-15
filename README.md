# caddy-security

<a href="https://github.com/greenpau/caddy-security/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-security/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-security" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>
<a href="https://caddyserver.com/docs/modules/git" target="_blank"><img src="https://img.shields.io/badge/caddydocs-git-green.svg"></a>

Security App and Plugin for [Caddy v2](https://github.com/caddyserver/caddy).

Please see other plugins:
* [caddy-trace](https://github.com/greenpau/caddy-trace)
* [caddy-systemd](https://github.com/greenpau/caddy-systemd)

<!-- begin-markdown-toc -->
## Table of Contents

* [Overview](#overview)
* [Getting Started](#getting-started)

<!-- end-markdown-toc -->

## Overview

The `caddy-security` **app** allows managing authentication portal,
authorization security policy and credentials. The **plugin**
enforces the security policy on endpoints with `authorize` keyword
and serves authentication portal with `authenticate` keyword.

## Getting Started

The configuration happens in Caddy's 
[**global options block**](https://caddyserver.com/docs/caddyfile/options).


### Credentials

The following configuration adds SMTP credentials to security app.
Subsequently, the app and plugin will be able to use the credentials.

```
{
  security {
    credentials email smtp.outlook.com {
      address outlook.office365.com:993
      protocol smtp
      username {env.SMTP_USERNAME}
      password {env.SMTP_PASSWORD}
    }
  }
}
```

### Authentication

The following configuration adds authentication portal.

```
{
  security {
    authentication portal myportal {
      crypto default token lifetime 3600
      crypto key sign-verify {env.JWT_SECRET}
      backend local {env.HOME}/.local/caddy/users.json local
      cookie domain myfiosgateway.com
      ui {
        links {
          "My Website" https://assetq.myfiosgateway.com:8443/ icon "las la-star"
          "My Identity" "/whoami" icon "las la-user"
        }
      }
      transform user {
        match origin local
        action add role authp/user
        ui link "Portal Settings" /settings icon "las la-cog"
      }
    }
  }
}

auth.myfiosgateway.com {
  authenticate * with myportal
}
```

### Authorization

The following configuration adds authorization functionality and handlers.

```
{
  security {
    authorization policy mypolicy {
      set auth url https://auth.myfiosgateway.com/
      crypto key verify {env.JWT_SECRET}
      allow roles authp/admin authp/user
    }
  }
}


www.myfiosgateway.com {
    authorize with mypolicy
	root * {env.HOME}/public_html
	file_server
}
```
