# caddy-security

<a href="https://github.com/greenpau/caddy-security/actions/" target="_blank"><img src="https://github.com/greenpau/caddy-security/workflows/build/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/caddy-security" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>
<a href="https://caddy.community" target="_blank"><img src="https://img.shields.io/badge/community-forum-ff69b4.svg"></a>
<a href="https://caddyserver.com/docs/modules/security" target="_blank"><img src="https://img.shields.io/badge/caddydocs-security-green.svg"></a>

Security App and Plugin for [Caddy v2](https://github.com/caddyserver/caddy). It includes:

* Authentication Plugin for implementing Form-Based, Basic, Local, LDAP, OpenID
  Connect, OAuth 2.0, SAML Authentication
* Authorization Plugin for HTTP request authorization based on JWT/PASETO tokens
* Credentials Plugin for managing credentials for various integrations

Please show your **appreciation for this work** and :star: :star: :star:

Please consider **sponsoring this project**!

Please ask questions either here or via LinkedIn. I am happy to help you! @greenpau

**Documentation**: [authp.github.io](https://authp.github.io)

**Security Policy**: [SECURITY.md](SECURITY.md)

Please see other plugins:
* [caddy-trace](https://github.com/greenpau/caddy-trace)
* [caddy-systemd](https://github.com/greenpau/caddy-systemd)
* [caddy-git](https://github.com/greenpau/caddy-git)

<!-- begin-markdown-toc -->
## Table of Contents

* [Overview](#overview)
* [Getting Started](#getting-started)
  * [Credentials](#credentials)
  * [Messaging](#messaging)
  * [Authentication](#authentication)
  * [Authorization](#authorization)
* [User Interface](#user-interface)
  * [User Login](#user-login)
  * [Portal](#portal)
  * [User Identity (whoami)](#user-identity-whoami)
  * [User Settings](#user-settings)
    * [Password Management](#password-management)
    * [Add U2F Token (Yubico)](#add-u2f-token-yubico)
    * [Add Authenticator App](#add-authenticator-app)
  * [Multi-Factor Authentication](#multi-factor-authentication)

<!-- end-markdown-toc -->

## Overview

The `caddy-security` **app** allows managing authentication portal,
authorization security policy and credentials. The **plugin**
enforces the security policy on endpoints with `authorize` keyword
and serves authentication portal with `authenticate` keyword.

The app and plugin use Authentication, Authorization, and
Accounting (AAA) Security Functions (SF) from
[github.com/greenpau/go-authcrunch](https://github.com/greenpau/go-authcrunch).

## Getting Started

The configuration happens in `Caddyfile`'s 
[**global options block**](https://caddyserver.com/docs/caddyfile/options).

* **Setting Up Local Authentication**: [Video](https://www.youtube.com/watch?v=k8tbbffMGZk)
  and [Config Gist](https://gist.github.com/greenpau/dbfadd3c9fee21dbb0a0d3902a8d0ec0)
* **Login with App Authenticator and Yubico U2F**: [Video](https://youtu.be/poOkq_jb1B0)
* **Customizing Caddy Auth Portal UI**: [Video](https://www.youtube.com/watch?v=20XOn-RBIX0&t=0s)
* **Caddy Authorize: Authorizing HTTP Requests**: [Video](https://www.youtube.com/watch?v=Mxbjfv47YiQ&t=1s&vq=hd1080)

Download Caddy with the plugins enabled:
* <a href="https://caddyserver.com/api/download?os=windows&arch=amd64&p=github.com%2Fgreenpau%2Fcaddy-security%40v1.1.14&p=github.com%2Fgreenpau%2Fcaddy-trace%40v1.1.8" target="_blank">windows/amd64</a>
* <a href="https://caddyserver.com/api/download?os=linux&arch=amd64&p=github.com%2Fgreenpau%2Fcaddy-security%40v1.1.14&p=github.com%2Fgreenpau%2Fcaddy-trace%40v1.1.8" target="_blank">linux/amd64</a>

### Credentials

The following configuration adds SMTP credentials to security app.
Subsequently, the app and plugin will be able to use the credentials
in its messaging configuration.

```
{
  security {
    credentials root@localhost {
      username {env.SMTP_USERNAME}
      password {env.SMTP_PASSWORD}
    }
  }
}
```

### Messaging

The following configuration sets up email messaging provider. It will use
the previously configured `root@localhost` credentials.

```
{
  security {
    messaging email provider localhost-smtp-server {
      address 127.0.0.1:1025
      protocol smtp
      credentials root@localhost
      sender root@localhost "My Auth Portal"
      bcc greenpau@localhost
    }
  }
}
```

It can also be "passwordless":

```
{
  security {
    messaging email provider localhost-smtp-server {
      address 127.0.0.1:1025
      protocol smtp
      passwordless
      sender root@localhost "My Auth Portal"
      bcc greenpau@localhost
    }
  }
}
```

It may support TLS:

```
{
  security {
    messaging email provider localhost-smtp-server {
      address 127.0.0.1:1025
      protocol smtps
      passwordless
      sender root@localhost "My Auth Portal"
      bcc greenpau@localhost
    }
  }
}
```

### Authentication

The following configuration adds authentication portal.

```
{
  security {

    local identity store localdb {
      realm local
      path {$HOME}/.local/caddy/users.json
    }

    authentication portal myportal {
      crypto default token lifetime 3600
      crypto key sign-verify {env.JWT_SECRET}
      enable identity store localdb
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

## User Interface

### User Login

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_01.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_02.png)

### Portal

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_03.png)

### User Identity (whoami)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_04.png)

### User Settings

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_05.png)

#### Password Management

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_06.png)

#### Add U2F Token (Yubico)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_07.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_08.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_09.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_10.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_11.png)

#### Add Authenticator App

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_12.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/ms_mfa_app_add_account.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/ms_mfa_app_new_account.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/ms_mfa_app_scan_qrcode.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_13.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_14.png)

### Multi-Factor Authentication

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_15.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_16.png)

![](https://raw.githubusercontent.com/authp/authp.github.io/main/docs/authenticate/images/authp_demo_17.png)
