# Contributing Guidelines

## Contributor License Agreements

I'd love to accept your pull request! Before I can take them, we have to jump a
couple of legal hurdles.

***NOTE***: Only original source code from you and other people that have
signed the CLA can be accepted into the main repository.

Please fill out either the individual or corporate Contributor License Agreement (CLA).
* If you are an individual writing original source code and you're sure you own the
  intellectual property, then you'll need to sign an [individual CLA](/assets/cla/individual_cla.md).
* If you work for a company that wants to allow you to contribute your work, then
  you'll need to sign a [corporate CLA](/assets/cla/corporate_cla.md).

Follow either of the two links above to access the appropriate CLA. Next,
accept the CLA in the following way.

For Individual CLA:
1. Review the Individual CLA provided in `assets/cla/individual_cla.md`
2. Consent to the CLA by adding your name and email address to
  the `assets/cla/consent.yaml` file.

For Corporate CLA:
1. Review the Corporate CLA provided in `assets/cla/corporate_cla.md`
2. Consent to the CLA by adding your name and email address, and business
  name to the `assets/cla/consent.yaml` file.

## Pull Request Checklist

Before sending your pull requests, make sure you followed this list.

1. Open an issue to discuss your PR
2. Ensure you read appropriate Contributor License Agreement (CLA)
3. Run unit tests

## Development Environment

The contribution to this project requires setting up a development
environment. The following steps allow developers to test their
setup using local source code.

First, designate directory for building, e.g. `tmpdev`.

```bash
mkdir -p ~/tmpdev
cd ~/tmpdev
```

Second, fork the following repositories in Github into to your own Github
handle, e.g. `anonymous`:

* `https://github.com/greenpau/caddy-security` => `https://github.com/anonymous/caddy-security`
* `https://github.com/greenpau/go-authcrunch` => `https://github.com/anonymous/go-authcrunch`

Provided you are in `tmpdev` directory, clone the forked repositories:

```bash
git clone git@github.com:anonymous/caddy-security.git
git clone git@github.com:anonymous/go-authcrunch.git
```

Next, browse to `caddy-security` and run the following `make` command to install
various dependencies:

```bash
cd caddy-security
make dep
```

Next, modify `go.mod` in `github.com/greenpau/caddy-security`. Include
`replace` directives to instruct `go` using local directories, as opposed
to follow Github versions.

Note: the referenced versions must match.

```
module github.com/greenpau/caddy-security

go 1.16

require (
    github.com/greenpau/go-authcrunch v1.0.35
)

replace github.com/greenpau/go-authcrunch v1.0.35 => /home/greenpau/dev/go/src/github.com/greenpau/go-authcrunch
```

Then, modify `Makefile` such that that replacement passes to `xcaddy` builder:

```bash
        @mkdir -p ../xcaddy-$(PLUGIN_NAME) && cd ../xcaddy-$(PLUGIN_NAME) && \
                xcaddy build $(CADDY_VERSION) --output ../$(PLUGIN_NAME)/bin/caddy \
                --with github.com/greenpau/caddy-security@$(LATEST_GIT_COMMIT)=$(BUILD_DIR) \
                --with github.com/greenpau/go-authcrunch@v1.0.35=/home/greenpau/dev/go/src/github.com/greenpau/go-authcrunch
```

Once all the necessary packages are installed, you should be ready to compile
using the local source code. Run:

```bash
make
```

The above make command creates `xcaddy-caddy-security` directory in `tmpdev`.
Then, it starts building `caddy` and referencing locally sources plugins.

After the build, the resultant binary will be in `bin/` directory.
You can then test it with your own configuration files.

```bash
bin/caddy run -config assets/config/Caddyfile | jq
```

Additionally, you should be able to run tests:

```bash
make ctest
```
