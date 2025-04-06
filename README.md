# acme

## Name

*acme* - enables dynamic DNS updates via HTTP API with authentication for ACME DNS-01 challenges.

## Description

The *acme* plugin provides a dynamic DNS API server for handling ACME DNS-01 challenges. It's designed to be compatible with [go-acme (Lego)](https://go-acme.github.io/lego/dns/httpreq/index.html) which is used by Traefik and other popular ACME clients. This plugin only answers queries for `_acme-challenge` subdomains and provides a REST API for dynamically updating the corresponding TXT records, which are used by ACME clients to validate domain ownership for certificate issuance. All other DNS queries are passed to the next plugin in the chain.

## Features

- **RESTful HTTP API**: Simple REST API for managing TXT records
- **Flexible Authentication**: Support for Basic Auth, API headers, and query parameters
- **IP-based Access Control**: Restrict API access by IP address or CIDR ranges
- **Account Management**: Create and manage accounts with domain restrictions
- **Multiple Storage Options**: SQLite database with in-memory option (coming soon)
- **Go-ACME Compatibility**: Works with Lego library used by Traefik and other tools
- **Proxy Support**: Header-based client IP detection for reverse proxy setups
- **ACME-Subdomain Specific**: Only answers `_acme-challenge` queries, passing all others to the next plugin
- **Selective Fallthrough**: Configurable fallthrough behavior for ACME challenge domains
- **Wildcard Certificate Support**: Easily manage wildcard certificates with DNS-01 challenges

## Syntax

```
acme [ZONES...] {
    [endpoint ADDRESS]
    [db TYPE PATH]
    [extract_ip_from_header HEADER]
    [allowfrom [CIDR...]]
    [require_auth]
    [account USERNAME PASSWORD [ZONE] [CIDR...]]
    [enable_registration]
    [fallthrough [ZONES...]]
}
```

* **ZONES** zones the *acme* plugin will be authoritative for. If empty, the zones from the server block are used.
* `endpoint` specifies the **ADDRESS** for the API server. If not specified, the API server will not be started and the database will operate in read-only mode (useful when delegating a zone but still want to use the plugin for DNS-01 challenges).
* `db` selects the database backend:
  * `badger` with a **PATH** to the database directory (default: "acme_db_data" in the current directory).
  * `sqlite` with a **PATH** to the database file. This requires coredns to be compiled with `CGO_ENABLED=1`.
  * `memory` for an in-memory database (coming soon).
* `extract_ip_from_header` extracts the client IP address from the specified HTTP header instead of using the TCP remote address.
* `allowfrom` lists IP addresses or CIDR ranges allowed to access the API globally.
* `require_auth` requires authentication for API record updates. When enabled, username/password authentication is required for updating or deleting TXT records. When disabled (default), records can be updated without authentication, but global IP restrictions from `allowfrom` are still enforced if set.
* `account` registers an account with:
  * **USERNAME** - User identifier for authentication
  * **PASSWORD** - Password for authentication
  * [**ZONE**] - Optional domain name zone the account is authorized to manage
  * [**CIDR...**] - Optional list of IP addresses or CIDR ranges allowed to access with this account
* `enable_registration` allows new account registrations via the API.
* `fallthrough [ZONES...]` routes queries to the next plugin when a request is for a TXT record of `_acme-challenge` subdomain, but no record is found. If specific **ZONES** are listed, fallthrough will only happen for those specific zones. Without this option, the plugin will respond with NXDOMAIN if no record is found.

**Important Notes:**
- This plugin only answers queries for `_acme-challenge` subdomains - all other queries are passed to the next plugin
- Always include the trailing dot (`.`) after domain names to ensure proper fully qualified domain names (FQDNs)
- When no IP restrictions are specified for an account or globally, access will be allowed to all by default. Make sure to only expose the API to trusted networks in this case.

## Examples

Basic configuration with default settings:

```
auth.example.org {
    acme {
        endpoint 0.0.0.0:8080
        fallthrough
    }
    forward . 8.8.8.8
}
```

DNS-only mode (no API server):

```
auth.example.org {
    acme {
        db badger /var/lib/coredns/acme.db
        fallthrough
    }
    forward . 8.8.8.8
}
```

Secure production setup with TLS and multiple accounts for different zones:

```
example.org {
    tls /etc/coredns/certs/cert.pem /etc/coredns/certs/key.pem

    acme subdomain.example.org {
        db sqlite /var/lib/coredns/acme.db
        endpoint 0.0.0.0:8443
        extract_ip_from_header X-Forwarded-For
        allowfrom 10.0.0.0/8 192.168.0.0/16
        require_auth
        account user1 strong-password1 one.subdomain.example.org
        account user2 strong-password2 two.subdomain.example.org 10.1.0.0/16 192.168.1.0/24
    }

    # Logging
    log {
        class error
    }

    # Forward regular DNS queries
    forward . 1.1.1.1 8.8.8.8 {
        policy random
        health_check 10s
    }
}
```

## Build

This plugin can be compiled as part of CoreDNS by adding the following line to the `plugin.cfg` file:

```
acme:github.com/ShrewdHydra/coredns-acme
```

Then compile CoreDNS:

```sh
go generate
go build
```

Or using make:

```sh
make
```

## API Usage

The plugin provides a RESTful API for managing DNS records for ACME DNS-01 challenges, compatible with the Lego httpreq provider used by Traefik and other tools.

### Endpoints

#### Account Registration
```
POST /register
```

**Request:**
```json
{
  "username": "username",
  "password": "password",
  "zone": "example.org"
}
```

**Response:**
```json
{
  "username": "username",
  "password": "password",
  "zone": "example.org"
}
```

#### Present TXT Record
```
POST /present
```

**Request:**
```json
{
  "fqdn": "_acme-challenge.example.org",
  "txt": "acme-challenge-value"
}
```

**Response:**
```json
{
  "success": true
}
```

#### Cleanup TXT Record
```
POST /cleanup
```

**Request:**
```json
{
  "fqdn": "_acme-challenge.example.org",
  "txt": "acme-challenge-value"
}
```

**Response:**
```json
{
  "success": true
}
```

#### Health Check
```
GET /health
```

**Response:**
```
OK
```

### Traefik Integration

You can configure Traefik to use the ACME plugin by adding the following to your `traefik.yml` file:

```yaml
# Static configuration
certificatesResolvers:
  myresolver:
    acme:
      email: your-email@example.com
      storage: /path/to/acme.json
      dnsChallenge:
        provider: httpreq
        resolvers:
          - "8.8.8.8:53"
          - "1.1.1.1:53"

# Environment variables for the httpreq provider
environment:
  - HTTPREQ_ENDPOINT=https://auth.example.org:8080
  - HTTPREQ_USERNAME=your_username
  - HTTPREQ_PASSWORD=your_password
```

## Metrics

If monitoring is enabled (via the *prometheus* directive) the following metrics are exported:

* `coredns_acme_request_count_total{server}` - counter of DNS requests served by the *acme* plugin, labeled by DNS server address
* `coredns_acme_api_request_count_total{server, endpoint}` - counter of API requests to the *acme* plugin, labeled by HTTP server address and endpoint name (register, present, cleanup, health)

The `server` label indicates which server handled the request. See the *metrics* plugin for details.

## Security Considerations

- Use HTTPS for the API server in production
- Set up proper IP restrictions to prevent unauthorized access
- Follow the principle of least privilege when setting up accounts
- Generate strong random passwords for API access
- When no IP restrictions are specified, access will be allowed to all by default. Make sure to only expose the API to trusted networks in this case.
- Ensure domain names in configuration end with a trailing dot (`.`) to use proper FQDNs

## See Also

* [CoreDNS](https://coredns.io)
* [Let's Encrypt](https://letsencrypt.org)
* [ACME Protocol](https://tools.ietf.org/html/rfc8555)
* [Lego's HTTP Request provider](https://go-acme.github.io/lego/dns/httpreq/)
* [Traefik](https://doc.traefik.io/traefik/)
* [joohoi's ACME Server](https://github.com/joohoi/acme-dns) which was the inspiration for this plugin

## License

MIT License

## Troubleshooting

### Common Issues and Solutions

#### API Access Denied
- Verify the client IP is in the allowed CIDR ranges for the account
- Check if the `extract_ip_from_header` setting is properly configured for proxy environments
- Ensure the domain being updated matches the account's allowed zones and is part of the zone the plugin is authoritative for
- If you've enabled `require_auth`, authentication is mandatory for API record updates, so confirm you're using the correct credentials
- If `require_auth` is disabled, you can update records without authentication, but global IP restrictions (set using `allowfrom`) still apply
- If you cannot access the API at all, check if you've configured an `endpoint` - without one, the API server doesn't start (DNS-only mode)

#### DNS-Only Mode
- If you don't specify an `endpoint`, the plugin will operate in DNS-only mode where:
  - No API server is started, so record updates via API are not possible
  - The database is opened in read-only mode at the driver level
  - This prevents any write operations, ensuring the database integrity
  - This is useful when you need to serve DNS challenges from a delegated zone
  - Make sure to populate the database with records from a CoreDNS instance that has the API enabled when using this mode

#### Database Issues
- Verify the SQLite path is writable by the CoreDNS process
- Check for database corruption by running:
  ```bash
  sqlite3 /path/to/acme.db "PRAGMA integrity_check;"
  ```
- If using DNS-only mode, ensure the database was populated with records by a CoreDNS instance with API enabled

#### DNS Propagation Problems
- If using a CNAME record, ensure `_acme-challenge.yourdomain.com` points to the correct subdomain
- Check that the ACME client is using the correct API endpoint and credentials
- Verify CoreDNS is correctly forwarding non-ACME queries to upstream DNS servers

#### Certificate Issuance Failures
- Review the ACME client logs for specific error messages
- Ensure the TXT record is being properly set through the API
- Verify the domain's DNS is correctly delegated to your CoreDNS server
- Check that the ACME challenge subdomain is accessible from the internet
