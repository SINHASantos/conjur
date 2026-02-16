# Deploying the SaaS Authenticator Service Alongside Conjur

This section describes how to obtain, deploy and configure the **SaaS Authenticator Service** so it can be used by Conjur

---

## Overview

The **SaaS Authenticator Service** is a stateless HTTP service that Conjur uses to validate credentials (e.g., for certificate authentication).  
Users are responsible for deploying and managing the service in their own environment. 

---

## Getting the Authenticator Service Binary

The authenticator binary will be included with Conjur releases and made available through GitHub releases.

---

## Security Best Practices

### Network Isolation: The SaaS Authenticator should only be accessible to Conjur
- Use localhost for same-host deployments (on default HTTP allowlist)
- Use pod-local networking in Kubernetes (add service name to HTTP allowlist)
- Use Docker internal networks in Docker Compose (add service name to HTTP allowlist)

### Connection Security Model:
- Trusted networks (HTTP): Use HTTP only within trusted boundaries.
- Untrusted networks (HTTPS): Use HTTPS with certificate verification.
- No bypass: HTTPS certificate verification cannot be disabled. If you need unencrypted communication, use HTTP with an explicit allowlist entry.

### Firewall 
Do not expose SaaS Authenticator ports publicly. Unnecessary exposure opens the door to potential denial of service.

---

## Conjur Configuration Parameters

In order to enable and configure Conjur to use the Authenticator Service, a set of environment variables must be set.

### Required
| Parameter                                      | Purpose                                                                                                                         | Example                  |
|------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|--------------------------|
| `CONJUR_FEATURE_AUTHENTICATOR_SERVICE_ENABLED` | Feature flag that enables the Authenticator Service                                                                             | true                     |
| `CONJUR_AUTHENTICATOR_SERVICE_URL`             | URL of your authenticator service (HTTP or HTTPS). Must be HTTPS unless allow‑listed.                                           | http://auth-service:8080 |
| `CONJUR_AUTHENTICATOR_SERVICE_HTTP_ALLOWLIST`  | Comma-separated list of hostnames/IPs allowed for HTTP communication with the authenticator service. Required if using HTTP.    | auth-service             |
| `CONJUR_AUTHENTICATOR_SERVICE_CA_CERT`         | A path to CA certificate that Conjur uses to validate the TLS certificate of the Authenticator Service. Required if using HTTPS | /path/to/ca.pem          |

---

## Deployment

Common deployment approaches include:

- As a Docker Compose service within a trusted network boundary
- As a standalone HTTP(S) service
- As a sidecar container (Kubernetes)
---

### Authenticator Service configuration

The Authenticator Service binary has to be run with a configuration file provided as a command-line argument. The absolute minimum configuration has to include the `port` and `http_timeout` parameters.

The configuration file is a json file with the following structure:


```json
{
  // Enables debug mode
  "debug": true,

  // Sets the HTTP server listening port
  "port": "8080",

  // Sets the HTTP server timeout
  "http_timeout": "10s",

  // Enables the DataDog profiler
  "enable_profiler": false,

  // Enables the DataDog tracer
  "enable_tracer": true,

  // Sets the environment variable for profiler and tracer
  "environment": "production",

  // Sets the version of the application
  "version": "1.2.3",

  // Feature flag for the legacy JWT behavior allowing missing issuer/audience values
  "allow_missing_jwt_claims": false
}
```

Assuming your config file is named `authenticator-config.json`, you can run the Authenticator Service binary as follows:

```bash
$ ./authenticator-service-binary -c /path/to/authenticator-config.json
```

###  Docker Compose Example

Assuming you have created a Dockerfile for the Authenticator Service, you can add it as a service in your `docker-compose.yml` and configure Conjur to communicate with it over HTTP within the Docker network:

```yaml
services:
  conjur:
    image: cyberark/conjur
    environment:
      CONJUR_FEATURE_AUTHENTICATOR_SERVICE_ENABLED: 'true'
      CONJUR_AUTHENTICATOR_SERVICE_URL: 'http://auth-service:8080'
      CONJUR_AUTHENTICATOR_SERVICE_HTTP_ALLOWLIST: 'auth-service'
  #...

  auth-service:
     build:
      context: ./auth-service
      dockerfile: Dockerfile
      # No ports exposed - only accessible via Docker network
      
```

### Compatibility Matrix

The following table shows the compatibility between Conjur OSS and the SaaS Authenticator Service:

| SaaS Authenticator / Conjur OSS | 1.25.0+ |
|---------------------------------|---------|
| 1.395.0+                        | ✓       |
