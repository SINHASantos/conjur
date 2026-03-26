# frozen_string_literal: true

module Conjur
  module Rack
    # AuthPaths defines which URL paths require token authentication and which do not.
    #
    # These constants live in the conjur-rack gem rather than in the Rails initializer
    # (config/initializers/rack_middleware.rb) to simplify testing: the initializer
    # cannot be loaded in isolation without booting the full Rails stack, which makes
    # unit-testing the path rules impossible. Keeping the constants here — in the plain
    # Ruby gem that owns the Authenticator middleware — lets spec/rack/auth_paths_spec.rb
    # exercise every route case fast, without Rails, and alongside the middleware itself.
    module AuthPaths
      # Paths that bypass authentication entirely. These endpoints accept credentials
      # (or require none at all) and so cannot demand a prior token.
      EXCEPT = [
        %r{^/$},
        %r{^/authenticators/?$},
        %r{^/assets/},
        %r{^/host_factories/hosts/?$},

        # Every authenticate endpoint — the caller is proving identity here, so
        # there is no pre-existing token to validate.
        # Covers: /authn/:account/:id/authenticate
        %r{^/authn/.*/authenticate/?$},
        # Covers: /authn-{type}/.../:account/authenticate (jwt, oidc, ldap, gcp, k8s, etc.)
        %r{^/authn-[^/]+/.*/authenticate/?$},

        # Covers: /authn/:account/login
        %r{^/authn/.*/login/?$},
        # Covers: /authn-{type}/:service_id/:account/login
        %r{^/authn-[^/]+/.*/login/?$},

        # OIDC provider discovery — required open for the UI
        %r{^/authn-oidc/.*/providers/?$}
      ].freeze

      # Paths where a token is used if present, but its absence is not an error.
      OPTIONAL = [
        %r{^/public_keys/},
        # API key rotation can use basic auth or an authz token
        %r{^/authn/.*/api_key/?$},
        %r{^/authn-[^/]+/.*/api_key/?$},

        # Password Updates can use basic auth or an authz token
        %r{^/authn/.*/password/?$},

        # Cert injection uses mTLS to secure connection so we don't force auth
        %r{^/authn-k8s/.*/inject_client_cert/?$}
      ].freeze
    end
  end
end
