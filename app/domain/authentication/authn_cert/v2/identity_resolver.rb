# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      # This class is responsible for resolving a role identifier based on the
      # provided X.509 certificate attributes.
      #
      # The inherited Base::IdentityResolver returns the role identifier provided
      # in request parameters if one exists. If one does not exists, it calls
      # `identity_from_credential`, which performs our custom X.509 attribute
      # mapping.
      class IdentityResolver < Authentication::Base::IdentityResolver

        # Override the base `call` method to check authenticator-specific config
        # for request-based or credential-based role ID derivation.
        #
        # @param [String] id - the role ID supplied via request parameters
        # @param [Hash] credential - decoded credential attributes
        # @return [String] - a Conjur role ID
        def call(id: nil, credential: nil)
          host_mode = @authenticator.variables[:host_mode]
          case host_mode
          when 'spiffe'
            @logger.debug(LogMessages::Authentication::DerivingRoleID.new(@authenticator.identifier))
            identity_from_credential(credential).bind do |identity|
              identity_from_role_id(identity)
            end
          when 'request', '', nil
            @logger.debug(LogMessages::Authentication::ProvidedRoleID.new(@authenticator.identifier))
            identity_from_role_id(
              formatted_id(id)
            )
          else
            @failure.new(
              "Invalid host-mode",
              exception: Errors::Authentication::Certificate::InvalidConfig.new("Invalid host mode: #{host_mode}"),
              status: :unauthorized
            )
          end
        end

        # Maps a set of X.509 certificate attributes to a Conjur role identifier.
        # Specifically, the set of certificate attributes must properly
        # represent a well-formed X.509 SPIFFE Verifiable Identity Document (SVID),
        # and the Conjur role identifier is constructed from the SPIFFE ID
        # included in the SVID URI SANs.
        #
        # This function validates X.509 SVID attributes and SPIFFE IDs by
        # implementing the requirements listed in the SPIFFE ID standards.
        # https://github.com/spiffe/spiffe/blob/09f06142427febcdd384554cbb2b9f223dcdaec0/standards/SPIFFE-ID.md
        #
        # @attribute [AuthenticatorsV2::CertAuthenticatorType] authenticator
        # @param [Hash] credential - a map of X.509 certificate attributes
        #
        # @return [String] - a Conjur role ID
        def identity_from_credential(credential)
          get_trust_domain(authenticator: @authenticator).bind do |trust_domain|
            check_identity_path(authenticator: @authenticator).bind do
              extract_uri_san(credential: credential).bind do |uri_san|
                check_san_is_valid_uri(uri_san: uri_san).bind do |uri|
                  check_uri_is_spiffe_id(parsed_uri: uri).bind do |spiffe_id|
                    unless spiffe_id.host == trust_domain
                      return @failure.new(
                        "Trust domain mismatch",
                        exception: Errors::Authentication::Certificate::TrustDomainMismatch.new(uri_san, trust_domain),
                        status: :unauthorized
                      )
                    end

                    # Currently, certificate authentication only supports host
                    # type roles, and not users.
                    @success.new("host/#{spiffe_id.path.sub(%r{^/}, '')}")
                  end
                end
              end
            end
          end
        end

        private

        def get_trust_domain(authenticator:)
          trust_domain = authenticator.variables[:trust_domain]
          if trust_domain.nil?
            return @failure.new(
              "SPIFFE trust domain missing from certificate authenticator configuration",
              exception: Errors::Authentication::Certificate::NoTrustDomain.new,
              status: :unauthorized
            )
          end

          unless valid_trust_domain?(trust_domain)
            return @failure.new(
              "SPIFFE trust domain is invalid",
              exception: Errors::Authentication::Certificate::InvalidTrustDomain.new,
              status: :unauthorized
            )
          end

          @success.new(trust_domain)
        end

        def valid_trust_domain?(trust_domain)
          return false if trust_domain.empty?

          trust_domain.match?(/\A[a-z0-9.\-_]+\z/)
        end

        def check_identity_path(authenticator:)
          identity_path = authenticator.variables[:identity_path]
          if identity_path.blank?
            return @failure.new(
              "Certificate authenticator operating in SPIFFE mode must include workload identity path",
              exception: Errors::Authentication::Certificate::NoIdentityPath.new,
              status: :unauthorized
            )
          end

          @success.new('identity-path present')
        end

        def extract_uri_san(credential:)
          uri_sans = credential['sans_uri']
          count = 0 if uri_sans.nil?
          count = uri_sans.length unless uri_sans.nil?
          if count != 1
            return @failure.new(
              "Client certificate must contain exactly 1 URI SAN",
              exception: Errors::Authentication::Certificate::BadURISANCount.new(count),
              status: :unauthorized
            )
          end

          @success.new(uri_sans.first)
        end

        def check_san_is_valid_uri(uri_san:)
          # Parse and validate URI form according to the SPIFFE ID standard.
          # https://github.com/spiffe/spiffe/blob/09f06142427febcdd384554cbb2b9f223dcdaec0/standards/SPIFFE-ID.md
          parsed_uri = URI.parse(uri_san)

          if parsed_uri.query.present?
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(uri_san, "must not include a query component"),
              status: :unauthorized
            )
          end
          if parsed_uri.fragment.present?
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(uri_san, "must not include a fragment component"),
              status: :unauthorized
            )
          end
          # URI instances return default port values for well-defined schemes,
          # even if one is not directly included in the original string.
          #   'http://trust.com' -> 80
          #   'https://trust.com' -> 443
          # We only care if the port was included in the original string found
          # in the client certificate.
          if parsed_uri.port.present? && uri_san.include?(":#{parsed_uri.port}")
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(uri_san, "must not include a port"),
              status: :unauthorized
            )
          end
          if parsed_uri.userinfo.present?
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(uri_san, "must not include userinfo"),
              status: :unauthorized
            )
          end

          @success.new(parsed_uri)
        rescue URI::InvalidURIError => e
          @failure.new(
            "Malformed SPIFFE ID",
            exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(uri_san, "must be valid URI: #{e}"),
            status: :unauthorized
          )
        end

        def check_uri_is_spiffe_id(parsed_uri:)
          # Validate URI, specifically in its representation of a valid SPIFFE
          # ID according to the SPIFFE ID standard.
          # https://github.com/spiffe/spiffe/blob/09f06142427febcdd384554cbb2b9f223dcdaec0/standards/SPIFFE-ID.md
          unless parsed_uri.scheme == 'spiffe'
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(parsed_uri.to_s, "scheme must be 'spiffe://'"),
              status: :unauthorized
            )
          end

          unless valid_trust_domain?(parsed_uri.host)
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(parsed_uri.to_s, "malformed trust domain"),
              status: :unauthorized
            )
          end

          workload_id = parsed_uri.path
          if workload_id.blank?
            return @failure.new(
              "Malformed SPIFFE ID",
              exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(parsed_uri.to_s, "must include workload ID"),
              status: :unauthorized
            )
          end
          workload_id.sub(%r{^/}, '').split('/').each do |segment|
            unless valid_path_segment?(segment)
              return @failure.new(
                "Malformed SPIFFE ID",
                exception: Errors::Authentication::Certificate::MalformedSPIFFEID.new(parsed_uri.to_s, "invalid path segment '#{segment}'"),
                status: :unauthorized
              )
            end
          end

          @success.new(parsed_uri)
        end

        def valid_path_segment?(segment)
          return false if segment.empty?
          return false if segment == '.'
          return false if segment == '..'

          segment.match?(/\A[a-zA-Z0-9.\-_]+\z/)
        end
      end
    end
  end
end
