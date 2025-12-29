# frozen_string_literal: true

require 'cgi'

module Authentication
  module AuthnCert
    module V2
      # Strategy implementations are responsible for:
      #   1. Performing credential validation
      #   2. Deconstructing the credential into a set of usable attributes
      #   3. Resolving a Conjur role ID from the request context
      class Strategy
        CERTIFICATE_HEADER = 'X-SSL-Client-Certificate'

        def initialize(
          authenticator:,
          saas_auth_client: SaasAuthClient,
          identity_resolver: Authentication::AuthnCert::V2::IdentityResolver,
          authenticator_credential_validation: Authentication::AuthnCert::V2::Validations::AuthenticatorCredentialValidation,
          logger: Rails.logger
        )
          @authenticator = authenticator
          @saas_auth_client = saas_auth_client
          @identity_resolver = identity_resolver
          @authenticator_credential_validation = authenticator_credential_validation
          @logger = logger

          @success = Responses::Success
          @failure = Responses::Failure
        end

        def callback(request_headers:, parameters: nil, request_body: nil) # rubocop:disable Lint/UnusedMethodArgument
          @logger.info(LogMessages::Authentication::AuthnCert::AuthenticationStarted.new)
          get_certificate_from_headers(headers: request_headers).bind do |certificate|
            validate_certificate(certificate: certificate).bind do |certificate_attributes|
              enforce_global_restrictions(certificate_attributes: certificate_attributes).bind do
                identity_role(certificate_attributes: certificate_attributes, parameters: parameters).bind do |identity|
                  @logger.info(LogMessages::Authentication::AuthnCert::CredentialValidationSucceeded.new)
                  @success.new(
                    Authentication::RoleIdentifier.new(
                      identifier: identity,
                      attributes: certificate_attributes
                    )
                  )
                end
              end
            end
          end
        end

        private

        def get_certificate_from_headers(headers:)
          return @failure.new("request requires headers") if headers.nil?

          certificate = headers[CERTIFICATE_HEADER]
          return @failure.new("request header #{CERTIFICATE_HEADER} missing or empty") unless certificate.present?

          # As a Rails app, Conjur relies on a proxy to terminate TLS and stash
          # the client certificate in a request header. When stored as a header,
          # newlines in the the client certificate must be escaped in some
          # fashion. Here, we expect the client certificate to have been URL
          # encoded, similar to the value of NGINX's $ssl_client_escaped_cert
          # embedded variable.
          #
          # https://nginx.org/en/docs/http/ngx_http_ssl_module.html#variables
          @success.new(CGI.unescape(certificate))
        end

        def validate_certificate(certificate:)
          @saas_auth_client.new.validate_certificate(
            certificate: certificate,
            authenticator: @authenticator
          ).bind do |response|
            @success.new(response['attributes'])
          end
        end

        def enforce_global_restrictions(certificate_attributes:)
          validation = @authenticator_credential_validation.new(
            authenticator: @authenticator,
            credential_attributes: certificate_attributes
          )

          return @success.new(true) if validation.valid?

          error = validation.errors.first
          @failure.new(
            error.message.to_s,
            exception: error.type,
            status: :unauthorized
          )
        end

        def identity_role(certificate_attributes:, parameters:)
          @identity_resolver.new(authenticator: @authenticator).call(
            id: parameters.nil? ? nil : parameters[:id],
            credential: certificate_attributes
          )
        end
      end
    end
  end
end
