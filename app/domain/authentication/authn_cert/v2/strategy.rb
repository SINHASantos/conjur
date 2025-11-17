# frozen_string_literal: true

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
          logger: Rails.logger
        )
          @authenticator = authenticator
          @saas_auth_client = saas_auth_client
          @identity_resolver = identity_resolver
          @logger = logger

          @success = Responses::Success
          @failure = Responses::Failure
        end

        def callback(request_headers:, parameters: nil, request_body: nil) # rubocop:disable Lint/UnusedMethodArgument
          get_certificate_from_headers(headers: request_headers).bind do |certificate|
            validate_certificate(certificate: certificate).bind do |certificate_attributes|
              identity_role(certificate_attributes: certificate_attributes, parameters: parameters).bind do |identity|
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

        private

        def get_certificate_from_headers(headers:)
          return @failure.new("request requires headers") if headers.nil?

          certificate = headers[CERTIFICATE_HEADER]
          return @failure.new("request header #{CERTIFICATE_HEADER} missing or empty") unless certificate.present?

          @success.new(certificate)
        end

        def validate_certificate(certificate:)
          @saas_auth_client.new.do(
            certificate: certificate,
            authenticator: @authenticator
          ).bind do |response|
            @success.new(response[:attributes])
          end
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
