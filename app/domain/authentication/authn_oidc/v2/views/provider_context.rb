require 'securerandom'
require 'digest'

module Authentication
  module AuthnOidc
    module V2
      module Views
        class ProviderContext
          def initialize(
            client: Authentication::AuthnOidc::V2::OidcClient,
            digest: Digest::SHA256,
            random: SecureRandom,
            logger: Rails.logger
          )
            @client = client
            @logger = logger
            @digest = digest
            @random = random

            @success = Responses::Success
            @failure = Responses::Failure
          end

          def call(authenticators:)
            providers = []
            authenticators.each do |authenticator|
              nonce = @random.hex(25)
              code_verifier = @random.hex(25)
              code_challenge = @digest.base64digest(code_verifier).tr("+/", "-_").tr("=", "")

              generate_redirect_url(
                client: @client.new(authenticator: authenticator),
                authenticator: authenticator,
                nonce: nonce,
                code_challenge: code_challenge
              ).bind do |redirect_uri|
                providers << {
                  service_id: authenticator.service_id,
                  type: 'authn-oidc',
                  name: authenticator.name,
                  nonce: nonce,
                  code_verifier: code_verifier,
                  redirect_uri: redirect_uri
                }
              end
            end if authenticators.is_a?(Array)
            providers
          end

          def generate_redirect_url(client:, authenticator:, nonce:, code_challenge:)
            # On success, `return` inside the block exits this method. On failure, `bind` returns
            # the Failure from `oidc_configuration` so we can log it before building the response.
            result = client.oidc_configuration.bind do |config|
              params = {
                client_id: authenticator.client_id,
                response_type: authenticator.response_type,
                scope: ERB::Util.url_encode(authenticator.scope),
                nonce: nonce,
                code_challenge: code_challenge,
                code_challenge_method: 'S256',
                redirect_uri: ERB::Util.url_encode(authenticator.redirect_uri)
              }
              formatted_params = params.map { |key, value| "#{key}=#{value}" }.join("&")

              return @success.new("#{config['authorization_endpoint']}?#{formatted_params}")
            end
            message = "Authn-OIDC '#{authenticator.service_id}' provider-uri: '#{authenticator.provider_uri}' is unreachable"
            @logger.warn(message)
            log_oidc_discovery_failure_details(result)
            @failure.new(message, exception: Errors::Authentication::OAuth::ProviderDiscoveryFailed.new)
          end

          private

          # Emits diagnostic detail at DEBUG when discovery fails: the Responses::Failure message,
          # optional domain exception class/message from OidcClient, and a backtrace.
          # Responses::Failure#backtrace already prefers the domain exception's backtrace when
          # available, so we log it directly without duplicating that priority logic here.
          def log_oidc_discovery_failure_details(failure)
            parts = [failure.message]
            if failure.exception
              parts << "#{failure.exception.class}: #{failure.exception.message}"
            end
            @logger.debug("Authn-OIDC provider discovery failure: #{parts.compact.join(' | ')}")
            @logger.debug(failure.backtrace.join("\n")) if failure.backtrace.present?
          end
        end
      end
    end
  end
end
