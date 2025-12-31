# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      class SaasAuthClient
        def initialize(
          http_client: Authentication::Util::NetworkTransporter,
          authenticator_service_url: Rails.application.config.conjur_config.authenticator_service_url
        )
          @http_client = http_client.new(
            hostname: authenticator_service_url
          )

          @success = Responses::Success
          @failure = Responses::Failure
        end

        # Make a request to a locally running credential validation service to
        # validate that a provided X.509 certificate is signed by the CA of a
        # requested Certificate Authenticator webservice, and decode the X.509
        # certificate into a map of identifying attributes.
        #
        #   {
        #     attributes: {
        #       serial_number: '...'
        #       subject: '...',
        #       not_before: '...',
        #       not_after: '...',
        #       san_uri: [
        #         '...'
        #       ]
        #     }
        #   }
        #
        # @param certificate [String] Authenticating client's certificate.
        # @param authenticator [AuthenticatorsV2::CertAuthenticatorType]
        #   Configuration of a Certificate authenticator instance.
        #
        # @return [Hash] A map of the client certificate's identifying attributes.
        def validate_certificate(certificate:, authenticator:)
          Rails.logger.info(LogMessages::Authentication::AuthnCert::CertificateValidationStarted.new(authenticator.service_id))
          response = @http_client.post(
            path: "/authentications/cert",
            body: post_body(certificate, authenticator),
            request_type: :json,
            error_type: :json
          ).bind do |certificate_attributes|
            unless well_formed_response?(certificate_attributes)
              return @failure.new(
                "Empty or malformed certificate attributes",
                exception: Errors::Authentication::Service::BadResponse.new("Empty or malformed certificate attributes"),
                status: :unauthorized
              )
            end

            Rails.logger.info(LogMessages::Authentication::AuthnCert::CertificateValidationSucceeded.new(authenticator.service_id))
            return @success.new(certificate_attributes)
          end

          failure_from_service_response(response.message)
        end

        private

        # Convert an authenticator instance and client X.509 certificate into
        # a request body for the authenticator service.
        def post_body(certificate, authenticator)
          {}.tap do |body|
            body['payload'] = certificate
            body['configuration'] = configuration_object(authenticator)
          end
        end

        def configuration_object(authenticator)
          {}.tap do |obj|
            obj['ca_cert'] = authenticator.variables[:ca_cert] unless authenticator.variables[:ca_cert].nil?
            obj['crl'] = authenticator.variables[:crl] unless authenticator.variables[:crl].nil?
            obj['crl_url'] = authenticator.variables[:crl_url] unless authenticator.variables[:crl_url].nil?
          end
        end

        def well_formed_response?(body)
          body.is_a?(Hash) &&
            body['attributes'].is_a?(Hash) &&
            body['attributes'].any?
        end

        # The authenticator service's API responses include failure details
        # meant to be logged for audit and debug purposes. These API responses
        # are groups of parallel errors on failure in the following format:
        #
        #   {
        #     code: "TOP_LEVEL_ERROR_CODE",
        #     message: "Top level error message",
        #     errors: [
        #       {
        #         code: "LOW_LEVEL_ERROR_CODE",
        #         message: "Low level error message",
        #         field: "/related/input/field"
        #       }
        #     ]
        #   }
        #
        # The service is responsible for making sure that LOW_LEVEL_AUDIT_CODES
        # are valid Conjur audit codes in contexts where backward compatibility
        # needs to be considered.
        #
        # This function converts an error group JSON object into a Failure
        # response that other components can consume.
        def failure_from_service_response(response_body)
          unless valid_error_group?(response_body)
            return @failure.new(
              "Malformed error response from authenticator service",
              exception: Errors::Authentication::Service::MalformedError.new,
              status: :unauthorized
            )
          end

          error = response_body['errors'].first
          @failure.new(
            'Credential validation failed',
            exception: Errors::Authentication::Service::DynamicError.new(
              error['code'], error['message']
            ),
            status: :unauthorized
          )
        end

        def valid_error_group?(body)
          body.is_a?(Hash) &&
            !body['errors'].nil? &&
            body['errors'].is_a?(Array) &&
            body['errors'].length.positive? &&
            body['errors'].first['code'].present? &&
            body['errors'].first['message'].present?
        end
      end
    end
  end
end
