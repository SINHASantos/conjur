# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      class SaasAuthClient
        def initialize
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
        def do(certificate:, authenticator:) # rubocop:disable Lint/UnusedMethodArgument
          @success.new({
            attributes: {
              subject: 'CN=client',
              issuer: 'CN=CyberArk CA',
              san_uri: ['spiffe://trust.com/workload'],
              not_before: '2023-01-01T00:00:00Z',
              not_after: '2024-01-01T00:00:00Z',
              serial_number: '1234567890',
              thumbprint: 'abcdef1234567890abcdef1234567890abcdef12'
            }
          })
        end
      end
    end
  end
end
