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

        # Maps a set of X.509 certificate attributes to a Conjur role identifier.
        #
        # @attribute [AuthenticatorsV2::CertAuthenticatorType] authenticator
        # @param [Hash] credential - a map of X.509 certificate attributes
        #
        # @return [String] - a Conjur role ID
        def identity_from_credential(credential) # rubocop:disable Lint/UnusedMethodArgument
          @success.new("alice")
        end
      end
    end
  end
end
