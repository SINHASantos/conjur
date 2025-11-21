# frozen_string_literal: true

module Authentication
  module AuthnOidc
    module V2
      # This class is responsible for resolving the identity of a
      # user or host based on the provided credentials. This allows
      # for custom, per-authenticator logic to be implemented.
      class IdentityResolver < Authentication::Base::IdentityResolver

        # We're overriding the call method to ensure that only the credential
        # is used to resolve the identity.
        #
        # rubocop:disable Lint/UnusedMethodArgument
        def call(credential:, id: nil)
          identity_from_credential(credential).bind do |identity|
            identity_from_role_id(identity)
          end
        end
        # rubocop:enable Lint/UnusedMethodArgument

        # Handle looking up the identity from the credential
        def identity_from_credential(credential)
          identity = credential[@authenticator.identity_attribute]

          if identity.present?
            return @success.new(identity)
          end

          @failure.new(
            "Claim '#{@authenticator.identity_attribute}' was not found in the JWT token",
            exception: Errors::Authentication::AuthnOidc::IdTokenClaimNotFoundOrEmpty.new(
              @authenticator.identity_attribute,
              'claim-mapping'
            ),
            status: :unauthorized
          )
        end
      end
    end
  end
end
