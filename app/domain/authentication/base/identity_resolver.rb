# frozen_string_literal: true

module Authentication
  module Base
    class IdentityResolver
      # Made public to allow this to be called by the Authentication Handler
      def self.id_from_params(id)
        if id.to_s.match(%r{^host/})
          role_identifier = id.gsub(%r{^host/}, '')
          { role_id: role_identifier, type: 'host' }
        else
          { role_id: id, type: 'user' }
        end
      end

      def initialize(authenticator:, logger: Rails.logger)
        @authenticator = authenticator
        @logger = logger

        @success = Responses::Success
        @failure = Responses::Failure
      end

      # If an authenticator needs a mix of the role identifier and the credential
      # to resolve the identity, the child class should overwrite the `call` method.
      def call(id: nil, credential: nil)
        if id.present?
          @logger.debug(LogMessages::Authentication::ProvidedRoleID.new(@authenticator.identifier))
          identity_from_role_id(
            formatted_id(id)
          )
        else
          @logger.debug(LogMessages::Authentication::DerivingRoleID.new(@authenticator.identifier))
          identity_from_credential(credential).bind do |identity|
            identity_from_role_id(identity)
          end
        end
      end

      # If the role is identified via the credential (for example, JWT claims,
      # AWS STS response, etc.), this method needs to be overwritten in the
      # child class.
      #
      # rubocop:disable Lint/UnusedMethodArgument
      def identity_from_credential(credential)
        raise 'Not implemented'
      end
      # rubocop:enable Lint/UnusedMethodArgument

      private

      def formatted_id(id)
        strip_empty_elements(id.to_s.split('/')).join('/')
      end

      def identity_from_role_id(id)
        parts = IdentityResolver.id_from_params(id)
        identity_with_authenticator_path(parts[:role_id]).bind do |identity|
          @success.new("#{@authenticator.account}:#{parts[:type]}:#{identity}")
        end
      end

      # If identity path is present, prefix it to the identity
      # Make sure we allow flexibility for optionally included trailing slash on identity_path
      def identity_with_authenticator_path(identity)
        identity_with_path = strip_empty_elements(
          formatted_identity_path.split('/') + identity.split('/')
        ).join('/')
        @success.new(
          identity_with_path
        )
      end

      def formatted_identity_path
        strip_empty_elements(
          @authenticator&.identity_path
            .to_s
            .split('/')
        ).join('/')
      end

      def strip_empty_elements(elements)
        elements.compact.reject(&:empty?)
      end
    end
  end
end
