# frozen_string_literal: true

# Conjur API authenticator
module Authentication
  module AuthnApiKey
    module V2
      class Strategy
        AUTHN_API_KEY_ANNOTATION_NAME = 'authn/api-key'

        # This authenticator is a bit different because it validates based on the
        # information stored in the Conjur database. As such, Role and Credential
        # are made available.  Longer term, they should probably become part of this
        # authenticator.
        def initialize(
          authenticator:,
          logger: Rails.logger,
          credentials: ::Credentials,
          role: ::Role,
          conjur_config: Rails.application.config.conjur_config
        )
          @authenticator = authenticator
          @logger = logger
          @credentials = credentials
          @role = role
          @conjur_config = conjur_config

          @success = Responses::Success
          @failure = Responses::Failure
        end

        # Parameter `id` is guaranteed to be present based on the
        # upstream routes file.
        #
        # NOTE: The `request_headers` parameter is not used in this context, but
        # needs to be present to adhere to the interface.
        #
        # rubocop:disable Lint/UnusedMethodArgument
        def callback(parameters:, request_body:, request_headers: nil)
          role_id = parameters[:id]
          api_key = request_body

          # Support accessing user roles with an optional "user/" prefix.
          full_role_id = if (match = role_id.match(%r{^(host|user)/(.+)})&.captures)
            "#{@authenticator.account}:#{match[0]}:#{match[1]}"
          else
            "#{@authenticator.account}:user:#{role_id}"
          end

          role_identifier = Authentication::RoleIdentifier.new(
            identifier: full_role_id
          )
          role_with_annotation = role_with_api_key_annotation(full_role_id)
          if role_with_annotation.nil?
            exception = Errors::Authentication::Security::RoleNotFound.new(role_id)
            return @failure.new(
              exception.message,
              exception: exception
            )
          end

          unless api_key_authn_enabled?(
            role_with_annotation[:authn_api_key_annotation],
            role_id: full_role_id
          )
            exception = Errors::Authentication::AuthenticationDisabled.new(role_id)
            return @failure.new(
              exception.message,
              exception: exception
            )
          end

          role_credentials = @credentials[full_role_id]
          if role_credentials.nil?
            exception = Errors::Authentication::RoleHasNoCredentials.new(role_id)
            return @failure.new(
              exception.message,
              exception: exception
            )
          end

          return @success.new(role_identifier) if role_credentials.valid_api_key?(api_key)

          exception = Errors::Authentication::InvalidCredentials.new
          @failure.new(
            exception.message,
            exception: exception
          )
        end
        # rubocop:enable Lint/UnusedMethodArgument

        # TODO: need to pull this over from the authn-jwt refactor
        #
        # # Called by status handler. This handles checking as much of the strategy
        # # integrity as possible without performing an actual authentication.
        # def verify_status
        #   true
        # end

        private

        def role_with_api_key_annotation(role_id)
          @role.left_join(
            :resources,
            Sequel.qualify(:roles, :role_id) => Sequel.qualify(:resources, :resource_id)
          ).left_join(
            :annotations,
            {
              Sequel.qualify(:resources, :resource_id) => Sequel.qualify(:annotations, :resource_id),
              Sequel.qualify(:annotations, :name) => AUTHN_API_KEY_ANNOTATION_NAME
            }
          ).where(
            Sequel.qualify(:roles, :role_id) => role_id
          ).select(
            Sequel.qualify(:roles, :role_id),
            Sequel.qualify(:annotations, :value).as(:authn_api_key_annotation)
          ).first
        end

        def api_key_authn_enabled?(annotation_value, role_id:)
          api_key_authn_default = @conjur_config.authn_api_key_default
          return api_key_authn_default if annotation_value.nil?

          case annotation_value.to_s.strip.downcase
          when 'false'
            false
          when 'true'
            true
          else
            @logger.debug(
              "Ignoring unrecognized authn/api-key annotation value '#{annotation_value}' " \
              "for role '#{role_id}'. Falling back to configured default API key auth setting " \
              "'#{api_key_authn_default}'."
            )

            api_key_authn_default
          end
        end
      end
    end
  end
end
