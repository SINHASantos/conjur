# frozen_string_literal: true

module DB
  module Repository
    # This class is responsible for:
    #   1. Retrieving the target role during the authentication workflow.
    #   2. Validating the role against the authenticator's requirements.
    #
    # This class includes one public method:
    #   - `find` returns a single role based on the provided role_identifier
    #
    # This class depends on a target authenticator implementing the following:
    #   - RoleValidation is responsible for checking that a role's annotations
    #     are properly configured for the desired authentication and authenticator.
    #   - RoleCredentialValidation is responsible for checking that a role's
    #     annotations accurately map to traits of the provided credential.
    #
    class AuthenticatorRoleRepository
      def initialize(
        authenticator:,
        role_validation: nil,
        role_credential_validation: nil,
        role: ::Role,
        logger: Rails.logger
      )
        @authenticator = authenticator
        @role = role
        @logger = logger
        @role_validation = role_validation
        @role_credential_validation = role_credential_validation

        @success = Responses::Success
        @failure = Responses::Failure
      end

      # @params [::Authentication::RoleIdentifier] role_identifier
      #   The role identifier to use when finding and validating the role.
      def find(role_identifier)
        find_role(role_identifier).bind do |role|
          # If the target authenticator does not implement role validations,
          # quickly return a success response. In this case, we don't care
          # whether the role has annotations configured.
          return @success.new(role) if @role_validation.nil?

          # If the target authenticator implements role validations, but the
          # target role is incapable of being assigned annotations, quickly
          # return a failure response.
          if !role.resource? && !@role_validation.nil?
            exception = Errors::Authentication::Constraints::RoleMissingAnyRestrictions.new
            return @failure.new(
              exception.message,
              exception: exception,
              status: :unauthorized
            )
          end

          relevant_authenticator_annotations(
            annotations: {}.tap { |h| role.resource.annotations.each {|a| h[a.name] = a.value }}
          ).bind do |role_authenticator_annotations|
            # Verify that the relevant annotations set on the role satisfy the
            # authenticators requirements.
            role_annotations_valid?(
              annotations: role_authenticator_annotations
            ).bind do
              # If the target authenticator does not implement role credential
              # validations, return a success response. In this case, we don't
              # care whether the role's annotations match the credential
              # attributes in any way.
              return @success.new(role) if @role_credential_validation.nil?

              # Verify that the role's relevant annotations match some
              # credential attributes.
              role_annotations_match_credentials?(
                annotations: role_authenticator_annotations[:all].merge(role_authenticator_annotations[:specific]),
                credential_attributes: role_identifier.attributes
              ).bind do
                @success.new(role)
              end
            end
          end
        end
      end

      private

      def find_role(role_identifier)
        role = @role[role_identifier.identifier]
        return @success.new(role) if role.present?

        @failure.new(
          "Failed to find role for: '#{role_identifier.identifier}'",
          exception: Errors::Authentication::Security::RoleNotFound.new(role_identifier.role_for_error),
          status: :bad_request
        )
      end

      def run_validations(validation)
        unless validation.valid?
          error = validation.errors.first
          case error
          when ActiveModel::Error
            if error.type == :blank
              return @failure.new(
                error.full_message,
                exception: Errors::Authentication::Constraints::RoleMissingAnyRestrictions.new,
                status: :unauthorized
              )
            else
              return @failure.new(
                error.full_message,
                exception: error.type,
                status: :unauthorized
              )
            end
          else
            return @failure.new(
              error.message.to_s,
              exception: error.type,
              status: :unauthorized
            )
          end
        end
        @success.new('success')
      end

      def role_annotations_valid?(annotations:)
        role_annotation_validation = @role_validation.new(
          annotations: annotations[:all],
          specific_annotations: annotations[:specific],
          authenticator: @authenticator
        )

        run_validations(role_annotation_validation).bind do
          @success.new(annotations)
        end
      end

      # Need to account for the following two options:
      # Annotations relevant to specific authenticator
      # - !host
      #   id: myapp
      #   annotations:
      #     authn-jwt/raw/ref: valid
      #
      # Annotations relevant to type of authenticator
      # - !host
      #   id: myapp
      #   annotations:
      #     authn-jwt/project_id: myproject
      #     authn-jwt/aud: myaud
      #
      # The response object includes the following keys:
      # - :all, a consolidated map of applicable global and service-specific
      #   annotations. If there are collisions between global and service-specific
      #   annotations that share a restriction name, the service-specific
      #   annotation is honored.
      # - :specific, a map of applicable service-specific annotations.
      def relevant_authenticator_annotations(annotations:)
        generic = annotations
          .select{|k, _| k.count('/') == 1}
          .select{|k, _| k.starts_with?(@authenticator.type)}
          .reject{|k, _| k.starts_with?(@authenticator.identifier)}
          .transform_keys{|k| k.gsub("#{@authenticator.type}/", '')}

        specific = annotations
          .select{|k, _| k.count('/') > 1}
          .select{|k, _| k.starts_with?(@authenticator.identifier)}
          .transform_keys{|k| k.gsub("#{@authenticator.identifier}/", '')}

        @success.new({ all: generic.merge(specific), specific: specific })
      end

      def role_annotations_match_credentials?(annotations:, credential_attributes:)
        role_credential_validation = @role_credential_validation.new(
          annotations: annotations,
          authenticator: @authenticator,
          credential_attributes: credential_attributes
        )

        run_validations(role_credential_validation).bind do
          @success.new('Annotations match credential')
        end
      end
    end
  end
end
