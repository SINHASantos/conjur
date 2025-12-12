# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        # This class validates that a client's X.509 certificate aligns with the
        # resource restriction set as annotations on the target role. In the
        # context of AuthnCert, we confirm that Subject Alternate Names
        # specified via annotations are present in the client's certificate.
        #
        # Due to the data flow of the authenticators architecture, this class
        # operates on the following assumptions:
        #   1. That annotation-based restrictions have been validated for
        #      presence, count, and validity by the AuthenticatorRoleRepository
        #      using the Validations::Constraints class.
        #   2. Given 1, the provided annotation set being empty is a valid state.
        #   3. That the credential has been successfully validated, and
        #      therefore the map of credential attributes cannot realistically
        #      be nil or empty.
        class RoleCredentialValidation
          include ActiveModel::Validations

          attr_reader :authenticator, :credential_attributes

          validates :authenticator, presence: true
          validates :credential_attributes, presence: true

          # Given assumption #2, the validations below should only be performed
          # if the annotations set is non-empty.
          validate :annotations_have_values, if: -> { annotations_present? && errors.empty? }
          validate :annotation_values_valid, if: -> { annotations_present? && errors.empty? }
          validate :annotations_match_credential, if: -> { annotations_present? && errors.empty? }

          def initialize(annotations:, authenticator:, credential_attributes:, logger: Rails.logger)
            @annotations = annotations
            @authenticator = authenticator
            @credential_attributes = credential_attributes
            @logger = logger

            @enforcer = Authentication::AuthnCert::V2::Wildcard::Enforcer
          end

          private

          def no_prior_errors?
            errors.empty?
          end

          def annotations_present?
            @annotations.any?
          end

          def annotations_have_values
            @annotations.each do |annotation, value|
              if value.blank?
                errors.add(:base, Errors::Authentication::ResourceRestrictions::EmptyAnnotationGiven.new(annotation))
              end
            end
          end

          def annotation_values_valid
            @annotations.each do |annotation, value|
              next if @enforcer.value_valid?(value, @enforcer.matcher_for(annotation))

              errors.add(:base, Errors::Authentication::Certificate::InvalidWildcards.new('Annotation', annotation, value))
            end
          end

          def annotations_match_credential
            @annotations.each do |annotation, value|
              next if @enforcer.value_matches_credential?(value, @enforcer.attribute_for(annotation, @credential_attributes), @enforcer.matcher_for(annotation))

              errors.add(:base, Errors::Authentication::ResourceRestrictions::InvalidResourceRestrictions.new(annotation))
            end
          end
        end
      end
    end
  end
end
