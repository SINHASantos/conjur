# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        # This class validates that a client's X.509 certificate aligns with the
        # global, webservice-scoped restrictions set as configuration variables
        # on the authenticator. In the context of AuthnCert, we confirm that
        # Subject Alternate Names specified via variables are present in the
        # client's certificate.
        #
        # Due to the data flow of the authenticators architecture, this class
        # operates on the assumption that the credential has been successfully
        # validated, and therefore the map of credential attributes cannot
        # realistically be nil or empty.
        #
        # Webservice-scoped restrictions are optional, and if none are present,
        # this validation will pass by default.
        class AuthenticatorCredentialValidation
          include ActiveModel::Validations

          attr_reader :authenticator, :credential_attributes

          validates :authenticator, presence: true
          validates :credential_attributes, presence: true

          validate :global_restriction_values_valid, if: -> { global_restrictions_present? }
          validate :global_restrictions_match_credential, if: -> { global_restrictions_present? && no_prior_errors? }

          def initialize(authenticator:, credential_attributes:, logger: Rails.logger)
            @authenticator = authenticator
            @credential_attributes = credential_attributes
            @logger = logger

            @enforcer = Authentication::AuthnCert::V2::Wildcard::Enforcer
          end

          private

          def no_prior_errors?
            errors.empty?
          end

          def global_restrictions_present?
            @global_restrictions_present ||= variables.any? do |variable|
              !authenticator.variables[variable_to_symbol(variable)].nil?
            end

            @global_restrictions_present
          end

          def global_restriction_values_valid
            variables.each do |variable|
              value = @authenticator.variables[variable_to_symbol(variable)]
              next if value.nil?
              next if @enforcer.value_valid?(value, @enforcer.matcher_for(variable))

              errors.add(:base, Errors::Authentication::Certificate::InvalidWildcards.new('Variable', variable, value))
            end
          end

          def global_restrictions_match_credential
            variables.each do |variable|
              value = @authenticator.variables[variable_to_symbol(variable)]
              next if value.nil?
              next if @enforcer.value_matches_credential?(
                value,
                @enforcer.attribute_for(variable, @credential_attributes),
                @enforcer.matcher_for(variable)
              )

              errors.add(:base, Errors::Authentication::Certificate::AttributeConstraintMismatch.new(readable(variable)))
            end
          end

          def variables
            %w[san-dns san-uri san-ip cn]
          end

          def variable_to_symbol(variable)
            variable.gsub('-', '_').to_sym
          end

          def readable(variable)
            case variable
            when 'san-dns'
              'DNS Subject Alternative Name'
            when 'san-uri'
              'URI Subject Alternative Name'
            when 'san-ip'
              'IP Subject Alternative Name'
            when 'cn'
              'Common Name'
            else
              'Unknown Attribute'
            end
          end
        end
      end
    end
  end
end
