# frozen_string_literal: true

module Workloads
  module Validating
    module AuthnDescriptorValidation
      include Validation
      include Workloads::Validating::AuthnDescriptorAzureValidation
      include Workloads::Validating::AuthnDescriptorCertValidation
      include Workloads::Validating::AuthnDescriptorClaimsValidation
      include Workloads::Validating::AuthnDescriptorGcpValidation
      include Workloads::Validating::AuthnDescriptorLdapValidation

      def type?(type)
        @type == type
      end

      def api_key?
        type?(AuthnDescriptor::API_KEY)
      end

      def not_api_key?
        !api_key?
      end

      def in_types?
        AuthnDescriptor::TYPES.include?(type)
      end

      def not_api_key_type?
        not_api_key? && in_types?
      end

      private

      def validate_data
        return unless @data.is_a?(Hash)
        return if @data.empty?

        return validate_claims_data if type?('aws') || type?('jwt')
        return validate_azure_data if type?('azure')
        return validate_cert_data if type?('cert')
        return validate_gcp_data if type?('gcp')
        validate_ldap_vars if type?('ldap')
      end

      def validate_allowed_keys_only(allowed_keys, actual_keys, msg_prefix)
        unexpected_keys = actual_keys - allowed_keys
        if unexpected_keys.any?
          errors.add(:data, message: "#{msg_prefix} #{unexpected_keys.join(', ')}")
        end
      end
    end
  end
end