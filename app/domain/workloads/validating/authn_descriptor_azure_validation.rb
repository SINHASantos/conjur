# frozen_string_literal: true

module Workloads
  module Validating
    module AuthnDescriptorAzureValidation
      include Validation

      def validate_azure_data
        validate_allowed_keys_only(AuthnDescriptor::AZURE_DATA_KEYS,
                                   @data.keys,
                                   "unexpected fields in Azure authenticator data:")

        validate_subscription_id(@data[:subscription_id]) if @data.key?(:subscription_id)
        validate_resource_group(@data[:resource_group]) if @data.key?(:resource_group)

        if @data.key?(:user_assigned_identity)
          validate_chars_and_length?(:user_assigned_identity,
                                     @data[:user_assigned_identity])
        end

        if @data.key?(:system_assigned_identity)
          validate_chars_and_length?(:system_assigned_identity,
                                     @data[:system_assigned_identity])
        end
      end

      private

      def validate_subscription_id(subscription_id)
        validate_is_class(:data, subscription_id, String, msg: "azure subscription_id must be a string"
        ) &&
          validate_str_regex(:data, subscription_id, /^[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?$/,
                             msg: "azure subscription_id must contain only letters, digits, and hyphens")
      end

      def validate_resource_group(resource_group)
        unless resource_group.is_a?(String) && resource_group.length.between?(1, 90)
          errors.add(:data, "azure resource_group must be a string between 1 and 90 characters")
        end

        if resource_group.is_a?(String) && (resource_group !~ /^[a-zA-Z0-9_\-.()]+$/)
          errors.add(:data, "azure resource_group can only contain alphanumeric characters, underscores, periods, hyphens, and parentheses")
        end
      end

      def validate_chars_and_length?(data_key, value)
        validate_is_class(:data, value, String, attr_name: data_key
        ) &&
          validate_string(:data, value, /\A[\w\-.,@:\/+= ]*\z/,
                          1000, 1,
                          attr_name: data_key,
                          msg: "#{data_key} must match regex ^[\\w\\-.,@:/+= ]*$ and be 1-1000 characters.")
      end
    end
  end
end
