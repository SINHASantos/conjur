# frozen_string_literal: true

module Workloads
  module Validating
    module AuthnDescriptorGcpValidation
      include Validation

      def validate_gcp_data
        validate_allowed_keys_only(AuthnDescriptor::GCP_DATA_KEYS,
                                   @data.keys,
                                   "Unexpected fields in GCP authenticator data:")

        validate_instance_name(@data[:instance_name]) if @data.key?(:instance_name)
        validate_project_id(@data[:project_id]) if @data.key?(:project_id)
        validate_service_account_id(@data[:service_account_id]) if @data.key?(:service_account_id)
        validate_account_email(@data[:service_account_email]) if @data.key?(:service_account_email)
      end

      private

      def validate_instance_name(instance_name)
        unless instance_name.is_a?(String) && instance_name.length.between?(1, 63)
          errors.add(:data, "GCP instance_name must be a string between 1 and 63 characters")
        end
        if instance_name.is_a?(String) && (instance_name !~ /^[a-zA-Z]([-a-zA-Z0-9]{0,61}[a-zA-Z0-9])?$/)
          errors.add(:data, "GCP instance_name must start with a letter and contain only letters, digits, and hyphens")
        end
      end

      def validate_project_id(project_id)
        unless project_id.is_a?(String) && project_id.length.between?(1, 30)
          errors.add(:data, "GCP project_id must be a string between 1 and 30 characters")
        end
        if project_id.is_a?(String) && (project_id !~ /^[a-zA-Z0-9\-]+$/)
          errors.add(:data, "GCP project_id can only contain letters, digits, and hyphens")
        end
      end

      def validate_service_account_id(service_account_id)
        unless service_account_id.is_a?(String) && service_account_id.length.between?(1, 100)
          errors.add(:data, "GCP service_account_id must be a string between 1 and 100 characters")
        end

        if service_account_id.is_a?(String) && (service_account_id !~ /^[a-zA-Z0-9\-]+$/)
          errors.add(:data, "GCP service_account_id can only contain letters, digits, and hyphens")
        end
      end

      def validate_account_email(email)
        unless email.is_a?(String) && email =~ /^[^@\s]+@[^@\s]+\.[^@\s]+$/
          errors.add(:data, "Invalid GCP service_account_email")
        end
      end
    end
  end
end
