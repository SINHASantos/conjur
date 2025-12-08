# frozen_string_literal: true

module Workloads
  module Validating
    module AuthnDescriptorClaimsValidation
      include Validation

      MAX_CLAIMS_SIZE = 10

      def validate_claims_data
        if @data.size > MAX_CLAIMS_SIZE
          errors.add(:data, "no more than #{MAX_CLAIMS_SIZE} claims are allowed in data")
        end

        @data.each do |key, value|
          if !string_like?(key) || !string_like?(value)
            errors.add(:data, "invalid claims parameter. Keys and values must be strings.")
            return false
          end

          validate_string(:data, key,
                          PATH_PATTERN,
                          PATH_LENGTH_MAX,
                          PATH_LENGTH_MIN,
                          attr_name: "key",
                          msg_reg_pat: "invalid 'key' parameter. Valid characters: letters, numbers, and these special characters are allowed: _ / -. Other characters are not allowed.")

          validate_string(:data, value,
                          Annotations::Annotations::VALUE_PATTERN,
                          Annotations::Annotations::VALUE_LENGTH_MAX,
                          Annotations::Annotations::VALUE_LENGTH_MIN,
                          attr_name: "value",
                          msg_reg_pat: "invalid 'value' parameter. All characters except less than (<), greater than (>), and single quote (') are allowed.")
        end
      end
    end
  end
end
