# frozen_string_literal: true

module Workloads
  module Validating
    module AuthnDescriptorCertValidation
      include Validation

      SAN_DATA_KEYS = %i[san_uri san_dns san_ip].freeze
      SAN_DATA_STR_KEYS = SAN_DATA_KEYS.map(&:to_s).freeze
      CERT_DATA_KEYS = (%i[cn] + SAN_DATA_KEYS).freeze

      def validate_cert_data
        validate_allowed_keys_only(CERT_DATA_KEYS,
                                   @data.keys,
                                   "unexpected fields in Certificate authenticator data:")

        validate_cn(@data[:cn]) if @data.key?(:cn)
        validate_san_entries(@data)
      end

      private

      def validate_cn(cn)
        msg = "invalid certificate cn"
        validate_is_class(:data, cn, String, msg:
        ) &&
        validate_string(:data, cn, /\A[a-zA-Z0-9\-\.\*\/]+\z/,
                        255, 1, msg:)
      end

      def validate_san_entries(data)
        SAN_DATA_KEYS.each do |key|
          next unless data[key] &&
                      validate_is_class(:data, data[key], Array,
                                        msg: "certificate #{key} must be an array")

          data[key].each do |value|
            case key
            when :san_uri
              # Dont validate if data value is nil because nil as value is valid
              validate_url(key, value) if value
            when :san_dns
              # Dont validate if data value is nil because nil as value is valid
              validate_not_allowed_chars_and_length(key, value) if value
            when :san_ip
              validate_san_ip(key, value)
            end
          end
        end
      end

      def validate_url(attr, url)
        validate_is_class(:data, url, String, attr_name: attr
        ) &&
        # Ensure the string does not contain '<', '>' '?', or spaces and does not exceed max_length
        validate_string(:data, url, /\A[^<> ?]*\z/,
                        1000, 1,
                        attr_name: attr,
                        msg_reg_pat: "#{attr} all characters except space ( ), quotation marks (?), less than (<), and greater than (>) are allowed.")
      end

      def validate_not_allowed_chars_and_length(attr, value)
       validate_is_class(:data, value, String, attr_name: attr
       ) &&

        # Ensure the string does not contain '<', '>', or spaces and does not exceed max_length
        validate_string(:data, value, /\A[^<> ]*\z/,
                        1000, 1,
                        attr_name: attr,
                        msg_reg_pat: "#{attr} all characters except space ( ), less than (<), and greater than (>) are allowed.")
      end

      def validate_san_ip(attr, value)
        return unless validate_is_class(:data, value, String,
                                        attr_name: attr,
                                        msg: "invalid IP address format")

        if value.include?('/')
          errors.add(:data, "CIDR notation is not supported in IP addresses")
        end

        begin
          IPAddr.new(value)
        rescue IPAddr::InvalidAddressError, IPAddr::AddressFamilyError
          errors.add(:data, "invalid IP address format")
        end
      end
    end
  end
end
