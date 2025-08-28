# frozen_string_literal: true

module Annotations
  class Annotations < Hash
    include ActiveModel::Validations
    include Validation

    VALUE_PATTERN = /\A[^<>']+\Z/.freeze
    VALUE_LENGTH_MIN = 1
    VALUE_LENGTH_MAX = 120
    FORBIDDEN_KEY = :type

    validate :validate

    def initialize(params = {})
      super()
      merge!(params)
      raise DomainValidationError.new(errors.full_messages.to_sentence, errors) if invalid?
    end

    def self.from_model(model)
      model.each_with_object({}) { |m, result| result[m.name] = m.value }
    end

    private

    def validate
      return if empty?

      if key?(FORBIDDEN_KEY) || key?(FORBIDDEN_KEY.to_s)
        errors.add(:base, "The annotation key '#{FORBIDDEN_KEY}' is reserved and cannot be used")
      end

      each do |key, value|
        if value.nil? || (value.is_a?(String) and value.empty?)
          raise Errors::Conjur::ParameterMissing, key
        end

        validate_key(key)
        validate_value(key, value)
      end
    end

    def validate_key(key)
      key_s = key.is_a?(Symbol) ? key.to_s : key
      if validate_is_class(key, key_s, String, msg: "must be of 'type=string'")
        validate_string(:base, key_s,
                        Validation::PATH_PATTERN,
                        Validation::PATH_LENGTH_MAX, Validation::PATH_LENGTH_MIN,
                        msg: "Invalid 'annotation name' parameter.")
      end
    end

    def validate_value(key, value)
      if validate_is_class(key, value, String, msg: "must be of 'type=string'")
        validate_string(key, value,
                        VALUE_PATTERN,
                        VALUE_LENGTH_MAX, VALUE_LENGTH_MIN,
                        msg: "Invalid 'annotation value'.")
      end
    end
  end
end
