# frozen_string_literal: true

module Validation
  NAME_LENGTH_MIN = 1
  NAME_LENGTH_MAX = 60
  NAME_PATTERN = /\A[A-Za-z0-9\-_]+\Z/.freeze
  NAME_PATTERN_MSG = "Wrong value '%{value}'"

  PATH_LENGTH_MIN = 1
  PATH_LENGTH_MAX = 500
  PATH_PATTERN = %r{\A[A-Za-z0-9\-_/]+\Z}.freeze
  PATH_PATTERN_MSG = "Wrong path '%{value}'"
  USER_PATH_PATTERN = %r{\A[A-Za-z0-9@\-_/]+\Z}.freeze
  USER_PATH_PATTERN_MSG = "Wrong path '%{value}'"

  IDENTIFIER_MAX_DEPTH = 15
  IDENTIFIER_MAX_DEPTH_MSG = "The number of identifier nesting exceeds maximum depth of #{IDENTIFIER_MAX_DEPTH}"
  IDENTIFIER_MAX_LENGTH = 950
  IDENTIFIER_MAX_LENGTH_MSG = "Identifier exceeds maximum length of #{IDENTIFIER_MAX_LENGTH} characters"

  class DomainValidationError < StandardError
    attr_reader :errors

    def initialize(message, errors = [])
      super(message)
      @errors = errors
    end
  end

  def validate_attrs_class(attrs, klass)
    attrs.each { |attr| validate_attr_class(attr, klass) }
  end

  def validate_attr_class(attr, klass)
    validate_is_class(attr, instance_variable_get("@#{attr}"), klass)
  end

  def validate_is_class(attr, value, klass, msg: nil, exc: nil, attr_name: nil)
    return true if value.is_a?(klass)

    a_an = [Integer, Array].include?(klass) ? "an" : "a"
    message = msg || "#{attr_name_str(attr_name)}must be #{a_an} #{klass.to_s.downcase}"
    errors.add(attr, message, strict: exc)
    false
  end

  def validate_identifier(attr, idfr, msg: nil, exc: nil)
    err_msgs = check_identifier(idfr)
    err_msgs.each { |em| errors.add(attr, msg || em, strict: exc) }
    err_msgs.empty?
  end

  def validate_str_min_length(attr, value, min_size, msg: nil, exc: nil, attr_name: nil)
    return true if value.length >= min_size

    message = msg || "#{attr_name_str(attr_name)}parameter length is less than #{min_size} characters"
    errors.add(attr, message, strict: exc)
    false
  end

  def validate_str_max_length(attr, value, max_size, msg: nil, exc: nil, attr_name: nil)
    return true if value.length <= max_size

    message = msg || "#{attr_name_str(attr_name)}parameter length exceeded. Limit the length to #{max_size} characters"
    errors.add(attr, message, strict: exc)
    false
  end

  def validate_str_regex(attr, value, regex_pattern, msg: nil, exc: nil, attr_name: nil)
    return true if value.match?(regex_pattern)

    message = msg || "invalid '#{attr_name || attr}' parameter"
    errors.add(attr, message, strict: exc)
    false
  end

  def validate_string(attr, value, regex_pattern, max_size, min_size,
                      msg: nil, exc: nil,
                      attr_name: nil,
                      msg_reg_pat: nil, msg_max_size: nil, msg_min_size: nil)
    is_valid = validate_str_min_length(attr, value, min_size,
                                       msg: msg_min_size || msg,
                                       exc:, attr_name:)
    is_valid = is_valid &&
               validate_str_max_length(attr, value, max_size,
                                       msg: msg_max_size || msg,
                                       exc:, attr_name:)
    is_valid &&
      validate_str_regex(attr, value, regex_pattern,
                         msg: msg_reg_pat || msg,
                         exc:, attr_name:)
  end

  def string_like?(value)
    value.is_a?(String) || value.is_a?(Symbol)
  end

  private

  def attr_name_str(attr_name)
    attr_name ? "#{attr_name} " : ""
  end

  def check_identifier(identifier)
    depth = identifier.delete_prefix('/').delete_suffix('/').count('/') + 1
    err_msgs = []
    err_msgs << IDENTIFIER_MAX_DEPTH_MSG if depth > IDENTIFIER_MAX_DEPTH
    err_msgs << IDENTIFIER_MAX_LENGTH_MSG if identifier.length > IDENTIFIER_MAX_LENGTH
    err_msgs
  end
end
