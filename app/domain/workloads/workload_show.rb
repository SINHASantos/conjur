# frozen_string_literal: true

require_relative '../domain'
require_relative '../validation'

module Workloads
  class WorkloadShow
    extend(Domain)
    include Domain
    include Validation
    include ActiveModel::Validations
    include Workloads::Validating::WorkloadValidation

    EXTENDED_IDENTIFIER_MAX_LENGTH = 1070

    attr_reader :identifier
    validates :identifier, presence: true
    validate -> { validate_string(:identifier, identifier,
                                  /\A.*\z/,
                                  EXTENDED_IDENTIFIER_MAX_LENGTH,
                                  1,
                                  attr_name: "identifier",
                                  msg_reg_pat: "Identifier is too long (maximum is #{EXTENDED_IDENTIFIER_MAX_LENGTH} characters)\"") }

    def initialize(**params)
      @identifier = params[:identifier]
      valid?
      raise DomainValidationError.new(errors.full_messages.to_sentence, errors) if errors.present?
    end

    def to_s
      "<WorkloadShow identifier=#{@identifier}>"
    end

    def as_json(options = {})
      except_keys = %w[validation_context context_for_validation errors]
      super(options).except(*except_keys)
    end
  end
end
