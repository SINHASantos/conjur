# frozen_string_literal: true

require_relative '../domain'
require_relative '../validation'

module Workloads
  class AuthnDescriptor
    extend(Domain)
    include Domain
    include Validation
    include Workloads::Validating::AuthnDescriptorValidation
    include ActiveModel::Validations

    attr_accessor :type, :service_id, :data
    validate -> { validate_attr_class(:type, String) }

    validates :type, inclusion: { in: TYPES, message: "contains unsupported value: %{value}" },
              if: -> { type.is_a?(String) }

    validate -> { validate_attr_class(:service_id, String) },
             if: -> { not_api_key_type? }

    validate -> { validate_attr_class(:data, Hash) },
             if: -> { not_api_key_type? }

    validates :service_id,
              format: { with: /\A[a-zA-Z0-9_\-]+\z/, message: "must contain only alphanumeric characters, underscores, and hyphens" },
              length: { minimum: 3, maximum: 60, message: "must be between 3 and 60 characters" },
              if: -> { not_api_key_type? }
    validate -> { errors.add(:service_id, "api_key descriptor must not contain 'service_id'") unless service_id.nil? },
             if: -> { api_key? }
    validates :service_id, inclusion: { in: ['default'], message: "for GCP must be 'default'" },
              if: -> { type?('gcp') }

    validate -> { errors.add(:data, "api_key descriptor must not contain 'data'") unless data.nil? },
             if: -> { api_key? }
    validate :validate_data

    def initialize(**params)
      @type = params[:type]
      @service_id = params[:service_id]
      @data = params[:data]

      valid?
      raise Validation::DomainValidationError.new(errors.full_messages.to_sentence, errors) if errors.present?

      @service_id ||= ''
      @data ||= {}
    end

    def to_s
      "<AuthnDescriptor type=#{@type} service_id=#{@service_id} data=#{@data}>"
    end

    def as_json(options = {})
      except_keys = %w[context_for_validation validation_context errors]
      except_keys << "service_id" if @service_id.empty? || api_key?
      except_keys << "data" if api_key?

      super(options).except(*except_keys)
    end
  end
end
