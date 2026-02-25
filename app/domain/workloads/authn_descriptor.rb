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

    TYPES = %w[api_key gcp jwt cert aws azure ldap].freeze
    API_KEY = "api_key"
    CERT = "cert"
    JWT = "jwt"
    AWS = "aws"
    GCP = "gcp"
    SAN_DATA_KEYS = %i[san_uri san_dns san_ip].freeze
    SAN_DATA_STR_KEYS = SAN_DATA_KEYS.map(&:to_s).freeze
    CERT_DATA_KEYS = (%i[cn] + SAN_DATA_KEYS).freeze
    GCP_DATA_KEYS = %i[instance_name project_id service_account_id service_account_email].freeze
    AZURE_DATA_KEYS = %i[subscription_id resource_group user_assigned_identity system_assigned_identity].freeze

    attr_reader :type, :service_id, :data

    validate -> { validate_attr_class(:type, String) }

    validates :type, inclusion: { in: TYPES, message: "contains unsupported value: %{value}" },
              if: -> { type.is_a?(String) }

    validate -> { validate_attr_class(:service_id, String) },
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
    validate -> { validate_attr_class(:data, Hash) && validate_data },
             if: -> { !data.nil? && not_api_key_type? }

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

    def branch_path
      auth_branch = ::Authenticators::TypeConverter.get_full_branch_from_type(@type)
      return @branch_path ||= auth_branch if type?('gcp')
      @branch_path ||= [auth_branch, @service_id].join('/')
    end

    def anns_path
      authn_type = ::Authenticators::TypeConverter.get_branch_from_type(@type)
      return @anns_path ||= authn_type if type?('gcp')
      @anns_path ||= [authn_type, @service_id].join('/')
    end
  end
end
