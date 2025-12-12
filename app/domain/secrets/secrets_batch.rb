# frozen_string_literal: true

module Secrets
  class SecretsBatch
    include ActiveModel::Validations
    include Validation

    MAX_SECRETS_IN_SINGLE_BATCH = 250
    IDS_MAX_SIZE = Rails.application.config.conjur_config.try(:conjur_max_secrets_in_single_batch) || MAX_SECRETS_IN_SINGLE_BATCH
    BASE_64 = 'base64'

    attr_reader :ids, :encode_values

    validates :ids, presence: true
    validate -> { validate_attr_class(:ids, Array) }

    validate -> { validate_attr_class(:encode_values, String) }
    validates :encode_values,
              inclusion: { in: ['', BASE_64],
                           message: "The encode_values query parameter must be #{BASE_64}: encode_values=#{BASE_64}" }

    extend(Domain)

    def initialize(**params)
      @ids = params[:ids]
      @encode_values = params[:encode_values] || ''
      valid?

      @ids = init_ids(@ids) if errors.empty?

      raise DomainValidationError.new(errors.full_messages.to_sentence, errors) if errors.present?
    end

    def to_s
      "#<SecretsBatch ids=#{@ids} encode_values=#{@encode_values}>"
    end

    def use_base64?
      @encode_values == BASE_64
    end

    private

    def init_ids(ids)
      if ids.size > IDS_MAX_SIZE
        raise Errors::Conjur::BatchRequestExceededMaxSize, IDS_MAX_SIZE
      end

      # this part is fine only if after we check errors
      # and raise an error in case of any
      ids.map { |id| validate_id_is_string?(id) && normalize_and_check_id(id) }
    end

    def normalize_and_check_id(id)
      nid = normalize_leading_slashes(id)
      errors.add(:ids, "The id '#{id}' is invalid") if nid.start_with?("/")
      check_id_is_not_dynamic(nid) # static only
      nid
    end

    def normalize_leading_slashes(id)
      id.start_with?("/") ? id[1..] : id
    end

    def validate_id_is_string?(id)
      validate_is_class(:ids, id, String,
                        msg: "The #{:ids} array can only contain strings")
    end

    def check_id_is_not_dynamic(identifier)
      return true unless identifier.start_with?(Issuer::DYNAMIC_VARIABLE_PREFIX)

      raise ApplicationController::UnprocessableEntity,
            "The request cannot contain dynamic secrets"
    end
  end
end
