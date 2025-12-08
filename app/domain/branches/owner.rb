# frozen_string_literal: true

module Branches
  class Owner
    include ActiveModel::Validations
    include Validation

    OWNER_KINDS = %w[host user group policy].freeze
    OWNER_KINDS_MSG = "'%{value}' is not a valid owner kind"

    attr_reader :kind, :id

    validates :kind, presence: true, inclusion: { in: OWNER_KINDS, message: OWNER_KINDS_MSG }
    validates :id, presence: true, format: { with: USER_PATH_PATTERN, message: USER_PATH_PATTERN_MSG },
              if: -> { kind == 'user' }
    validates :id, presence: true, format: { with: PATH_PATTERN, message: PATH_PATTERN_MSG },
              unless: -> { kind == 'user' }
    validates :id, length: { minimum: PATH_LENGTH_MIN, maximum: PATH_LENGTH_MAX }
    validate -> { validate_identifier(:id, id) }, if: -> { kind != 'user' }

    extend(Domain)

    def initialize(**params)
      @is_set = params.key?(:kind) || params.key?(:id)
      @kind = params[:kind] || ''
      @id = params[:id] || ''

      raise DomainValidationError.new(errors.full_messages.to_sentence, errors) if set? && invalid?
    end

    def set?
      @is_set
    end


    def self.from_model_id(owner_id)
      new(**{kind: kind(owner_id), id: identifier(owner_id)})
    end

    def as_json(options = {})
      super(options).except("context_for_validation", "errors", "is_set")
    end

    def not_admin?
      @id != 'admin' || @kind != 'user'
    end

    def to_s
      "#<Owner kind=#{@kind} id=#{@id} set=#{@is_set}>"
    end
  end
end
