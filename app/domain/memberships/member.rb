# frozen_string_literal: true

module Memberships
  class Member
    extend(Domain)
    include Domain
    include Validation
    include ActiveModel::Validations

    MEMBER_KINDS = %w[host user group].freeze
    MEMBER_KINDS_MSG = "'%{value}' is not a valid member kind"

    validates :kind, presence: true, inclusion: { in: MEMBER_KINDS, message: MEMBER_KINDS_MSG }
    validates :id, presence: true, format: { with: USER_PATH_PATTERN, message: USER_PATH_PATTERN_MSG }, if: -> { kind == 'user' }
    validates :id, presence: true, format: { with: PATH_PATTERN, message: PATH_PATTERN_MSG }, unless: -> { kind == 'user' }
    validates :id, length: { minimum: PATH_LENGTH_MIN, maximum: PATH_LENGTH_MAX }
    validate -> { validate_identifier(:id, id) }, if: -> { kind != 'user' }

    attr_accessor :kind, :id

    def initialize(**params)
      @kind = params[:kind]
      @id = params[:id]

      raise DomainValidationError, errors.full_messages.to_sentence if invalid?
    end

    def to_s
      "#<Member kind=#{@kind} id=#{@id}>"
    end

    def as_json(options = {})
      super(options).except("context_for_validation", "errors")
    end

    def self.from_model(membership_db)
      new(**{kind: kind(membership_db.member_id),
             id: identifier(membership_db.member_id)})
    end
  end
end
