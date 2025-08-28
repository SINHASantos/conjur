# frozen_string_literal: true

require_relative '../domain'
require_relative '../validation'

module Workloads
  class Workload
    extend(Domain)
    include Domain
    include Validation
    include ActiveModel::Validations
    include Workloads::Validating::WorkloadValidation

    attr_reader :name, :branch, :type, :subtype, :owner,
                :authn_descriptors, :annotations, :restricted_to

    validates :name, :branch, :type, presence: true
    validates :owner, :subtype, presence: true, allow_blank: true
    validate -> { validate_attrs_class([:name, :branch, :type, :subtype], String) }

    validates :name,
              length: { minimum: NAME_LENGTH_MIN, maximum: NAME_LENGTH_MAX },
              format: { with: NAME_PATTERN, message: "Valid characters: letters, numbers, and these special characters are allowed: : _ - . / {}. Other characters are not allowed." },
              if: -> { name.is_a?(String) }

    validates :branch,
              length: { minimum: PATH_LENGTH_MIN, maximum: PATH_LENGTH_MAX },
              format: { with: PATH_PATTERN, message: PATH_PATTERN_MSG },
              if: -> { branch.is_a?(String) }

    validates :type, inclusion: { in: TYPES, message: "contains unsupported value: %{value}" },
              if: -> { type.is_a?(String) }

    validates :subtype, inclusion: { in: KUBE_SUBTYPES, message: "must be one of: #{KUBE_SUBTYPES_STR}" },
              if: -> { kube_type? && in_types? && subtype.is_a?(String) }
    validates :subtype, inclusion: { in: [''], message: "is only allowed for type 'kubernetes'" },
              if: -> { not_kube_type? && in_types? && subtype.is_a?(String) }

    validate :validate_branch_and_name

    def initialize(**params)
      @name = params[:name]
      @branch = params[:branch]
      @type = init_type(params[:type])
      @subtype = init_subtype(params[:type], params[:subtype])
      valid?

      @owner = init_owner(params[:owner])
      @authn_descriptors = init_authn_descriptors(params[:authn_descriptors])
      @annotations = init_annotations(params[:annotations])
      @restricted_to = init_restricted_to(params[:restricted_to] || [])

      raise DomainValidationError.new(errors.full_messages.to_sentence, errors) if errors.present?
    end

    def to_s
      "<Workload name=#{@name} branch=#{@branch} type=#{@type} subtype=#{@subtype}
      owner=#{@owner} annotations=#{@annotations} restricted_to=#{@restricted_to}
      authn_descriptors=#{@authn_descriptors}>"
    end

    def as_json(options = {})
      except_keys = %w[validation_context context_for_validation errors]
      except_keys << "subtype" if @subtype.empty?

      super(options).except(*except_keys)
    end

    def identifier
      to_identifier(@branch, @name)
    end
  end
end
