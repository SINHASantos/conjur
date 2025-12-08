  # frozen_string_literal: true

module Branches
  class Branch
    extend(Domain)
    include Domain
    include Validation
    include ActiveModel::Validations

    attr_reader :name, :branch, :owner, :annotations

    validates :name, :branch, :owner,  presence: true
    validates :annotations, exclusion: { in: [nil], message: "cannot be nil" }
    validates :name, length: { minimum: NAME_LENGTH_MIN, maximum: NAME_LENGTH_MAX }
    validates :name, format: { with: NAME_PATTERN, message: NAME_PATTERN_MSG }
    validates :branch, length: { minimum: PATH_LENGTH_MIN }
    validates :branch, format: { with: PATH_PATTERN, message: PATH_PATTERN_MSG }
    validate :validate_branch_and_name

    def initialize(**params)
      @name = params[:name]
      @branch = params[:branch]
      @owner = params[:owner] ? Owner.new(**params[:owner]) : Owner.new
      @annotations = params[:annotations] ? Annotations::Annotations.new(params[:annotations]) : Annotations::Annotations.new

      raise DomainValidationError, errors.full_messages.to_sentence if invalid?
    end

    def to_s
      "#<Branch name=#{@name} branch=#{@branch} owner=#{@owner} annotations=#{@annotations}>"
    end

    def as_json(options = {})
      super(options).except("context_for_validation", "errors")
    end

    def self.from_model(model)
      new(name: res_name(model.identifier), # name
          branch: parent_of(model.identifier), # branch
          owner: { kind: kind(model.owner_id), id: identifier(model.owner_id) }, # owner
          annotations: Annotations::Annotations.from_model(model.annotations)) # annotations
    end

    def identifier
      to_identifier(@branch, @name)
    end

    private

    def validate_branch_and_name
      if @branch && @name
        validate_identifier("Identifier(branch/name)", to_identifier(@branch, @name))
      end
    end
  end
end
