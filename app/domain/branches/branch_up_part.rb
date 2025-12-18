# frozen_string_literal: true

module Branches
  class BranchUpPart
    include Domain
    include Validation
    include ActiveModel::Validations

    attr_reader :owner, :annotations

    validates :owner, exclusion: { in: [nil], message: "cannot be nil" }
    validates :annotations, exclusion: { in: [nil], message: "cannot be nil" }

    def initialize(**params)
      @owner = params[:owner] ? Branches::Owner.new(**params[:owner]) : Branches::Owner.new
      @annotations = params[:annotations] ? Annotations::Annotations.new(params[:annotations]) : Annotations::Annotations.new

      raise DomainValidationError, errors.full_messages.to_sentence if invalid?
    end

    def to_s
      "#<BranchUpPart owner=#{@owner} annotations=#{@annotations}>"
    end
  end
end
