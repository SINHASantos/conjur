# spec/domain/annotation/annotation_spec.rb
require 'spec_helper'

class SubjectClass
  include Validation
  include Domain
  include ActiveModel::Validations
  attr_accessor :branch, :name, :id, :kind

  validate -> { validate_is_class(:branch, branch, String) }

  def initialize(**params)
    @branch = params[:branch]
    @name = params[:name]
    @kind = params[:kind]
    @id = params[:id]

    raise DomainValidationError, errors.full_messages.to_sentence if invalid?
  end
end

RSpec.describe Validation do
  let(:branch) { 'main' }
  let(:name) { 'example' }
  let(:kind) { 'user' }
  let(:id) { 'user123' }
  let(:input) { {branch:, kind:, name:, id:} }
  let(:validator) { SubjectClass.new(**input) }

  describe '#validate_is_class' do
    it 'all proper data' do
      expect {
        SubjectClass.new(**input)
      }.not_to raise_error
    end

    it 'branch has invalid class' do
      expect {
        SubjectClass.new(**input.merge(branch: 123))
      }.to raise_error(Validation::DomainValidationError,
                       "Branch must be a string")
    end

    it 'kind has invalid class' do
      expect(validator.errors[:kind]).to be_empty
      validator.validate_is_class(:kind, 456, String, msg: 'Oh no!')
      expect(validator.errors[:kind]).not_to be_empty
    end

    it 'branch has invalid class' do
      expect {
        SubjectClass.new(**input.merge(branch: 123))
      }.to raise_error(Validation::DomainValidationError,
                       "Branch must be a string")
    end

    it 'kind has invalid class and using custom exception' do
      expect {
        validator.validate_is_class(:kind, 456, String,
                                   exc: Errors::Conjur::ParameterMissing)
      }.to raise_error(Errors::Conjur::ParameterMissing,
                       "CONJ00190W Missing required parameter: Kind must be a string")
    end

    it 'kind has invalid class and using custom exception' do
      expect {
        validator.validate_is_class(:kind, 456, String,
                                   msg: 'is not a string',
                                   exc: Errors::Conjur::ParameterMissing)
      }.to raise_error(Errors::Conjur::ParameterMissing,
                       "CONJ00190W Missing required parameter: Kind is not a string")
    end

  end
end