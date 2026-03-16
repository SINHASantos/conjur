# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do

    describe 'invalid input' do
      let(:valid_type) { 'aws' }
      let(:valid_service_id) { 'default' }
      let(:valid_data) { {} }

      let(:input) { { type: valid_type, service_id: valid_service_id, data: valid_data } }

      (Workloads::AuthnDescriptor::TYPES - [Workloads::AuthnDescriptor::API_KEY]).each do |type|
        it "creates a valid authn descriptor with empty data hash" do
          expect {
            described_class.new(**input.merge(type:, data: {}))
          }.not_to raise_error
        end
      end

      # invalid type

      ['', ' ', 'some string']
        .each do |invalid_type|
        it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
          expect {
            described_class.new(**input.merge(type: invalid_type))
          }.to raise_error(Validation::DomainValidationError,
                           /Type contains unsupported value:/)
        end
      end

      [nil, :symbol, 34, true, [], {}, //]
        .each do |invalid_type|
        it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
          expect {
            described_class.new(**input.merge(type: invalid_type))
          }.to raise_error(Validation::DomainValidationError)
        end
      end

      # invalid service_id

      [//]
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must be a string and Service must contain only alphanumeric characters, underscores, and hyphens')
        end
      end

      [34]
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must be a string and Service must be between 3 and 60 characters')
        end
      end

      ['!wrong', 'service id', 'service@id', 'service.id']
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must contain only alphanumeric characters, underscores, and hyphens')
        end
      end

      ['', ' ']
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must contain only alphanumeric characters, underscores, and hyphens and Service must be between 3 and 60 characters')
        end
      end

      ['a', 'aa', 'a' * 61]
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must be between 3 and 60 characters')
        end
      end

      [:symbol, true]
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must be a string')
        end
      end

      [nil, [], {}]
        .each do |invalid_service_id|
        it "raises DomainValidationError when service_id has invalid value = #{invalid_service_id}" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           'Service must be a string, Service must contain only alphanumeric characters, underscores, and hyphens, and Service must be between 3 and 60 characters')
        end
      end

      # invalid data
      it 'creates a valid descriptor when data is nil' do
        expect {
          described_class.new(**input.merge(data: nil))
        }.not_to raise_error
      end

      ['', ' ', 'non-empty', :symbol, 34, true, [], //]
        .each do |invalid_data|
        it "raises DomainValidationError when data has invalid value '#{invalid_data}'" do
          expect {
            described_class.new(**input.merge(data: invalid_data))
          }.to raise_error(Validation::DomainValidationError,
                           'Data must be a hash')
        end
      end
    end
  end
end
