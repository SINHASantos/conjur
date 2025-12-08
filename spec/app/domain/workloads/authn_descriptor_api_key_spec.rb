# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do
    describe 'type is api_key' do
      let(:valid_type) { 'api_key' }
      let(:valid_service_id) { nil }
      let(:valid_data) { nil }

      let(:input) { { type: valid_type }.symbolize_keys }

      def check_authn_descriptor(authn_descriptor)
        expect(authn_descriptor.type).to eq(valid_type)
        expect(authn_descriptor.service_id).to eq('')
        expect(authn_descriptor.data).to eq({})
      end

      it 'creates a valid authn descriptor' do
        authn_descriptor = described_class.new(**input)
        check_authn_descriptor(authn_descriptor)
      end

      # invalid type

      ['', ' ', 'some string']
        .each do |invalid_type|
        it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
          expect {
            described_class.new(**input.merge(type: invalid_type, service_id: "valid_service_id"))
          }.to raise_error(Validation::DomainValidationError,
                           "Type contains unsupported value: #{invalid_type}")
        end
      end

      [nil, :symbol, 34, true, [], {}, //]
        .each do |invalid_type|
        it "raises DomainValidationError when type has invalid value = '#{invalid_type}'" do
          expect {
            described_class.new(**input.merge(type: invalid_type, service_id: "valid_service_id"))
          }.to raise_error(Validation::DomainValidationError,
                           "Type must be a string")
        end
      end

      # invalid service_id

      ['', ' ', 'non-empty', :symbol, 34, true, [], {}, //]
        .each do |invalid_service_id|
        it "raises DomainValidationError when type is api_key and service_id has invalid value = '#{invalid_service_id}'" do
          expect {
            described_class.new(**input.merge(service_id: invalid_service_id))
          }.to raise_error(Validation::DomainValidationError,
                           "Service api_key descriptor must not contain 'service_id'")
        end
      end

      # invalid data

      ['', ' ', 'non-empty', :symbol, 34, true, [], {}, //]
        .each do |invalid_data|
        it "raises DomainValidationError when data has invalid value '#{invalid_data}'" do
          expect {
            described_class.new(**input.merge(data: invalid_data))
          }.to raise_error(Validation::DomainValidationError,
                           "Data api_key descriptor must not contain 'data'")
        end
      end
    end
  end
end
