# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do

    describe 'type is aws' do
      let(:valid_type) { 'aws' }
      let(:valid_service_id) { 'aws-service-id-1' }
      let(:valid_data) { {} }

      let(:input) { { type: valid_type, service_id: valid_service_id, data: valid_data } }

      def check_authn_descriptor(authn_descriptor)
        expect(authn_descriptor.type).to eq(valid_type)
        expect(authn_descriptor.service_id).to eq(valid_service_id)
        expect(authn_descriptor.data).to eq(valid_data)
      end

      it 'creates a valid authn descriptor' do
        authn_descriptor = described_class.new(**input.merge(data: valid_data))
        check_authn_descriptor(authn_descriptor)
      end

      # invalid data

      describe "and data validating" do
        let(:data) do
          (1..Workloads::Validating::AuthnDescriptorValidation::MAX_CLAIMS_SIZE - 4)
            .map { |i| ["aws_claim_key_#{i}", "aws_claim_value_#{i}"] }
            .to_h
            .merge(symbol_key: :symbol_value)
            .merge(empty_string: ' ', one_letter: 'x')
            .symbolize_keys
        end

        it "creates a valid authn descriptor with full data" do
          authn_descriptor = described_class.new(**input.merge(data:))
          expect(authn_descriptor.type).to eq(valid_type)
          expect(authn_descriptor.service_id).to eq(valid_service_id)
          expect(authn_descriptor.data).to eq(data.symbolize_keys)
        end

        # invalid data key

        it "raises DomainValidationError for too big data" do
          invalid_data = (1..Workloads::Validating::AuthnDescriptorValidation::MAX_CLAIMS_SIZE + 1).map { |i| ["aws_claim_key_#{i}", "aws_claim_value_#{i}"] }.to_h
          expect {
            described_class.new(**input.merge(data: invalid_data))
          }.to raise_error(Validation::DomainValidationError,
                           "Data no more than 10 claims are allowed in data")
        end

        it "raises DomainValidationError for too short key" do
          data[''] = "somevalue"
          expect {
            described_class.new(**input.merge(data:))
          }.to raise_error(Validation::DomainValidationError,
                           "Data key parameter length is less than 1 characters")
        end

        it "raises DomainValidationError for too long data key" do
          data["a" * (Validation::PATH_LENGTH_MAX + 1)] = "somevalue"
          expect {
            described_class.new(**input.merge(data:))
          }.to raise_error(Validation::DomainValidationError,
                           "Data key parameter length exceeded. Limit the length to 500 characters")
        end

        [' ', 'wrong!key']
          .each do |bad_key|
          it "raises DomainValidationError for invalid format data key = '#{bad_key}'" do
            data[bad_key] = "somevalue"
            expect {
              described_class.new(**input.merge(data:))
            }.to raise_error(Validation::DomainValidationError,
                             "Data invalid 'key' parameter. Valid characters: letters, numbers, and these special characters are allowed: _ / -. Other characters are not allowed.")
          end
        end

        [nil, 34, true, [], {}, //]
          .each do |bad_key|
          it "raises DomainValidationError for invalid data key = #{bad_key}" do
            data[bad_key] = "somevalue"
            expect {
              described_class.new(**input.merge(data:))
            }.to raise_error(Validation::DomainValidationError,
                             "Data invalid claims parameter. Keys and values must be strings.")
          end
        end

        # invalid data value

        it "raises DomainValidationError for too short data value" do
          data["aws_claim_key"] = ''
          expect {
            described_class.new(**input.merge(data:))
          }.to raise_error(Validation::DomainValidationError,
                           "Data value parameter length is less than 1 characters")
        end

        it "raises DomainValidationError for too long data value" do
          data["aws_claim_key"] = "a" * (Annotations::Annotations::VALUE_LENGTH_MAX + 1)
          expect {
            described_class.new(**input.merge(data:))
          }.to raise_error(Validation::DomainValidationError,
                           "Data value parameter length exceeded. Limit the length to 120 characters")
        end

        ["<badvalue", ">badvalue", "'badvalue", "bad'value"]
          .each do |bad_value|
          it "raises DomainValidationError for invalid format data value = '#{bad_value}'" do
            data["aws_claim_key"] = bad_value
            expect {
              described_class.new(**input.merge(data:))
            }.to raise_error(Validation::DomainValidationError,
                             "Data invalid 'value' parameter. All characters except less than (<), greater than (>), and single quote (') are allowed.")
          end
        end

        [nil, 34, true, [], {}, //]
          .each do |bad_value|
          it "raises DomainValidationError for invalid data value = '#{bad_value}'" do
            data["aws_claim_key"] = bad_value
            expect {
              described_class.new(**input.merge(data:))
            }.to raise_error(Validation::DomainValidationError,
                             "Data invalid claims parameter. Keys and values must be strings.")
          end
        end
      end
    end
  end
end
