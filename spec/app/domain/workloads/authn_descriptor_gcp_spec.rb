# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do

    describe 'type is gcp' do
      let(:valid_type) { 'gcp' }
      let(:valid_service_id) { 'default' }
      let(:valid_data) { {} }

      let(:input) { { type: valid_type, service_id: valid_service_id, data: valid_data } }

      def check_authn_descriptor(authn_descriptor)
        expect(authn_descriptor.type).to eq(valid_type)
        expect(authn_descriptor.service_id).to eq(valid_service_id)
        expect(authn_descriptor.data).to eq(valid_data)
      end

      it 'creates a valid authn descriptor' do
        authn_descriptor = described_class.new(**input)
        check_authn_descriptor(authn_descriptor)
      end

      # data

      describe "and data validating" do
        let(:data) do
          {
            "instance_name" => 'test-instance-1',
            "project_id" => 'test-project-1',
            "service_account_id" => 'test-service-account-1',
            "service_account_email" => 'test-1@cyberark.com'
          }
        end

        it "creates a valid authn descriptor with full data" do
          authn_descriptor = described_class.new(**input.merge(data: data).deep_symbolize_keys)
          expect(authn_descriptor.type).to eq(valid_type)
          expect(authn_descriptor.service_id).to eq(valid_service_id)
          expect(authn_descriptor.data).to eq(data.symbolize_keys)
        end

        it "raises DomainValidationError for unexpected fields in data" do
          invalid_data = { "unexpected_field" => "value" }
          expect {
            described_class.new(**input.merge(data: invalid_data))
          }.to raise_error(Validation::DomainValidationError)
        end

        [nil, '', ' ', "a" * 64, "1badname", "bad_name!", "-badname",
         "a" * 63 + "!", :symbol, 34, true, [], {}, //]
          .each do |bad_value|
          it "raises DomainValidationError for invalid instance_name value = #{bad_value}" do
            data["instance_name"] = bad_value
            expect {
              described_class.new(**input.merge(data: data))
            }.to raise_error(Validation::DomainValidationError)
          end
        end

        [nil, '', ' ', "a" * 31, "bad id", "bad_id!", "project@id", :symbol, 34, true, [], {}, //]
          .each do |bad_value|
          it "raises DomainValidationError for invalid project_id values = #{bad_value}" do
            data["project_id"] = bad_value
            expect {
              described_class.new(**input.merge(data: data))
            }.to raise_error(Validation::DomainValidationError)
          end
        end

        [nil, '', ' ', "a" * 101, "bad id", "bad_id!", "account@id", :symbol, 34, true, [], {}, //]
          .each do |bad_value|
          it "raises DomainValidationError for invalid service_account_id value = #{bad_value}" do
            data["service_account_id"] = bad_value
            expect {
              described_class.new(**input.merge(data: data))
            }.to raise_error(Validation::DomainValidationError)
          end
        end

        [nil, '', ' ', "not-an-email", "missingatsign.com", "missingdomain@",
         "@missinglocal.com", "bad@ email.com", :symbol, 34, true, [], {}, //]
          .each do |bad_value|
          it "raises DomainValidationError for invalid service_account_email value = #{bad_value}" do
            data["service_account_email"] = bad_value
            expect {
              described_class.new(**input.merge(data: data))
            }.to raise_error(Validation::DomainValidationError)
          end
        end
      end
    end
  end
end
