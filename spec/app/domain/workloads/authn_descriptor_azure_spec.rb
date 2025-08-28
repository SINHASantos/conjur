# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do

    describe 'type is azure' do
      let(:valid_type) { 'azure' }
      let(:valid_service_id) { 'azure-service-id' }
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
        context "with valid data using azur data keys" do
          it "accepts all allowed keys with valid values" do
            valid_data = Workloads::Validating::AuthnDescriptorValidation::AZURE_DATA_KEYS
                           .map { |adk| { adk => "azuredatavalue" } }
                           .reduce({}, :merge)
                           .symbolize_keys
            expect {
              described_class.new(**input.merge(data: valid_data))
            }.not_to raise_error
          end
        end

        context "with unexpected keys" do
          it "raises error for unexpected key" do
            invalid_data = { unexpected: "value" }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data unexpected fields in Azure authenticator data: unexpected")
          end
        end

        context "with invalid subscription_id" do
          it "raises error for non-string" do
            invalid_data = { subscription_id: 123 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data azure subscription_id must be a string")
          end

          it "raises error for invalid format" do
            invalid_data = { subscription_id: "sub@id" }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data azure subscription_id must contain only letters, digits, and hyphens")
          end
        end

        context "with invalid resource_group" do
          it "raises error for non-string" do
            invalid_data = { resource_group: 123 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data azure resource_group must be a string between 1 and 90 characters")
          end

          it "raises error for too long string" do
            invalid_data = { resource_group: "a" * 91 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data azure resource_group must be a string between 1 and 90 characters")
          end

          it "raises error for invalid characters" do
            invalid_data = { resource_group: "group$" }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data azure resource_group can only contain alphanumeric characters, underscores, periods, hyphens, and parentheses")
          end
        end

        context "with invalid user_assigned_identity" do
          it "raises error for non-string" do
            invalid_data = { user_assigned_identity: 123 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data user_assigned_identity must be a string")
          end

          it "raises error for invalid format" do
            invalid_data = { user_assigned_identity: "bad!identity" }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data user_assigned_identity must match regex ^[\\w\\-.,@:/+= ]*$ and be 1-1000 characters.")
          end

          it "raises error for too long string" do
            invalid_data = { user_assigned_identity: "a" * 1001 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data user_assigned_identity must match regex ^[\\w\\-.,@:/+= ]*$ and be 1-1000 characters.")
          end
        end

        context "with invalid system_assigned_identity" do
          it "raises error for non-string" do
            invalid_data = { system_assigned_identity: 123 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data system_assigned_identity must be a string")
          end

          it "raises error for invalid format" do
            invalid_data = { system_assigned_identity: "bad!identity" }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data system_assigned_identity must match regex ^[\\w\\-.,@:/+= ]*$ and be 1-1000 characters.")
          end

          it "raises error for too long string" do
            invalid_data = { system_assigned_identity: "a" * 1001 }
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data system_assigned_identity must match regex ^[\\w\\-.,@:/+= ]*$ and be 1-1000 characters.")
          end
        end
      end
    end
  end
end
