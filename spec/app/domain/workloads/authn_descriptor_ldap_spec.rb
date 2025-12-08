# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do

    describe 'type is ldap' do
      let(:valid_type) { 'ldap' }
      let(:valid_service_id) { 'ldap-service-id-1' }
      let(:valid_data) { { bind_password: 'bind!password' } }

      let(:input) { { type: valid_type, service_id: valid_service_id, data: valid_data } }

      def check_authn_descriptor(authn_descriptor, data = valid_data)
        expect(authn_descriptor.type).to eq(valid_type)
        expect(authn_descriptor.service_id).to eq(valid_service_id)
        expect(authn_descriptor.data).to eq(data)
      end

      it 'creates a valid authn descriptor' do
        authn_descriptor = described_class.new(**input)
        check_authn_descriptor(authn_descriptor)
      end

      # invalid data

      it 'creates a valid authn descriptor with empty data' do
        authn_descriptor = described_class.new(**input.merge(data: {}))
        check_authn_descriptor(authn_descriptor, {})
      end

      [:symbol, 34, true, [], {}, //]
        .each do |invalid_bind_password|
        it "raises DomainValidationError when data has invalid data bind_password = '#{invalid_bind_password}'" do
          expect {
            described_class.new(**input.merge(data: { bind_password: invalid_bind_password }))
          }.to raise_error(Validation::DomainValidationError,
                           "Data bind_password must be a string")
        end
      end

      [:symbol, 34, true, [], {}, //]
        .each do |invalid_tls_ca_cert|
        it "raises DomainValidationError when data has invalid data bind_password = '#{invalid_tls_ca_cert}'" do
          expect {
            described_class.new(**input.merge(data: { bind_password: "bind_pass_test_val",
                                                      tls_ca_cert: invalid_tls_ca_cert }))
          }.to raise_error(Validation::DomainValidationError,
                           "Data tls_ca_cert must be a string")
        end
      end

      it "raises DomainValidationError when data has tls_ca_cert without bind_password" do
        expect {
          described_class.new(**input.merge(data: { tls_ca_cert: 'tls_ca_cert' }))
        }.to raise_error(Errors::Conjur::ParameterMissing,
                         "CONJ00190W Missing required parameter: The 'bind_password' field must be specified when the 'tls_ca_cert' field is provided.")
      end
    end
  end
end
