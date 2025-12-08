# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Workloads::AuthnDescriptor, type: :model do
  describe 'initialization' do

    describe 'type is cert' do
      let(:valid_type) { 'cert' }
      let(:valid_service_id) { 'cert_service_id' }
      let(:valid_data) do
        {
          "cn" => "valid-cn",
          "san_uri" => ["https://example.com"],
          san_dns: ["example.com"],
          san_ip: ["192.168.1.1"]
        }.deep_symbolize_keys
      end

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

      # data

      describe "and data validating" do
        let(:base_data) do
          {
            cn: "valid-cn",
            san_uri: ["https://example.com"],
            san_dns: ["example.com"],
            san_ip: ["192.168.1.1"]
          }
        end

        it "raises DomainValidationError for unexpected fields in data" do
          invalid_data = { unexpected_field: "value" }
          expect {
            described_class.new(**input.merge(data: invalid_data))
          }.to raise_error(Validation::DomainValidationError,
                           "Data unexpected fields in Certificate authenticator data: unexpected_field")
        end

        # data cn

        context "cn validation" do
          it "accepts valid cn" do
            expect {
              described_class.new(**input.merge(base_data))
            }.not_to raise_error
          end

          [nil, '', ' ', "bad!cn", "a" * 256, 123, [], {}, //, true]
            .each do |bad_cn|
            it "raises DomainValidationError for invalid cn value = #{bad_cn.inspect}" do
              invalid_data = base_data.merge(cn: bad_cn)
              expect {
                described_class.new(**input.merge(data: invalid_data))
              }.to raise_error(Validation::DomainValidationError,
                               "Data invalid certificate cn")
            end
          end
        end

        # data san_uri

        context "san_uri validation" do
          it "accepts valid san_uri" do
            expect {
              described_class.new(**input.merge(base_data))
            }.not_to raise_error
          end

          it "accepts nil san_uri" do
            data = base_data.merge(san_uri: nil)
            expect {
              described_class.new(**input.merge(data: data).deep_symbolize_keys)
            }.not_to raise_error
          end

          it "raises DomainValidationError if san_uri is not an array" do
            invalid_data = base_data.merge(san_uri: "not-an-array")
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data certificate san_uri must be an array")
          end

          [true, :symbol, 123, {}, [], //]
            .each do |bad_uri|
            it "raises DomainValidationError for invalid san_uri value = #{bad_uri.inspect}" do
              invalid_data = base_data.merge(san_uri: [bad_uri])
              expect {
                described_class.new(**input.merge(data: invalid_data))
              }.to raise_error(Validation::DomainValidationError,
                               "Data san_uri must be a string")
            end
          end

          it "raises DomainValidationError for too short san_uri" do
            invalid_data = base_data.merge(san_uri: [''])
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data san_uri parameter length is less than 1 characters")
          end

          [' ', "bad<uri", "bad>uri", "bad?uri", "bad uri"]
            .each do |bad_uri|
            it "raises DomainValidationError for invalid san_uri value = #{bad_uri.inspect}" do
              invalid_data = base_data.merge(san_uri: [bad_uri])
              expect {
                described_class.new(**input.merge(data: invalid_data))
              }.to raise_error(Validation::DomainValidationError,
                               "Data san_uri all characters except space ( ), quotation marks (?), less than (<), and greater than (>) are allowed.")
            end
          end

          it "raises DomainValidationError for too long san_uri value" do
            invalid_data = base_data.merge(san_uri: ["a" * 1001])
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data san_uri parameter length exceeded. Limit the length to 1000 characters")
          end
        end

        # data san_dns

        context "san_dns validation" do
          it "accepts valid san_dns" do
            expect {
              described_class.new(**input.merge(data: base_data).deep_symbolize_keys)
            }.not_to raise_error
          end

          it "accepts nil san_dns" do
            invalid_data = base_data.merge(san_dns: nil)
            expect {
              described_class.new(**input.merge(data: invalid_data).deep_symbolize_keys)
            }.not_to raise_error
          end

          it "raises DomainValidationError if san_dns is not an array" do
            invalid_data = base_data.merge(san_dns: "not-an-array")
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data certificate san_dns must be an array")
          end

          it "raises DomainValidationError for too short san_uri value" do
            invalid_data = base_data.merge(san_dns: [''])
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data san_dns parameter length is less than 1 characters")
          end

          [' ', "bad<uri", "bad>uri", "bad uri"]
            .each do |bad_uri|
            it "raises DomainValidationError for invalid san_uri value = #{bad_uri.inspect}" do
              invalid_data = base_data.merge(san_dns: [bad_uri])
              expect {
                described_class.new(**input.merge(data: invalid_data))
              }.to raise_error(Validation::DomainValidationError,
                               "Data san_dns all characters except space ( ), less than (<), and greater than (>) are allowed.")
            end
          end

          it "raises DomainValidationError for too long san_uri value" do
            invalid_data = base_data.merge(san_dns: ["a" * 1001])
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data san_dns parameter length exceeded. Limit the length to 1000 characters")
          end
        end

        # data san_ip

        context "san_ip validation" do
          it "accepts valid san_ip" do
            expect {
              described_class.new(**input.merge(base_data))
            }.not_to raise_error
          end

          it "accepts nil san_ip" do
            invalid_data = base_data.merge(san_ip: nil)
            expect {
              described_class.new(**input.merge(data: invalid_data).deep_symbolize_keys)
            }.not_to raise_error
          end

          it "raises DomainValidationError if san_ip is not an array" do
            invalid_data = base_data.merge(san_ip: "not-an-array")
            expect {
              described_class.new(**input.merge(data: invalid_data))
            }.to raise_error(Validation::DomainValidationError,
                             "Data certificate san_ip must be an array")
          end

          ["not-an-ip", 123, nil, [], {}, true, //]
            .each do |bad_ip|
            it "raises DomainValidationError for invalid san_ip value = #{bad_ip.inspect}" do
              invalid_data = base_data.merge(san_ip: [bad_ip])
              expect {
                described_class.new(**input.merge(data: invalid_data))
              }.to raise_error(Validation::DomainValidationError,
                               "Data invalid IP address format")
            end
          end

          ["192.168.1.1/24"]
            .each do |bad_ip|
            it "raises DomainValidationError for invalid san_ip value = #{bad_ip.inspect}" do
              invalid_data = base_data.merge(san_ip: [bad_ip])
              expect {
                described_class.new(**input.merge(data: invalid_data))
              }.to raise_error(Validation::DomainValidationError,
                               "Data CIDR notation is not supported in IP addresses")
            end
          end
        end
      end
    end
  end
end
