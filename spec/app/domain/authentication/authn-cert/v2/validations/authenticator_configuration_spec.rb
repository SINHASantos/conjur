# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Validations::AuthenticatorConfiguration) do
  let(:validations) { described_class.new }
  let(:default_data) do
    {
      account: 'rspec',
      service_id: 'my-service',
      ca_cert: 'my-pem-certificate'
    }
  end
  let(:data) { default_data }

  context 'when all required data is present' do
    it 'is valid' do
      response = validations.call(**data)
      expect(response.success?).to be(true)
      expect(response.to_h).to eq(data)
    end
  end

  context 'when required configuration is missing' do
    let(:data) do
      {
        crl: "my-revocation-list"
      }
    end

    it 'is not valid' do
      response = validations.call(**data)
      expect(response.success?).to be(false)
      expect(response.errors.count).to eq(3)

      paths = %i[account service_id ca_cert]
      response.errors.each_with_index do |error, idx|
        expect(error.path).to eq([paths[idx]])
        expect(error.text).to eq('is missing')
      end
    end
  end

  context 'with host-mode set to spiffe' do
    let(:data) { default_data.merge!({ host_mode: 'spiffe' }) }

    context 'when additional required configuration is missing' do
      it 'is not valid' do
        response = validations.call(**data)
        expect(response.success?).to be(false)
        expect(response.errors.count).to eq(2)

        expectations = [
          { path: [:trust_domain], text: "variable 'trust-domain' must be used when 'host-mode' is set to 'spiffe'" },
          { path: [:identity_path], text: "variable 'identity-path' must be used when 'host-mode' is set to 'spiffe'" }
        ]

        response.errors.each_with_index do |error, idx|
          expect(error.path).to eq(expectations[idx][:path])
          expect(error.text).to eq(expectations[idx][:text])
        end
      end
    end
  end
end
