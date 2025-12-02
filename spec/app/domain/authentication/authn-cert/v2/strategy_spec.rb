# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Strategy) do
  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: 'rspec',
      service_id: 'foo',
      variables: {
        ca_cert: 'my-pem-ca',
        crl: 'my-revocation-list'
      }
    )
  end

  let(:certificate_attributes) do
    {
      subject: 'CN=client',
      issuer: 'CN=CyberArk CA',
      san_uri: ['spiffe://trust.com/workload'],
      not_before: '2023-01-01T00:00:00Z',
      not_after: '2024-01-01T00:00:00Z',
      serial_number: '1234567890',
      thumbprint: 'abcdef1234567890abcdef1234567890abcdef12'
    }
  end
  let(:saas_response) { { attributes: certificate_attributes } }

  let(:saas_auth_client) do
    class_double(Authentication::AuthnCert::V2::SaasAuthClient).tap do |double|
      allow(double).to receive(:new).and_return(instantiated_saas_client)
    end
  end
  let(:instantiated_saas_client) do
    instance_double(Authentication::AuthnCert::V2::SaasAuthClient).tap do |double|
      allow(double).to receive(:do).and_return(Responses::Success.new(saas_response))
    end
  end

  let(:strategy) do
    described_class.new(
      authenticator: authenticator,
      saas_auth_client: saas_auth_client
    )
  end

  describe('#callback', type: 'unit') do
    context 'when required headers are present' do
      let(:headers) { { 'X-SSL-Client-Certificate' => 'my-client-pem' } }

      it 'is successful' do
        response = strategy.callback(request_headers: headers)
        expect(response.success?).to be(true)
        expect(response.result.class).to be(Authentication::RoleIdentifier)
        expect(response.result.identifier).to eq('rspec:user:alice')
        expect(response.result.attributes).to eq(certificate_attributes)
      end
    end

    context 'when required headers are missing' do
      let(:headers) { {} }

      it 'is unsuccessful' do
        response = strategy.callback(request_headers: headers)
        expect(response.success?).to be(false)
        expect(response.message).to eq('request header X-SSL-Client-Certificate missing or empty')
      end
    end
  end
end
