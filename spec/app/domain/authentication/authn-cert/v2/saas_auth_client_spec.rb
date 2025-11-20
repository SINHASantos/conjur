# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::SaasAuthClient) do
  let(:hostname) { "saas-authn.com" }
  let(:port) { 443 }
  let(:path) { "/authentications/cert" }

  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: 'rspec',
      service_id: 'foo',
      variables: {}
    )
  end

  let(:transporter_class) do
    class_double(Authentication::Util::NetworkTransporter).tap do |double|
      allow(double).to receive(:new).and_return(transporter)
    end
  end
  let(:transporter) do
    instance_double(Authentication::Util::NetworkTransporter).tap do |double|
      allow(double).to receive(:post).and_return(saas_authn_response)
    end
  end

  describe('.validate_certificate') do
    let(:client) do
      described_class.new(
        http_client: transporter_class,
        saas_authenticator_url: 'http://saas-authn.com'
      )
    end

    context 'when http client returns a success response' do
      let(:saas_authn_response) do
        Responses::Success.new({ 'attributes' => {} })
      end

      it 'is returned by the saas core client' do
        expect(transporter).to receive(:post).with(
          path: '/authentications/cert',
          body: { 'payload' => 'some-cert', 'configuration' => {} },
          request_type: :json,
          error_type: :json
        )

        response = client.validate_certificate(certificate: 'some-cert', authenticator: authenticator)
        expect(response.success?).to be(true)
        expect(response.result).to eq({ 'attributes' => {} })
      end
    end

    context 'when http client returns a failure response' do
      context 'and it is in the expected format' do
        let(:saas_authn_response) do
          Responses::Failure.new({ 'errors' => [ { 'code' => 'MY_CODE', 'message' => 'MY_MESSAGE' } ] })
        end

        it 'is properly parsed into a failure response instance' do
          expect(transporter).to receive(:post).with(
            path: '/authentications/cert',
            body: { 'payload' => 'some-cert', 'configuration' => {} },
            request_type: :json,
            error_type: :json
          )

          response = client.validate_certificate(certificate: 'some-cert', authenticator: authenticator)
          expect(response.success?).to be(false)
          expect(response.message).to eq('Credential validation failed')
          expect(response.exception.message).to eq('MY_CODE MY_MESSAGE')
          expect(response.status).to eq(:unauthorized)
        end
      end

      context 'and it is not in the expected format' do
        let(:saas_authn_response) do
          Responses::Failure.new({ 'unknown-key': 'worthless-value' })
        end

        it 'returns a custom failure response' do
          response = client.validate_certificate(certificate: 'some-cert', authenticator: authenticator)
          expect(response.success?).to be(false)
          expect(response.message).to eq('Malformed error response from authenticator service')
          expect(response.exception.class).to be(Errors::Authentication::Service::MalformedError)
          expect(response.status).to eq(:unauthorized)
        end
      end
    end
  end
end
