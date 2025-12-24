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
    instance_double(Authentication::Util::NetworkTransporter)
  end

  describe('#initialize') do
    context 'with HTTP URL on allowlist' do
      it 'creates client successfully for localhost' do
        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'http://localhost:8080',
            http_allowlist: ['localhost', '127.0.0.1']
          )
        }.not_to raise_error
      end

      it 'creates client successfully for 127.0.0.1' do
        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'http://127.0.0.1:8080',
            http_allowlist: ['localhost', '127.0.0.1']
          )
        }.not_to raise_error
      end

      it 'creates client successfully for custom hostname on allowlist' do
        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'http://internal-service:8080',
            http_allowlist: ['localhost', 'internal-service']
          )
        }.not_to raise_error
      end
    end

    context 'with HTTP URL not on allowlist' do
      it 'raises HttpNotAllowed error' do
        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'http://untrusted-host:8080',
            http_allowlist: ['localhost', '127.0.0.1']
          )
        }.to raise_error(Errors::Authentication::Security::HttpNotAllowed) do |error|
          expect(error.message).to include('untrusted-host')
          expect(error.message).to include('not allowed')
          expect(error.message).to include('CONJUR_AUTHENTICATOR_SERVICE_HTTP_ALLOWLIST')
        end
      end

      it 'raises HttpNotAllowed error for external domain' do
        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'http://evil.example.com',
            http_allowlist: ['localhost']
          )
        }.to raise_error(Errors::Authentication::Security::HttpNotAllowed)
      end
    end

    context 'with HTTPS URL' do
      it 'creates client successfully without CA cert (uses system bundle)' do
        client = described_class.new(
          http_client: transporter_class,
          authenticator_service_url: 'https://saas-authn.com',
          ca_cert_path: nil,
          http_allowlist: ['localhost']
        )

        expect(transporter_class).to have_received(:new).with(
          hostname: 'https://saas-authn.com',
          ca_certificate: nil
        )
      end

      it 'creates client successfully with custom CA cert' do
        ca_cert_content = "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----"
        allow(File).to receive(:read).with('/path/to/ca.pem').and_return(ca_cert_content)

        client = described_class.new(
          http_client: transporter_class,
          authenticator_service_url: 'https://saas-authn.com',
          ca_cert_path: '/path/to/ca.pem',
          http_allowlist: ['localhost']
        )

        expect(transporter_class).to have_received(:new).with(
          hostname: 'https://saas-authn.com',
          ca_certificate: ca_cert_content
        )
      end

      it 'does not check allowlist for HTTPS URLs' do
        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'https://external-service.com',
            http_allowlist: ['localhost']
          )
        }.not_to raise_error
      end
    end

    context 'with default configuration' do
      it 'uses default allowlist from Rails config' do
        allow(Rails.application.config.conjur_config).to receive(:authenticator_service_http_allowlist)
          .and_return(['localhost', '127.0.0.1', '::1', 'host.docker.internal'])

        expect {
          described_class.new(
            http_client: transporter_class,
            authenticator_service_url: 'http://host.docker.internal:8080'
          )
        }.not_to raise_error
      end
    end
  end

  describe('.validate_certificate') do
    let(:transporter) do
      instance_double(Authentication::Util::NetworkTransporter).tap do |double|
        allow(double).to receive(:post).and_return(saas_authn_response)
      end
    end

    let(:client) do
      described_class.new(
        http_client: transporter_class,
        authenticator_service_url: 'http://localhost:8080',
        http_allowlist: ['localhost']
      )
    end

    context 'when http client returns a success response' do
      let(:saas_authn_response) do
        Responses::Success.new(saas_authn_response_body)
      end

      context 'when the body is malformed' do
        let(:saas_authn_response_body) { {} }

        it 'returns a failure response' do
          expect(transporter).to receive(:post).with(
            path: '/authentications/cert',
            body: { 'payload' => 'some-cert', 'configuration' => {} },
            request_type: :json,
            error_type: :json
          )

          response = client.validate_certificate(certificate: 'some-cert', authenticator: authenticator)
          expect(response.success?).to be(false)
          expect(response.message).to eq('Empty or malformed certificate attributes')
          expect(response.exception.class).to be(Errors::Authentication::Service::BadResponse)
          expect(response.status).to eq(:unauthorized)
        end
      end

      context 'when the body is well-formed' do
        let(:saas_authn_response_body) { { 'attributes' => { 'some-attr' => 'some-value' } } }

        it 'is returned by the saas core client' do
          expect(transporter).to receive(:post).with(
            path: '/authentications/cert',
            body: { 'payload' => 'some-cert', 'configuration' => {} },
            request_type: :json,
            error_type: :json
          )

          response = client.validate_certificate(certificate: 'some-cert', authenticator: authenticator)
          expect(response.success?).to be(true)
          expect(response.result).to eq({ 'attributes' => { 'some-attr' => 'some-value' } })
        end
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
