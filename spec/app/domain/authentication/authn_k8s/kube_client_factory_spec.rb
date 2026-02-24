# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::KubeClientFactory) do
  let(:api) { 'api' }
  let(:version) { 'v1' }
  let(:options) { { ssl_options: { verify_ssl: 0 } } }

  describe '.client' do
    context 'with a valid host_url' do
      it 'builds a client with the api path appended' do
        host_url = 'https://example.com/root'
        expected_url = 'https://example.com/root/api'
        client_double = instance_double(Kubeclient::Client)

        allow(Kubeclient::Client)
          .to receive(:new)
          .with(expected_url, version, **options)
          .and_return(client_double)

        result = described_class.client(
          api: api,
          version: version,
          host_url: host_url,
          options: options
        )

        expect(result).to eq(client_double)
      end

      it 'handles trailing slashes in the host_url' do
        host_url = 'https://example.com/root/'
        expected_url = 'https://example.com/root/api'
        client_double = instance_double(Kubeclient::Client)

        allow(Kubeclient::Client)
          .to receive(:new)
          .with(expected_url, version, **options)
          .and_return(client_double)

        result = described_class.client(
          api: api,
          version: version,
          host_url: host_url,
          options: options
        )

        expect(result).to eq(client_double)
      end
    end

    context 'with an invalid host_url' do
      it 'raises InvalidApiUrl when host_url is nil' do
        expect do
          described_class.client(
            api: api,
            version: version,
            host_url: nil,
            options: options
          )
        end.to raise_error(Errors::Authentication::AuthnK8s::InvalidApiUrl)
      end

      it 'raises InvalidApiUrl when host_url has no host' do
        host_url = 'http://'

        expect do
          described_class.client(
            api: api,
            version: version,
            host_url: host_url,
            options: options
          )
        end.to raise_error(Errors::Authentication::AuthnK8s::InvalidApiUrl)
      end
    end
  end
end
