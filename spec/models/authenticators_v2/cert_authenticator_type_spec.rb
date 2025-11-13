# frozen_string_literal: true

require 'spec_helper'

describe AuthenticatorsV2::CertAuthenticatorType, type: :model do
  include_context 'create user'

  let(:account) { 'rspec' }
  let(:dict) do
    {
      type: 'authn-cert',
      service_id: 'foo',
      enabled: true,
      owner_id: "#{account}:policy:conjur/authn-cert",
      annotations: {},
      variables: variables
    }
  end
  let(:authenticator) { described_class.new(dict) }

  describe '#data' do
    context 'when all data variables are missing' do
      let(:variables) { {} }
      it 'returns an empty hash' do
        data = authenticator.data
        expect(data).to eq({})
      end
    end

    context 'when all identity variables are missing' do
      let(:variables) do
        {
          ca_cert: 'ca bundle',
          crl: 'revocation list'
        }
      end
      it 'returns a hash that does not include the :identity key' do
        data = authenticator.data
        expect(data).to include(ca_cert: 'ca bundle')
        expect(data).to include(crl: 'revocation list')
        expect(data).not_to have_key(:identity)
      end
    end

    context 'when unrecognized variables exist' do
      let(:variables) { { unknown: 'value' } }
      it 'ignores them' do
        data = authenticator.data
        expect(data).to eq({})
      end
    end

    context 'when san_* variables are empty strings' do
      let(:variables) do
        {
          san_uri: '',
          san_dns: '',
          san_ip: ''
        }
      end
      it 'returns empty arrays' do
        data = authenticator.data
        expect(data[:identity][:san_uri]).to eq([])
        expect(data[:identity][:san_dns]).to eq([])
        expect(data[:identity][:san_ip]).to eq([])
      end
    end

    context 'when san_* variables contain comma-delimited strings' do
      let(:variables) do
        {
          san_uri: 'spiffe://trust.com/workload,https://conjur.org',
          san_dns: 'conjur.org,foo.com,bar.org',
          san_ip: '127.0.0.1,255.255.255.255,0:0:0:0:0:0:0:1'
        }
      end
      it 'parses them into arrays' do
        data = authenticator.data
        expect(data[:identity][:san_uri]).to contain_exactly(
          'spiffe://trust.com/workload',
          'https://conjur.org'
        )
        expect(data[:identity][:san_dns]).to contain_exactly(
          'conjur.org',
          'foo.com',
          'bar.org'
        )
        expect(data[:identity][:san_ip]).to contain_exactly(
          '127.0.0.1',
          '255.255.255.255',
          '0:0:0:0:0:0:0:1'
        )
      end
    end

    context 'when san_* variables contain duplicate entries' do
      let(:variables) do
        {
          san_uri: 'https://conjur.org,https://conjur.org',
          san_dns: 'conjur.org,conjur.org',
          san_ip: '127.0.0.1,127.0.0.1'
        }
      end
      it 'returns only unique values' do
        data = authenticator.data
        expect(data[:identity][:san_uri].length).to eq(1)
        expect(data[:identity][:san_dns].length).to eq(1)
        expect(data[:identity][:san_ip].length).to eq(1)
      end
    end

    context 'when san_* variables contain empty entries' do
      let(:variables) do
        {
          san_uri: ',,',
          san_dns: ',,',
          san_ip: ',,'
        }
      end
      it 'ignores them' do
        data = authenticator.data
        expect(data[:identity][:san_uri]).to eq([])
        expect(data[:identity][:san_dns]).to eq([])
        expect(data[:identity][:san_ip]).to eq([])
      end
    end
  end

  describe '#identity_path' do
    context 'when identity_path variable is missing' do
      let(:variables) { {} }
      it 'returns nil' do
        path = authenticator.identity_path
        expect(path).to be_nil
      end
    end

    context 'when identity_path variable exists' do
      let(:variables) { { identity_path: value } }
      context 'but is empty' do
        let(:value) { '' }
        it 'returns an empty string' do
          path = authenticator.identity_path
          expect(path).to eq(value)
        end
      end

      context 'and has been given a value' do
        let(:value) { '/path/to/workloads' }
        it 'returns the value' do
          path = authenticator.identity_path
          expect(path).to eq(value)
        end
      end
    end
  end

  describe '#format_type' do
    let(:variables) { {} }
    it 'returns "certificate" rather than "cert"' do
      formatted_type = authenticator.format_type
      expect(formatted_type).to eq('certificate')
    end
  end
end
