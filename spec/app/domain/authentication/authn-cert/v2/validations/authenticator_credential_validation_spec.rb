# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Validations::AuthenticatorCredentialValidation) do
  let(:validation) do
    described_class.new(
      authenticator: authenticator,
      credential_attributes: credential_attributes
    )
  end
  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: 'rspec',
      service_id: 'foo',
      variables: variables
    )
  end

  describe '.valid?', type: 'unit' do
    let(:variables) { {} }
    let(:default_credential_attributes) do
      {
        'sans_dns' => [ 'my.example.com', 'conjur.org' ],
        'sans_uri' => [ 'https://example.org/service/foo' ],
        'sans_ip' => [ '255.255.255.255', '127.0.0.1' ],
        'subject_components' => {
          'common_name' => 'onprem.secretsmanager.cyberark.com'
        }
      }
    end
    let(:credential_attributes) { default_credential_attributes }

    context 'when no global restrictions are present' do
      it 'passes validation' do
        expect(validation.valid?).to be(true)
      end
    end

    context 'when global restrictions are present' do
      let(:variables) do
        {
          san_dns: '*.example.com,conjur.org',
          san_uri: 'https://example.org/service/*',
          san_ip: '127.0.0.1,255.255.255.255',
          cn: '*.*.cyberark.com'
        }
      end

      context 'when credential attributes do not match global restrictions' do
        context 'for DNS names' do
          let(:credential_attributes) { default_credential_attributes.tap { |h| h['sans_dns'][0] = 'notmatching.com' } }
          it 'fails validation' do
            expect(validation.valid?).to be(false)
          end
        end

        context 'for URIs' do
          let(:credential_attributes) { default_credential_attributes.tap { |h| h['sans_uri'][0] = 'https://example.org/x/foo' } }
          it 'fails validation' do
            expect(validation.valid?).to be(false)
          end
        end

        context 'for IP addresses' do
          let(:credential_attributes) { default_credential_attributes.tap { |h| h['sans_ip'][0] = '192.168.1.1' } }
          it 'fails validation' do
            expect(validation.valid?).to be(false)
          end
        end

        context 'for Common Name' do
          let(:credential_attributes) { default_credential_attributes.tap { |h| h['subject_components']['common_name'] = 'onlyone.cyberark.com' } }
          it 'fails validation' do
            expect(validation.valid?).to be(false)
          end
        end
      end

      context 'when credential attributes match global restrictions' do
        it 'passes validation' do
          expect(validation.valid?).to be(true)
        end
      end

      context 'when global restrictions contain invalid wildcard' do
        let(:variables) { { san_dns: 'cyberark.*' } }
        it 'fails validation' do
          expect(validation.valid?).to be(false)
        end
      end
    end
  end
end
