# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Validations::RoleCredentialValidation) do
  let(:validation) do
    described_class.new(
      annotations: annotations,
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
    let(:annotations) { {} }
    let(:variables) { {} }
    let(:default_credential_attributes) do
      {
        'sans_dns' => [ 'my.example.com', 'conjur.org' ],
        'sans_uri' => [ 'https://example.org/service/foo' ],
        'sans_ip' => [ '256.256.256.256', '127.0.0.1' ],
        'common_name' => 'onprem.secretsmanager.cyberark.com'
      }
    end
    let(:credential_attributes) { default_credential_attributes }

    context 'when no applicable annotations are present' do
      it 'passes validation' do
        expect(validation.valid?).to be(true)
      end
    end

    context 'when annotations are present' do
      let(:annotations) do
        {
          'san-dns' => '*.example.com,conjur.org',
          'san-uri' => 'https://example.org/service/*',
          'san-ip' => '127.0.0.1,256.256.256.256',
          'cn' => '*.*.cyberark.com'
        }
      end

      context 'when credential attributes do not match annotations' do
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
          let(:credential_attributes) { default_credential_attributes.tap { |h| h['sans_ip'][0] = '0.0.0.0' } }
          it 'fails validation' do
            expect(validation.valid?).to be(false)
          end
        end

        context 'for Common Name' do
          let(:credential_attributes) { default_credential_attributes.tap { |h| h['common_name'] = 'onlyone.cyberark.com' } }
          it 'fails validation' do
            expect(validation.valid?).to be(false)
          end
        end
      end

      context 'when credential attributes match annotations' do
        it 'passes validation' do
          expect(validation.valid?).to be(true)
        end
      end

      context 'when annotations contain invalid wildcard' do
        let(:annotations) { { 'san-dns' => 'cyberark.*' } }
        it 'fails validation' do
          expect(validation.valid?).to be(false)
        end
      end
    end

    context 'when a required credential attribute is missing' do
      context 'when sans_dns is missing from credential' do
        let(:annotations) { { 'san-dns' => '*.example.com' } }
        let(:credential_attributes) { { 'common_name' => 'test' } }

        it 'fails validation' do
          expect(validation.valid?).to be(false)
        end
      end

      context 'when sans_dns is empty array' do
        let(:annotations) { { 'san-dns' => '*.example.com' } }
        let(:credential_attributes) { { 'sans_dns' => [] } }

        it 'fails validation' do
          expect(validation.valid?).to be(false)
        end
      end
    end

    context 'when handling whitespace in patterns' do
      context 'when patterns have leading/trailing whitespace' do
        let(:annotations) { { 'san-dns' => ' *.example.com , conjur.org ' } }
        let(:credential_attributes) { { 'sans_dns' => ['api.example.com', 'conjur.org'] } }

        it 'handles whitespace correctly and passes validation' do
          expect(validation.valid?).to be(true)
        end
      end
    end

    context 'when required instance variable is missing' do
      let(:credential_attributes) { { 'subject' => 'CN=test' } }

      context 'when authenticator is nil' do
        let(:authenticator) { nil }

        it 'fails validation due to missing authenticator' do
          expect(validation.valid?).to be(false)
          expect(validation.errors.messages[:authenticator]).to include("can't be blank")
        end
      end

      context 'when credential_attributes is nil' do
        let(:credential_attributes) { nil }

        it 'fails validation due to missing credential_attributes' do
          expect(validation.valid?).to be(false)
          expect(validation.errors.messages[:credential_attributes]).to include("can't be blank")
        end
      end
    end
  end
end
