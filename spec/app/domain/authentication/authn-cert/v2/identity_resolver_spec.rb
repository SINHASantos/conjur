# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::IdentityResolver) do
  let(:account) { 'rspec' }
  let(:id) { 'alice' }
  let(:credential) { nil }

  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: account,
      service_id: 'foo',
      variables: variables
    )
  end

  let(:resolver) { described_class.new(authenticator: authenticator) }

  describe '#call', type: 'unit' do
    context 'when host_mode variable is set to "spiffe"' do
      let(:variables) { { host_mode: 'spiffe' } }

      it 'sources identity from the provided credential' do
        expect(resolver).to receive(:identity_from_credential).with(credential).and_return(Responses::Success.new(id))

        response = resolver.call(id: id, credential: credential)
        expect(response.success?).to be(true)
        expect(response.result).to eq("#{account}:user:#{id}")
      end
    end

    context 'when host_mode variable is set to "request"' do
      let(:variables) { { host_mode: 'request' } }

      it 'sources identity from the parameter-provided ID' do
        expect(resolver).to receive(:identity_from_role_id).with(id).and_return(Responses::Success.new("#{account}:user:#{id}"))

        response = resolver.call(id: id, credential: credential)
        expect(response.success?).to be(true)
        expect(response.result).to eq("#{account}:user:#{id}")
      end
    end

    context 'when host_mode variable is set to any other value' do
      let(:variables) { { host_mode: 'invalid-mode' } }

      it 'returns a failure' do
        response = resolver.call(id: id, credential: credential)
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(Errors::Authentication::Certificate::InvalidConfig)
        expect(response.exception.message).to include('Invalid host mode: invalid-mode')
      end
    end

    context 'when host_mode variable is missing' do
      let(:variables) { {} }

      it 'sources identity from the parameter-provided ID' do
        expect(resolver).to receive(:identity_from_role_id).with(id).and_return(Responses::Success.new("#{account}:user:#{id}"))

        response = resolver.call(id: id, credential: credential)
        expect(response.success?).to be(true)
        expect(response.result).to eq("#{account}:user:#{id}")
      end
    end
  end

  describe '#identity_from_credential', type: 'unit' do
    context 'when trust_domain variable is missing' do
      let(:variables) { {} }

      it 'returns a failure response' do
        response = resolver.identity_from_credential(credential)
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(Errors::Authentication::Certificate::NoTrustDomain)
      end
    end

    context 'when trust_domain variable is present but invalid' do
      let(:variables) { { trust_domain: 'invalid$%^&*' } }

      it 'returns a failure response' do
        response = resolver.identity_from_credential(credential)
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(Errors::Authentication::Certificate::InvalidTrustDomain)
      end
    end

    context 'when identity_path variable is missing' do
      let(:variables) { { trust_domain: 'trust.com' } }

      it 'returns a failure response' do
        response = resolver.identity_from_credential(credential)
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(Errors::Authentication::Certificate::NoIdentityPath)
      end
    end

    context 'when authenticator is properly configured' do
      let(:variables) { { trust_domain: 'trust.com', identity_path: '/path/in/policy' } }

      context 'when client certificate has less than 1 URI SAN' do
        let(:credential) { {} }

        it 'returns a failure response' do
          response = resolver.identity_from_credential(credential)
          expect(response.success?).to be(false)
          expect(response.exception.class).to be(Errors::Authentication::Certificate::BadURISANCount)
        end
      end

      context 'when client certificate has more than 1 URI SAN' do
        let(:credential) { { 'san_uri' => [ 'a.com', 'b.com' ] } }

        it 'returns a failure response' do
          response = resolver.identity_from_credential(credential)
          expect(response.success?).to be(false)
          expect(response.exception.class).to be(Errors::Authentication::Certificate::BadURISANCount)
        end
      end

      context 'when the client certificate contains exactly 1 URI SAN' do
        let(:credential) { { 'sans_uri' => [ uri_san ] } }

        context 'when the URI cannot be properly parsed' do
          let(:uri_san) { 'some-uri' }

          it 'returns a failure response' do
            expect(URI).to receive(:parse).and_raise(URI::InvalidURIError)

            response = resolver.identity_from_credential(credential)
            expect(response.success?).to be(false)
            expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
            expect(response.exception.message).to include('must be valid URI')
          end
        end

        context 'when the URI includes a query' do
          let(:uri_san) { 'trust.com/path?query' }

          it 'returns a failure response' do
            response = resolver.identity_from_credential(credential)
            expect(response.success?).to be(false)
            expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
            expect(response.exception.message).to include('must not include a query component')
          end
        end

        context 'when the URI includes a fragment' do
          let(:uri_san) { 'trust.com/path#query' }

          it 'returns a failure response' do
            response = resolver.identity_from_credential(credential)
            expect(response.success?).to be(false)
            expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
            expect(response.exception.message).to include('must not include a fragment component')
          end
        end

        context 'when the URI includes a port' do
          let(:uri_san) { 'https://trust.com:9876/path' }

          it 'returns a failure response' do
            response = resolver.identity_from_credential(credential)
            expect(response.success?).to be(false)
            expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
            expect(response.exception.message).to include('must not include a port')
          end
        end

        context 'when the URI includes userinfo' do
          let(:uri_san) { 'https://user:password@trust.com/path' }

          it 'returns a failure response' do
            response = resolver.identity_from_credential(credential)
            expect(response.success?).to be(false)
            expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
            expect(response.exception.message).to include('must not include userinfo')
          end
        end

        context 'when the URI is valid' do
          context 'when the URI has an invalid scheme' do
            let(:uri_san) { 'https://trust.com/path' }

            it 'returns a failure response' do
              response = resolver.identity_from_credential(credential)
              expect(response.success?).to be(false)
              expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
              expect(response.exception.message).to include('scheme must be \'spiffe://\'')
            end
          end

          context 'when the URI has an invalid trust domain' do
            let(:uri_san) { 'spiffe://sl!ghtlym~lformed/path' }

            it 'returns a failure response' do
              response = resolver.identity_from_credential(credential)
              expect(response.success?).to be(false)
              expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
              expect(response.exception.message).to include('malformed trust domain')
            end
          end

          context 'when the URI does not include a SPIFFE workload ID' do
            let(:uri_san) { 'spiffe://trust.com' }

            it 'returns a failure response' do
              response = resolver.identity_from_credential(credential)
              expect(response.success?).to be(false)
              expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
              expect(response.exception.message).to include('must include workload ID')
            end
          end

          context 'when the URI includes a SPIFFE workload ID with invalid segments' do
            let(:uri_san) { 'spiffe://trust.com/.././workload' }

            it 'returns a failure response' do
              response = resolver.identity_from_credential(credential)
              expect(response.success?).to be(false)
              expect(response.exception.class).to be(Errors::Authentication::Certificate::MalformedSPIFFEID)
              expect(response.exception.message).to include('invalid path segment \'..\'')
            end
          end

          context 'when the URI is a valid SPIFFE ID' do
            context 'when the SPIFFE ID does not match the expected trust_domain' do
              let(:uri_san) { 'spiffe://belief.com/path/to/workload' }

              it 'returns a failure response' do
                response = resolver.identity_from_credential(credential)
                expect(response.success?).to be(false)
                expect(response.exception.class).to be(Errors::Authentication::Certificate::TrustDomainMismatch)
              end
            end

            context 'when the SPIFFE ID matches the expected trust_domain' do
              let(:uri_san) { 'spiffe://trust.com/path/to/spiffe/workload' }

              it 'returns the identity in a success response' do
                response = resolver.identity_from_credential(credential)
                expect(response.success?).to be(true)
                expect(response.result).to eq('host/path/to/spiffe/workload')
              end
            end
          end
        end
      end
    end
  end
end
