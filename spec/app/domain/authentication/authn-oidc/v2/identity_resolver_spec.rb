# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnOidc::V2::IdentityResolver) do
  let(:resolver) do
    described_class.new(
      authenticator: authenticator
    )
  end

  let(:jwt_payload) { { 'claim_mapping' => 'alice', 'nonce': 'nonce' } }

  let(:mapping) { 'claim_mapping' }
  let(:authenticator) do
    AuthenticatorsV2::OidcAuthenticatorType.new(
      account: "rspec",
      service_id: "foo",
      variables: {
        redirect_uri: "http://conjur/authn-oidc/cucumber/authenticate",
        provider_uri: "http://test",
        name: "foo",
        client_id: "ConjurClient",
        client_secret: 'client_secret',
        claim_mapping: mapping
      }
    )
  end

  describe '.call', type: 'unit' do
    context 'when target role is a user' do
      context 'when identity claim mapping is in the claim set' do
        it 'returns the identity' do
          response = resolver.call(credential: jwt_payload)
          expect(response.success?).to be(true)
          expect(response.result).to eq('rspec:user:alice')
        end
      end
      context 'when identity claim mapping is not in the claim set' do
        let(:jwt_payload) { { 'foo' => 'bob', 'nonce': 'nonce' } }
        it 'returns nil' do
          response = resolver.call(credential: jwt_payload)
          expect(response.success?).to be(false)
          expect(response.exception.class).to be(Errors::Authentication::AuthnOidc::IdTokenClaimNotFoundOrEmpty)
          expect(response.exception.message).to eq("CONJ00013E Claim 'claim_mapping' not found or empty in ID token. This claim is defined in the claim-mapping variable.")
          expect(response.status).to eq(:unauthorized)
        end
      end
    end
  end
end
