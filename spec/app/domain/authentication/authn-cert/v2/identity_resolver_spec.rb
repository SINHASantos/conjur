# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::IdentityResolver) do
  let(:resolver) { described_class.new(authenticator: authenticator) }
  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: 'rspec',
      service_id: 'foo',
      variables: {}
    )
  end

  describe '.call', type: 'unit' do
    it 'returns the identity' do
      response = resolver.call(credential: '')
      expect(response.success?).to be(true)
      expect(response.result).to eq('rspec:user:alice')
    end
  end
end
