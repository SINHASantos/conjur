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
      variables: {}
    )
  end

  describe '.valid?', type: 'unit' do
    let(:annotations) { {} }
    let(:credential_attributes) { {} }

    it 'is valid' do
      response = validation.valid?
      expect(response).to be(true)
    end
  end
end
