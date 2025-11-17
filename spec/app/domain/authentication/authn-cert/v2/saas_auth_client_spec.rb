# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::SaasAuthClient) do
  let(:client) { described_class.new }

  describe '.do', type: 'unit' do
    it 'returns certificate attributes' do
      response = client.do(certificate: 'my-cert', authenticator: nil)
      expect(response.success?).to be(true)
      expect(response.result).to have_key(:attributes)
    end
  end
end
