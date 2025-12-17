# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::IpAddress) do
  let(:matcher) { described_class.new }

  def assert_on_failure(response, contained_message)
    expect(response.success?).to be(false)
    expect(response.message).to be_a(message_class)
    expect(response.to_s).to include(contained_message)
  end

  describe '#valid?', type: 'unit' do
    let(:message_class) { LogMessages::Authentication::AuthnCert::IPPatternValidationFailed }

    context 'when pattern is empty' do
      it 'returns false' do
        assert_on_failure(matcher.valid?(''), "pattern may not be empty")
        assert_on_failure(matcher.valid?('   '), "pattern may not be empty")
        assert_on_failure(matcher.valid?(nil), "pattern may not be empty")
      end
    end

    context 'when pattern includes a wildcard' do
      it 'returns false' do
        assert_on_failure(matcher.valid?('192.168.*.1'), "wildcards not allowed")
      end
    end

    context 'when pattern is in CIDR notation' do
      it 'returns false' do
        assert_on_failure(matcher.valid?('192.168.1.0/24'), "CIDR notation not allowed")
      end
    end

    context 'when pattern is not a valid IP address' do
      it 'returns false' do
        assert_on_failure(matcher.valid?('999.999.999.999'), "invalid IP address")
        assert_on_failure(matcher.valid?('not.an.ip.address'), "invalid IP address")
      end
    end

    context 'when pattern is a valid IP address' do
      it 'returns true' do
        expect(matcher.valid?('192.168.1.1').success?).to be(true)
      end
    end
  end

  describe '#match?', type: 'unit' do
    let(:message_class) { LogMessages::Authentication::AuthnCert::IPPatternMatchingFailed }

    context 'when pattern matches candidate exactly' do
      it 'returns true' do
        expect(matcher.match?('192.168.1.1', '192.168.1.1').success?).to be(true)
      end
    end

    context 'when pattern does not match candidate' do
      it 'returns false' do
        assert_on_failure(matcher.match?('198.51.100.0/22', '198.51.100.1'), "failed to match")
        assert_on_failure(matcher.match?('192.168.1.1', '192.168.1.2'), "failed to match")
      end
    end
  end
end
