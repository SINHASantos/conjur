# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::IpAddress) do
  let(:matcher) { described_class }

  describe '#valid?', type: 'unit' do
    context 'when pattern is empty' do
      it 'returns false' do
        expect(matcher.valid?('')).to be(false)
        expect(matcher.valid?('   ')).to be(false)
        expect(matcher.valid?(nil)).to be(false)
      end
    end

    context 'when pattern includes a wildcard' do
      it 'returns false' do
        expect(matcher.valid?('192.168.*.1')).to be(false)
      end
    end

    context 'when pattern is in CIDR notation' do
      it 'returns false' do
        expect(matcher.valid?('192.168.1.0/24')).to be(false)
      end
    end

    context 'when pattern is not a valid IP address' do
      it 'returns false' do
        expect(matcher.valid?('999.999.999.999')).to be(false)
        expect(matcher.valid?('not.an.ip.address')).to be(false)
      end
    end

    context 'when pattern is a valid IP address' do
      it 'returns true' do
        expect(matcher.valid?('192.168.1.1')).to be(true)
      end
    end
  end

  describe '#match?', type: 'unit' do
    context 'when pattern matches candidate exactly' do
      it 'returns true' do
        expect(matcher.match?('192.168.1.1', '192.168.1.1')).to be(true)
      end
    end

    context 'when pattern does not match candidate' do
      it 'returns false' do
        expect(matcher.match?('198.51.100.0/22', '198.51.100.1')).to be(false)
        expect(matcher.match?('192.168.1.1', '192.168.1.2')).to be(false)
      end
    end
  end
end
