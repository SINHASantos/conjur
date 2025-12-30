# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::DnsName) do
  let(:matcher) { described_class.new }

  def assert_on_failure(response, contained_message)
    expect(response.success?).to be(false)
    expect(response.message).to be_a(message_class)
    expect(response.to_s).to include(contained_message)
  end

  describe '#valid?', type: 'unit' do
    let(:message_class) { LogMessages::Authentication::AuthnCert::DNSPatternValidationFailed }

    context 'when pattern does not include a wildcard' do
      context 'when pattern is a valid DNS name' do
        let(:pattern) { 'example.co.uk' }
        it 'returns true' do
          expect(matcher.valid?(pattern).success?).to be(true)
        end
      end
      context 'when pattern is an invalid DNS name' do
        let(:pattern) { 'to be, or not to be?' }
        it 'returns false' do
          assert_on_failure(matcher.valid?(pattern), "invalid DNS name")
        end
      end
      context 'when pattern includes an empty label' do
        context 'as a prefix' do
          let(:pattern) { '.example.com' }
          it 'returns false' do
            assert_on_failure(matcher.valid?(pattern), "empty labels are not allowed")
          end
        end
        context 'in the interior' do
          let(:pattern) { 'test..example.com' }
          it 'returns false' do
            assert_on_failure(matcher.valid?(pattern), "empty labels are not allowed")
          end
        end
        context 'as a suffix' do
          let(:pattern) { 'example.com.' }
          it 'returns false' do
            assert_on_failure(matcher.valid?(pattern), "empty labels are not allowed")
          end
        end
      end
      context 'when pattern is a private non-ICANN domain' do
        let(:pattern) { 'myapp.compute-1.amazonaws.com' }
        it 'returns true' do
          expect(matcher.valid?(pattern).success?).to be(true)
        end
      end
    end
    context 'when pattern includes a wildcard' do
      context 'when a wildcard is included in the eTLD+1' do
        context 'as TLD replacement' do
          let(:pattern) { 'example.*' }
          it 'returns false' do
            assert_on_failure(matcher.valid?(pattern), "wildcard in eTLD+1 not allowed")
          end
        end
        context 'when eTLD a single label' do
          let(:pattern) { '*.com' }
          it 'returns false' do
            assert_on_failure(matcher.valid?(pattern), "wildcard in eTLD+1 not allowed")
          end
        end
        context 'when eTLD is two labels' do
          let(:pattern) { '*.co.uk' }
          it 'returns false' do
            assert_on_failure(matcher.valid?(pattern), "wildcard in eTLD+1 not allowed")
          end
        end
        context 'as a partial label replacement' do
          context 'as a prefix' do
            let(:pattern) { '*example.com' }
            it 'returns false' do
              assert_on_failure(matcher.valid?(pattern), "wildcard in eTLD+1 not allowed")
            end
          end
          context 'in the interior' do
            let(:pattern) { 'exa*mple.com' }
            it 'returns false' do
              assert_on_failure(matcher.valid?(pattern), "wildcard in eTLD+1 not allowed")
            end
          end
          context 'as a suffix' do
            let(:pattern) { 'example*.com' }
            it 'returns false' do
              assert_on_failure(matcher.valid?(pattern), "wildcard in eTLD+1 not allowed")
            end
          end
        end
      end
      context 'when a wildcard is included outside the eTLD+1' do
        context 'as a whole label replacement' do
          let(:pattern) { '*.example.com' }
          it 'returns true' do
            expect(matcher.valid?(pattern).success?).to be(true)
          end
        end
        context 'as a partial label replacement' do
          context 'as a prefix' do
            let(:pattern) { '*partial.example.com' }
            it 'returns true' do
              expect(matcher.valid?(pattern).success?).to be(true)
            end
          end
          context 'in the interior' do
            let(:pattern) { 'par*tial.example.com' }
            it 'returns false' do
              assert_on_failure(matcher.valid?(pattern), "invalid segment 'par*tial'")
            end
          end
          context 'as a suffix' do
            let(:pattern) { 'partial*.example.com' }
            it 'returns false' do
              assert_on_failure(matcher.valid?(pattern), "invalid segment 'partial*'")
            end
          end
        end
        context 'multiple wildcards' do
          context 'in the same label' do
            let(:pattern) { '**.example.com' }
            it 'returns false' do
              assert_on_failure(matcher.valid?(pattern), "double-wildcard not allowed")
            end
          end
          context 'spread across labels' do
            let(:pattern) { '*.*.example.com' }
            it 'returns true' do
              expect(matcher.valid?(pattern).success?).to be(true)
            end
          end
        end
      end
      context 'when a wildcard is included in a private non-ICANN domain' do
        let(:pattern) { '*.compute-1.amazonaws.com' }
        it 'returns false' do
          assert_on_failure(matcher.valid?(pattern), "wildcards not allowed in private non-ICANN domains")
        end
      end
      context 'when a wildcard is valid but could represent a private non-ICANN domain' do
        let(:pattern) { '*.*.amazonaws.com' }
        it 'returns true' do
          expect(matcher.valid?(pattern).success?).to be(true)
        end
      end
    end
  end

  describe '#match?', type: 'unit' do
    let(:message_class) { LogMessages::Authentication::AuthnCert::DNSPatternMatchingFailed }

    context 'when pattern does not include a wildcard' do
      let(:pattern) { 'example.co.uk' }
      it 'performs direct string comparison' do
        expect(matcher.match?(pattern, 'example.co.uk').success?).to be(true)
      end
      it 'rejects strings that do not match the pattern' do
        assert_on_failure(matcher.match?(pattern, 'example.com'), "direct comparison failed")
        assert_on_failure(matcher.match?(pattern, 'a.example.co.uk'), "direct comparison failed")
      end
      it 'ignores case mismatches' do
        expect(matcher.match?(pattern, 'EXAMPLE.CO.UK').success?).to be(true)
      end
    end
    context 'when pattern includes a wildcard and is valid' do
      let(:pattern) { '*.example.com' }
      it 'matches many potential dns names' do
        expect(matcher.match?(pattern, 'api.example.com').success?).to be(true)
        expect(matcher.match?(pattern, 'ab.example.com').success?).to be(true)
        expect(matcher.match?(pattern, 'c.example.com').success?).to be(true)
      end
      it 'does not match an invalid candidate DNS name' do
        assert_on_failure(matcher.match?(pattern, '.example.com'), "invalid candidate DNS name")
      end
      context 'when pattern includes regex characters' do
        let(:pattern) { 'abc[0-9].*.example.com' }
        it 'they are compared directly' do
          expect(matcher.match?(pattern, 'abc[0-9].api.example.com').success?).to be(true)
          assert_on_failure(matcher.match?(pattern, 'abc5.api.example.com'), "label mismatch")
        end
      end
      context 'when wildcard is partial' do
        let(:pattern) { '*test.example.com' }
        it 'matches valid dns names' do
          expect(matcher.match?(pattern, 'sometest.example.com').success?).to be(true)
          expect(matcher.match?(pattern, 'test.example.com').success?).to be(true)

          assert_on_failure(matcher.match?(pattern, 'some.test.example.com'), "segment count mismatch")
          assert_on_failure(matcher.match?(pattern, 'sometest.illustration.com'), "label mismatch")
        end
      end
      context 'when pattern includes many wildcard segments' do
        let(:pattern) { '*.*.example.com' }
        it 'matches all wildcards' do
          expect(matcher.match?(pattern, 'a.b.example.com').success?).to be(true)

          assert_on_failure(matcher.match?(pattern, 'a.example.com'), "segment count mismatch")
          assert_on_failure(matcher.match?(pattern, 'a.b.c.example.com'), "segment count mismatch")
        end
      end
    end
    context 'when the pattern is valid but the candidate DNS name is in a private non-ICANN domain' do
      let(:pattern) { '*.*.amazonaws.com' }
      let(:dns_name) { 'api.compute-1.amazonaws.com' }
      it 'returns false' do
        assert_on_failure(matcher.match?(pattern, dns_name), "wildcards not allowed in private non-ICANN domains")
      end
    end
  end
end
