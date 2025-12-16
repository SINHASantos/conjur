# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::DnsName) do
  let(:matcher) { described_class }

  describe '#valid?', type: 'unit' do
    context 'when pattern does not include a wildcard' do
      context 'when pattern includes an empty label' do
        context 'as a prefix' do
          let(:pattern) { '.example.com' }
          it 'returns false' do
            expect(matcher.valid?(pattern)).to be(false)
          end
        end
        context 'in the interior' do
          let(:pattern) { 'test..example.com' }
          it 'returns false' do
            expect(matcher.valid?(pattern)).to be(false)
          end
        end
        context 'as a suffix' do
          let(:pattern) { 'example.com.' }
          it 'returns false' do
            expect(matcher.valid?(pattern)).to be(false)
          end
        end
      end
    end
    context 'when pattern includes a wildcard' do
      context 'when a wildcard is included in the eTLD+1' do
        context 'as TLD replacement' do
          let(:pattern) { 'example.*' }
          it 'returns false' do
            expect(matcher.valid?(pattern)).to be(false)
          end
        end
        context 'when eTLD a single label' do
          let(:pattern) { '*.com' }
          it 'returns false' do
            expect(matcher.valid?(pattern)).to be(false)
          end
        end
        context 'when eTLD is two labels' do
          let(:pattern) { '*.co.uk' }
          it 'returns false' do
            expect(matcher.valid?(pattern)).to be(false)
          end
        end
        context 'as a partial label replacement' do
          context 'as a prefix' do
            let(:pattern) { '*example.com' }
            it 'returns false' do
              expect(matcher.valid?(pattern)).to be(false)
            end
          end
          context 'in the interior' do
            let(:pattern) { 'exa*mple.com' }
            it 'returns false' do
              expect(matcher.valid?(pattern)).to be(false)
            end
          end
          context 'as a suffix' do
            let(:pattern) { 'example*.com' }
            it 'returns false' do
              expect(matcher.valid?(pattern)).to be(false)
            end
          end
        end
      end
      context 'when a wildcard is included outside the eTLD+1' do
        context 'as a whole label replacement' do
          let(:pattern) { '*.example.com' }
          it 'returns true' do
            expect(matcher.valid?(pattern)).to be(true)
          end
        end
        context 'as a partial label replacement' do
          context 'as a prefix' do
            let(:pattern) { '*partial.example.com' }
            it 'returns true' do
              expect(matcher.valid?(pattern)).to be(true)
            end
          end
          context 'in the interior' do
            let(:pattern) { 'par*tial.example.com' }
            it 'returns false' do
              expect(matcher.valid?(pattern)).to be(false)
            end
          end
          context 'as a suffix' do
            let(:pattern) { 'partial*.example.com' }
            it 'returns false' do
              expect(matcher.valid?(pattern)).to be(false)
            end
          end
        end
        context 'multiple wildcards' do
          context 'in the same label' do
            let(:pattern) { '**.example.com' }
            it 'returns false' do
              expect(matcher.valid?(pattern)).to be(false)
            end
          end
          context 'spread across labels' do
            let(:pattern) { '*.*.example.com' }
            it 'returns true' do
              expect(matcher.valid?(pattern)).to be(true)
            end
          end
        end
      end
    end
  end

  describe '#match?', type: 'unit' do
    let(:matcher) { described_class }

    context 'when pattern does not include a wildcard' do
      let(:pattern) { 'example.co.uk' }
      it 'preforms direct string comparison' do
        expect(matcher.match?(pattern, 'example.co.uk')).to be(true)
      end
      it 'rejects strings that do not match the pattern' do
        expect(matcher.match?(pattern, 'example.com')).to be(false)
        expect(matcher.match?(pattern, 'a.example.co.uk')).to be(false)
      end
      it 'ignores case mismatches' do
        expect(matcher.match?(pattern, 'EXAMPLE.co.uk')).to be(true)
      end
    end
    context 'when pattern includes a wildcard and is valid' do
      let(:pattern) { '*.example.com' }
      it 'matches many potential dns names' do
        expect(matcher.match?(pattern, 'a.example.com')).to be(true)
        expect(matcher.match?(pattern, 'ab.example.com')).to be(true)
        expect(matcher.match?(pattern, 'c.example.com')).to be(true)
      end
      it 'does not match an empty label' do
        expect(matcher.match?(pattern, '.example.com')).to be(false)
      end
      context 'when pattern includes regex characters' do
        let(:pattern) { 'abc[0-9].*.example.com' }
        it 'they are compared directly' do
          expect(matcher.match?(pattern, 'abc[0-9].api.example.com')).to be(true)
          expect(matcher.match?(pattern, 'abc5.api.example.com')).to be(false)
        end
      end
      context 'when wildcard is partial' do
        let(:pattern) { '*test.example.com' }
        it 'matches valid dns names' do
          expect(matcher.match?(pattern, 'sometest.example.com')).to be(true)
          expect(matcher.match?(pattern, 'test.example.com')).to be(true)
          expect(matcher.match?(pattern, 'some.test.example.com')).to be(false)
          expect(matcher.match?(pattern, 'sometest.illustration.com')).to be(false)
        end
      end
      context 'when pattern includes many wildcard segments' do
        let(:pattern) { '*.*.example.com' }
        it 'matches all wildcards' do
          expect(matcher.match?(pattern, 'a.example.com')).to be(false)
          expect(matcher.match?(pattern, 'a.b.example.com')).to be(true)
          expect(matcher.match?(pattern, 'a.b.c.example.com')).to be(false)
        end
      end
    end
  end
end
