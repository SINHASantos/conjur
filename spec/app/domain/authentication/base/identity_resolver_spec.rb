# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::Base::IdentityResolver) do
  let(:resolver) do
    described_class.new(
      authenticator: authenticator
    )
  end
  let(:authenticator) do
    Authentication::Base::DataObject.new(
      account: 'rspec',
      service_id: 'foo'
    )
  end

  describe '.call', type: 'unit' do
    context 'when an identity is provided' do
      context 'when identity is a user' do
        it 'returns the identity' do
          result = resolver.call(id: 'alice')
          expect(result.success?).to be(true)
          expect(result.result).to eq('rspec:user:alice')
        end
        context 'when identity is nested' do
          it 'returns the identity' do
            result = resolver.call(id: 'foo/bar/alice')
            expect(result.success?).to be(true)
            expect(result.result).to eq('rspec:user:foo/bar/alice')
          end
          context 'when identity starts with a slash' do
            it 'returns the identity' do
              result = resolver.call(id: '/foo/bar/alice')
              expect(result.success?).to be(true)
              expect(result.result).to eq('rspec:user:foo/bar/alice')
            end
          end
        end
        context 'when authenticator does not include a mapped policy path' do
          let(:authenticator) do
            Authentication::AuthnApiKey::V2::DataObjects::Authenticator.new(
              account: 'rspec'
            )
          end
          it 'returns the identity' do
            result = resolver.call(id: 'alice')
            expect(result.success?).to be(true)
            expect(result.result).to eq('rspec:user:alice')
          end
        end
        context 'when authenticator includes a mapped policy path' do
          let(:authenticator) do
            Authentication::Base::Mock::DataObjects::Authenticator.new(
              account: 'rspec',
              service_id: 'foo',
              identity_path: identity_path
            )
          end

          let(:identity_path) { 'foo/bar' }
          it 'returns the identity' do
            result = resolver.call(id: 'alice')
            expect(result.success?).to be(true)
            expect(result.result).to eq('rspec:user:foo/bar/alice')
          end
          context 'when identity path starts with a slash' do
            let(:identity_path) { '/foo/bar' }
            it 'returns the identity' do
              result = resolver.call(id: 'alice')
              expect(result.success?).to be(true)
              expect(result.result).to eq('rspec:user:foo/bar/alice')
            end
          end
          context 'when identity path ends with a slash' do
            let(:identity_path) { 'foo/bar/' }
            it 'returns the identity' do
              result = resolver.call(id: 'alice')
              expect(result.success?).to be(true)
              expect(result.result).to eq('rspec:user:foo/bar/alice')
            end
          end
        end
      end
      context 'when identity is a host' do
        it 'returns the identity' do
          result = resolver.call(id: 'host/foo')
          expect(result.success?).to be(true)
          expect(result.result).to eq('rspec:host:foo')
        end
        context 'when id starts with a slash' do
          it 'returns the identity' do
            result = resolver.call(id: '/host/foo')
            expect(result.success?).to be(true)
            expect(result.result).to eq('rspec:host:foo')
          end
        end
        context 'when authenticator includes a mapped policy path' do
          let(:authenticator) do
            Authentication::Base::Mock::DataObjects::Authenticator.new(
              account: 'rspec',
              service_id: 'foo',
              identity_path: identity_path
            )
          end
          let(:identity_path) { 'foo/bar' }
          it 'returns the identity' do
            result = resolver.call(id: 'host/baz')
            expect(result.success?).to be(true)
            expect(result.result).to eq('rspec:host:foo/bar/baz')
          end
        end
      end
    end
    context 'when an identity and credential are provided' do
      it 'returns the identity using the id' do
        result = resolver.call(id: 'alice', credential: 'bob')
        expect(result.success?).to be(true)
        expect(result.result).to eq('rspec:user:alice')
      end
    end
    context 'when only a credential is provided' do
      it 'raises an error' do
        expect { resolver.call(credential: 'bob') }.to raise_error(RuntimeError, 'Not implemented')
      end
    end
  end
end

module Authentication
  module Base
    module Mock
      module DataObjects
        class Authenticator < Authentication::Base::DataObject
          def initialize(account:, service_id:, identity_path:)
            @identity_path = identity_path
            super(account: account, service_id: service_id)
          end
          attr_reader :identity_path
        end
      end
    end
  end
end
