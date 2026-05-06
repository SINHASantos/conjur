# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnApiKey::V2::Strategy) do
  let(:authenticator) { Authentication::AuthnApiKey::V2::DataObjects::Authenticator.new(account: 'default') }
  let(:parameters) { { id: params_id, account: 'default' } }

  let(:role) { double(::Role) }
  let(:credentials) { double(::Credentials) }
  let(:credential) { double(::Credentials) }
  let(:logger) { instance_double(Logger, debug: nil) }
  let(:annotation_value) { nil }
  let(:authn_api_key_default) { true }
  let(:conjur_config) { double('conjur_config', authn_api_key_default: authn_api_key_default) }
  let(:resource_record) do
    {
      resource_id: conjur_role_identifier,
      authn_api_key_annotation: annotation_value
    }
  end

  let(:strategy) do
    Authentication::AuthnApiKey::V2::Strategy.new(
      authenticator: authenticator,
      logger: logger,
      role: role,
      credentials: credentials,
      conjur_config: conjur_config
    )
  end

  describe '.callback' do
    let(:request_body) { 'abc123' }

    shared_examples 'a successful response' do
      it 'is successful' do
        response = strategy.callback(request_body: request_body, parameters: parameters)

        expect(response.success?).to eq(true)
        expect(response.result.class).to eq(Authentication::RoleIdentifier)
        expect(response.result.identifier).to eq(conjur_role_identifier)
        expect(response.result.attributes).to eq({})
      end
    end

    shared_examples 'a role-not-found response' do
      it 'is unsuccessful' do
        response = strategy.callback(request_body: request_body, parameters: parameters)

        expect(response.success?).to eq(false)
        expect(response.message).to eq(role_not_found_message)
        expect(response.status).to eq(:unauthorized)
        expect(response.exception.class).to eq(Errors::Authentication::Security::RoleNotFound)
      end
    end

    context 'when role is a user' do
      let(:params_id) { 'foo-bar' }
      let(:conjur_role_identifier) { 'default:user:foo-bar' }
      context 'when Role is found' do
        before do
          allow(strategy).to receive(:role_with_api_key_annotation)
            .with(conjur_role_identifier)
            .and_return(resource_record)
        end

        context 'when authn/api-key annotation is false' do
          let(:annotation_value) { 'false' }

          it 'is unsuccessful and does not fetch credentials' do
            expect(credentials).not_to receive(:[])

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(false)
            expect(response.message).to eq("CONJ00195E Authentication is disabled for 'foo-bar'")
            expect(response.status).to eq(:unauthorized)
            expect(response.exception.class).to eq(Errors::Authentication::AuthenticationDisabled)
          end
        end

        context 'when authn/api-key annotation is FALSE (uppercase)' do
          let(:annotation_value) { 'FALSE' }

          it 'is unsuccessful and does not fetch credentials' do
            expect(credentials).not_to receive(:[])

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(false)
            expect(response.message).to eq("CONJ00195E Authentication is disabled for 'foo-bar'")
            expect(response.status).to eq(:unauthorized)
            expect(response.exception.class).to eq(Errors::Authentication::AuthenticationDisabled)
          end
        end

        context 'when authn/api-key annotation is absent' do
          let(:annotation_value) { nil }

          it 'uses default=true and allows authentication' do
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(credential)
            expect(credential).to receive(:valid_api_key?).with('abc123').and_return(true)

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(true)
          end

          context 'when role exists but resource is missing' do
            let(:resource_record) do
              {
                role_id: conjur_role_identifier,
                authn_api_key_annotation: nil
              }
            end

            it 'treats missing resource as missing annotation and allows authentication' do
              expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(credential)
              expect(credential).to receive(:valid_api_key?).with('abc123').and_return(true)

              response = strategy.callback(request_body: request_body, parameters: parameters)

              expect(response.success?).to eq(true)
            end
          end

          context 'and authn_api_key_default is false' do
            let(:authn_api_key_default) { false }

            it 'is unsuccessful and does not fetch credentials' do
              expect(credentials).not_to receive(:[])

              response = strategy.callback(request_body: request_body, parameters: parameters)

              expect(response.success?).to eq(false)
              expect(response.message).to eq("CONJ00195E Authentication is disabled for 'foo-bar'")
              expect(response.status).to eq(:unauthorized)
              expect(response.exception.class).to eq(Errors::Authentication::AuthenticationDisabled)
            end
          end
        end

        context 'when authn/api-key annotation is unrecognized and default is true' do
          let(:annotation_value) { 'unexpected-value' }

          it 'falls back to default, logs debug, and allows authentication' do
            expect(logger).to receive(:debug).with(include("'unexpected-value'", "'default:user:foo-bar'"))
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(credential)
            expect(credential).to receive(:valid_api_key?).with('abc123').and_return(true)

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(true)
          end
        end

        context 'when authn/api-key annotation is unrecognized and default is false' do
          let(:annotation_value) { 'unexpected-value' }
          let(:authn_api_key_default) { false }

          it 'falls back to default, logs debug, and denies authentication' do
            expect(logger).to receive(:debug).with(include("'unexpected-value'", "'default:user:foo-bar'"))
            expect(credentials).not_to receive(:[])

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(false)
            expect(response.message).to eq("CONJ00195E Authentication is disabled for 'foo-bar'")
            expect(response.status).to eq(:unauthorized)
            expect(response.exception.class).to eq(Errors::Authentication::AuthenticationDisabled)
          end
        end

        context 'when Credential is present' do
          before do
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(credential)
          end
          context 'when provided API key matches the stored API key' do
            before do
              expect(credential).to receive(:valid_api_key?).with('abc123').and_return(true)
            end
            include_examples 'a successful response'

            context 'when role id is prefixed with user/' do
              let(:params_id) { 'user/foo-bar' }
              let(:conjur_role_identifier) { 'default:user:foo-bar' }

              include_examples 'a successful response'
            end
          end
          context 'when provided API key does not match the stored API key' do
            before do
              expect(credential).to receive(:valid_api_key?).with('abc123').and_return(false)
            end
            it 'is unsuccessful' do
              response = strategy.callback(request_body: request_body, parameters: parameters)

              expect(response.success?).to eq(false)
              expect(response.message).to eq("CONJ00002E Invalid credentials")
              expect(response.status).to eq(:unauthorized)
              expect(response.exception.class).to eq(Errors::Authentication::InvalidCredentials)
            end
          end
        end
        context 'When Credential is not found' do
          before do
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(nil)
          end

          it 'is unsuccessful' do
            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(false)
            expect(response.message).to eq("CONJ00120E Role 'foo-bar' has no credentials")
            expect(response.status).to eq(:unauthorized)
            expect(response.exception.class).to eq(Errors::Authentication::RoleHasNoCredentials)
          end
        end
      end
      context 'when Role is not found' do
        let(:role_not_found_message) { "CONJ00007E 'foo-bar' not found" }

        before do
          allow(strategy).to receive(:role_with_api_key_annotation)
            .with(conjur_role_identifier)
            .and_return(nil)
        end

        include_examples 'a role-not-found response'
      end
    end

    context 'when role is a host' do
      let(:params_id) { 'host/foo-bar' }
      let(:conjur_role_identifier) { 'default:host:foo-bar' }
      context 'when Role is found' do
        before do
          allow(strategy).to receive(:role_with_api_key_annotation)
            .with(conjur_role_identifier)
            .and_return(resource_record)
        end

        context 'when authn/api-key annotation is false' do
          let(:annotation_value) { 'false' }

          it 'is unsuccessful and does not fetch credentials' do
            expect(credentials).not_to receive(:[])

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(false)
            expect(response.message).to eq("CONJ00195E Authentication is disabled for 'host/foo-bar'")
            expect(response.status).to eq(:unauthorized)
            expect(response.exception.class).to eq(Errors::Authentication::AuthenticationDisabled)
          end
        end

        context 'when authn/api-key annotation is absent' do
          let(:annotation_value) { nil }

          it 'uses default=true and allows authentication' do
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(credential)
            expect(credential).to receive(:valid_api_key?).with('abc123').and_return(true)

            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(true)
          end

          context 'and authn_api_key_default is false' do
            let(:authn_api_key_default) { false }

            it 'is unsuccessful and does not fetch credentials' do
              expect(credentials).not_to receive(:[])

              response = strategy.callback(request_body: request_body, parameters: parameters)

              expect(response.success?).to eq(false)
              expect(response.message).to eq("CONJ00195E Authentication is disabled for 'host/foo-bar'")
              expect(response.status).to eq(:unauthorized)
              expect(response.exception.class).to eq(Errors::Authentication::AuthenticationDisabled)
            end
          end
        end

        context 'when Credential is present' do
          before do
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(credential)
          end
          context 'when provided API key matches the stored API key' do
            before do
              expect(credential).to receive(:valid_api_key?).with('abc123').and_return(true)
            end
            include_examples 'a successful response'

            context 'when host includes slashes' do
              let(:params_id) { 'host/foo/bar' }
              let(:conjur_role_identifier) { 'default:host:foo/bar' }

              include_examples 'a successful response'
            end
          end
          context 'when provided API key does not match the stored API key' do
            before do
              expect(credential).to receive(:valid_api_key?).with('abc123').and_return(false)
            end
            it 'is unsuccessful' do
              response = strategy.callback(request_body: request_body, parameters: parameters)

              expect(response.success?).to eq(false)
              expect(response.message).to eq("CONJ00002E Invalid credentials")
              expect(response.status).to eq(:unauthorized)
              expect(response.exception.class).to eq(Errors::Authentication::InvalidCredentials)
            end
          end
        end
        context 'When Credential is not found' do
          before do
            expect(credentials).to receive(:[]).with(conjur_role_identifier).and_return(nil)
          end

          it 'is unsuccessful' do
            response = strategy.callback(request_body: request_body, parameters: parameters)

            expect(response.success?).to eq(false)
            expect(response.message).to eq("CONJ00120E Role 'host/foo-bar' has no credentials")
            expect(response.status).to eq(:unauthorized)
            expect(response.exception.class).to eq(Errors::Authentication::RoleHasNoCredentials)
          end
        end
      end
      context 'when Role is not found' do
        let(:role_not_found_message) { "CONJ00007E 'host/foo-bar' not found" }

        before do
          allow(strategy).to receive(:role_with_api_key_annotation)
            .with(conjur_role_identifier)
            .and_return(nil)
        end

        include_examples 'a role-not-found response'
      end
    end
  end
end
