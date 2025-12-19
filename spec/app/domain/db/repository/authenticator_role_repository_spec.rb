# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(DB::Repository::AuthenticatorRoleRepository) do
  let(:role_repository) { ::Role }
  let(:credential) { 'my-credential' }
  let(:account) { 'rspec' }

  before(:each) do
    ::Role.create(role_id: "#{account}:policy:root") if ::Role["#{account}:policy:root"].nil?
    ::Role.create(role_id: "#{account}:user:admin") if ::Role["#{account}:user:admin"].nil?
    ::Resource.create(resource_id: "#{account}:policy:root", owner_id: "#{account}:user:admin") if ::Resource["#{account}:policy:root"].nil?
  end
  after(:each) do
    ::Role["#{account}:policy:root"].destroy
    ::Resource["#{account}:policy:root"].destroy
  end

  describe('#find') do
    let(:service_id) { 'my-service'}
    let(:identity_path) { 'my-path'}
    let(:type) { 'authn-xyz' }
    let(:credential_attributes) { { claim: 'value' } }
    let(:role_id) do
      Authentication::RoleIdentifier.new(
        identifier: id,
        attributes: credential_attributes
      )
    end

    let(:authenticator_model) do
      DB::Repository::Mock::DataObjects::Authenticator.new(
        account: account,
        service_id: service_id,
        identity_path: identity_path,
        type: type
      )
    end

    let(:constraints_class) { nil }
    let(:role_credential_validation_class) { nil }

    let(:repo) do
      described_class.new(
        authenticator: authenticator_model,
        constraint_validation: constraints_class,
        role_credential_validation: role_credential_validation_class
      )
    end

    context 'when role is not found' do
      let(:id) { "#{account}:host:unknown" }

      it 'is unsuccessful' do
        response = repo.find(role_id)

        expect(response.success?).to be(false)
        expect(response.exception.class).to eq(Errors::Authentication::Security::RoleNotFound)
        expect(response.status).to eq(:bad_request)
      end
    end

    context 'when a role does not have an associated resource' do
      let(:id) { "#{account}:user:known"}

      before(:each) do
        ::Role.find_or_create(role_id: id)
      end
      after(:each) do
        ::Role[id].destroy
      end

      let(:role_id) do
        Authentication::RoleIdentifier.new(
          identifier: id
        )
      end

      context 'when role validations are not defined' do
        it 'is successful' do
          response = repo.find(role_id)

          expect(response.success?).to be(true)
          expect(response.result.role_id).to eq(id)
        end
      end

      context 'when role validations are defined' do
        let(:constraints_class) do
          class_double('ConstraintsClass').tap do |double|
            allow(double).to receive(:new).and_return(constraints)
          end
        end
        let(:constraints) do
          instance_double('ConstraintsInstance').tap do |double|
            allow(double).to receive(:run).and_return(Responses::Failure.new('error message'))
          end
        end
        let(:role_credential_validation_class) do
          class_double('RoleCredentialValidationClass').tap do |double|
            allow(double).to receive(:new).and_return(role_credential_validation)
          end
        end
        let(:role_credential_validation) do
          instance_double('RoleCredentialValidationInstance').tap do |double|
            allow(double).to receive(:valid?).and_return(false)
          end
        end

        it 'is unsuccessful' do
          response = repo.find(role_id)

          expect(response.success?).to be(false)
          expect(response.exception.class).to eq(Errors::Authentication::Constraints::RoleMissingAnyRestrictions)
          expect(response.status).to eq(:unauthorized)
        end
      end
    end

    context 'when role has an associated resource' do
      let(:id) { "#{account}:host:known" }

      before(:each) do
        ::Role.find_or_create(role_id: id)
        ::Resource.create(resource_id: id, owner_id: "#{account}:policy:root")
      end
      after(:each) do
        ::Role[id].destroy
        ::Resource[id].destroy
      end

      context 'when role has related annotations' do
        let(:global_restriction) { { key: 'global', value: 'global-value' } }
        let(:specific_restriction) { { key: 'specific', value: 'specific-value' } }
        let(:slashed_restriction) { { key: 'with/some/slashes', value: 'slashed-value' } }

        context 'when role validations are not defined' do
          before(:each) do
            ::Annotation.create(resource_id: id, name: "#{type}/#{global_restriction[:key]}", value: global_restriction[:value])
            ::Annotation.create(resource_id: id, name: "#{type}/#{service_id}/#{specific_restriction[:key]}", value: specific_restriction[:value])
            ::Annotation.create(resource_id: id, name: "#{type}/#{service_id}/#{slashed_restriction[:key]}", value: slashed_restriction[:value])
          end
          after(:each) do
            ::Annotation[id, "#{type}/#{global_restriction[:key]}"].destroy
            ::Annotation[id, "#{type}/#{service_id}/#{specific_restriction[:key]}"].destroy
            ::Annotation[id, "#{type}/#{service_id}/#{slashed_restriction[:key]}"].destroy
          end

          let(:constraints_class) do
            class_double('ConstraintsClass').tap do |double|
              allow(double).to receive(:new).and_return(constraints)
            end
          end
          let(:constraints) do
            instance_double('ConstraintsInstance').tap do |double|
              allow(double).to receive(:run).and_return(Responses::Failure.new('error message'))
            end
          end

          it 'performs validation' do
            response = repo.find(role_id)

            expect(response.success?).to be(false)
            expect(response.to_s).to include("error message")
          end
        end

        context 'when role validations are defined and pass' do
          let(:constraints_class) do
            class_double('ConstraintsClass').tap do |double|
              allow(double).to receive(:new).and_return(constraints)
            end
          end
          let(:constraints) do
            instance_double('ConstraintsInstance').tap do |double|
              expect(double).to receive(:run).with(**expected_constraints_args).and_return(Responses::Success.new(true))
            end
          end

          context 'when annotations include applicable restrictions' do
            before(:each) do
              ::Annotation.create(resource_id: id, name: "#{type}/#{global_restriction[:key]}", value: global_restriction[:value])
              ::Annotation.create(resource_id: id, name: "#{type}/#{service_id}/#{specific_restriction[:key]}", value: specific_restriction[:value])
              ::Annotation.create(resource_id: id, name: "#{type}/#{service_id}/#{slashed_restriction[:key]}", value: slashed_restriction[:value])
            end
            after(:each) do
              ::Annotation[id, "#{type}/#{global_restriction[:key]}"].destroy
              ::Annotation[id, "#{type}/#{service_id}/#{specific_restriction[:key]}"].destroy
              ::Annotation[id, "#{type}/#{service_id}/#{slashed_restriction[:key]}"].destroy
            end

            let(:expected_constraints_args) do
              {
                annotations: {
                  global_restriction[:key] => global_restriction[:value],
                  specific_restriction[:key] => specific_restriction[:value],
                  slashed_restriction[:key] => slashed_restriction[:value]
                },
                authenticator: authenticator_model
              }
            end

            it 'is successful' do
              response = repo.find(role_id)

              expect(response.success?).to be(true)
              expect(response.result.role_id).to eq(id)
            end

            context 'when role credential validations are not defined' do
              it 'is successful' do
                response = repo.find(role_id)

                expect(response.success?).to be(true)
                expect(response.result.role_id).to eq(id)
              end
            end

            context 'when role credential validations are defined as pass' do
              let(:role_credential_validation_class) do
                class_double('RoleCredentialValidationClass').tap do |double|
                  expect(double).to receive(:new).and_return(role_credential_validation)
                end
              end
              let(:role_credential_validation) do
                instance_double('RoleCredentialValidationInstance').tap do |double|
                  expect(double).to receive(:valid?).and_return(true)
                end
              end

              it 'is successful' do
                response = repo.find(role_id)

                expect(response.success?).to be(true)
                expect(response.result.role_id).to eq(id)
              end
            end

            context 'when role credential validations are defined and fail' do
              let(:role_credential_validation_class) do
                class_double('RoleCredentialValidationClass').tap do |double|
                  expect(double).to receive(:new).and_return(role_credential_validation)
                end
              end
              let(:role_credential_validation) do
                instance_double('RoleCredentialValidationInstance').tap do |double|
                  expect(double).to receive(:valid?).and_return(false)
                  expect(double).to receive(:errors).and_return([
                    DB::Repository::Mock::Error.new("error message", "error type")
                  ])
                end
              end

              it 'is unsuccessful' do
                response = repo.find(role_id)

                expect(response.success?).to be(false)
                expect(response.to_s).to include("error message")
              end
            end
          end

          context 'when global and service-specific restrictions collide' do
            before(:each) do
              ::Annotation.create(resource_id: id, name: "#{type}/#{global_restriction[:key]}", value: global_restriction[:value])
              ::Annotation.create(resource_id: id, name: "#{type}/#{service_id}/#{global_restriction[:key]}", value: specific_restriction[:value])
            end
            after(:each) do
              ::Annotation[id, "#{type}/#{global_restriction[:key]}"].destroy
              ::Annotation[id, "#{type}/#{service_id}/#{global_restriction[:key]}"].destroy
            end

            let(:expected_constraints_args) do
              {
                annotations: {
                  global_restriction[:key] => specific_restriction[:value]
                },
                authenticator: authenticator_model
              }
            end

            it 'is successful' do
              response = repo.find(role_id)

              expect(response.success?).to be(true)
              expect(response.result.role_id).to eq(id)
            end
          end
        end
      end

      context 'when role does not have related annotations' do
        context 'when role validations are not defined' do
          it 'is successful without evaluating validations' do
            response = repo.find(role_id)

            expect(response.success?).to be(true)
            expect(response.result.role_id).to eq(id)
          end
        end
      end

      context 'when role validations are defined and fail' do
        let(:constraints_class) do
          class_double('ConstraintsClass').tap do |double|
            allow(double).to receive(:new).and_return(constraints)
          end
        end
        let(:constraints) do
          instance_double('ConstraintsInstance').tap do |double|
            allow(double).to receive(:run).and_return(Responses::Failure.new('error message'))
          end
        end

        it 'is unsuccessful' do
          response = repo.find(role_id)

          expect(response.success?).to be(false)
          expect(response.to_s).to include("error message")
        end
      end
    end
  end
end

module DB
  module Repository
    module Mock
      module DataObjects
        class Authenticator < Authentication::Base::DataObject
          def initialize(account:, service_id:, identity_path:, type:)
            @identity_path = identity_path
            @type = type
            super(account: account, service_id: service_id)
          end
          attr_reader :identity_path
        end
      end

      class Error
        def initialize(message, type)
          @message = message
          @type = type
        end
        attr_reader :message, :type
      end
    end

  end
end
