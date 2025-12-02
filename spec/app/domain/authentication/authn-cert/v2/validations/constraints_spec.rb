# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Validations::Constraints) do
  let(:authenticator) do
    AuthenticatorsV2::CertAuthenticatorType.new(
      account: 'rspec',
      service_id: 'foo',
      variables: variables
    )
  end
  let(:constraints) { described_class.new }

  describe '.run', type: 'unit' do
    context 'when host_mode variable is missing' do
      let(:variables) { {} }

      context 'when annotations do not include any applicable constraints' do
        let(:annotations) { {} }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::RoleMissingRequiredConstraints)
        end
      end

      context 'when annotations include a non-permitted constraint' do
        let(:annotations) { { 'non-permitted' => 'some-value' } }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::ConstraintNotSupported)
        end
      end

      context 'when annotations include a valid set of constraints' do
        let(:annotations) { { 'san-uri' => 'spiffe://trust.com/workload/id', 'san-dns' => 'conjur.org' } }

        it 'passes validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(true)
        end
      end
    end

    context 'when host_mode variable is "request"' do
      let(:variables) { { host_mode: 'request' } }

      context 'when annotations do not include any applicable constraints' do
        let(:annotations) { {} }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::RoleMissingRequiredConstraints)
        end
      end

      context 'when annotations include a non-permitted constraint' do
        let(:annotations) { { 'non-permitted' => 'some-value' } }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::ConstraintNotSupported)
        end
      end

      context 'when annotations include a valid set of constraints' do
        let(:annotations) { { 'san-uri' => 'spiffe://trust.com/workload/id', 'san-dns' => 'conjur.org' } }

        it 'passes validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(true)
        end
      end
    end

    context 'when host_mode variable is an unrecognized value' do
      let(:variables) { { host_mode: 'unrecognized' } }

      context 'when annotations do not include any applicable constraints' do
        let(:annotations) { {} }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::RoleMissingRequiredConstraints)
        end
      end

      context 'when annotations include a non-permitted constraint' do
        let(:annotations) { { 'non-permitted' => 'some-value' } }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::ConstraintNotSupported)
        end
      end

      context 'when annotations include a valid set of constraints' do
        let(:annotations) { { 'san-uri' => 'spiffe://trust.com/workload/id', 'san-dns' => 'conjur.org' } }

        it 'passes validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(true)
        end
      end
    end

    context 'when host_mode variable is "spiffe""' do
      let(:variables) { { host_mode: 'spiffe' } }

      context 'when annotations do not include any applicable constraints' do
        let(:annotations) { {} }

        it 'passes validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(true)
        end
      end

      context 'when annotations include a non-permitted constraint' do
        let(:annotations) { { 'non-permitted' => 'some-value' } }

        it 'fails validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(false)
          expect(result.exception.class).to be(Errors::Authentication::Constraints::ConstraintNotSupported)
        end
      end

      context 'when annotations include a valid set of constraints' do
        let(:annotations) { { 'san-uri' => 'spiffe://trust.com/workload/id', 'san-dns' => 'conjur.org' } }

        it 'passes validation' do
          result = constraints.run(annotations: annotations, authenticator: authenticator)
          expect(result.success?).to be(true)
        end
      end
    end
  end
end
