# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::Constraints::PermittedConstraint) do
  context "Given PermittedConstraint initialized with 1 restriction" do
    let(:permitted_restriction) { ["permitted"] }
    let(:not_permitted_restrictions) { %w[not_permitted_first not_permitted_second] }
    let(:raised_error) { ::Errors::Authentication::Constraints::ConstraintNotSupported }

    subject(:constraint) do
      Authentication::Constraints::PermittedConstraint.new(permitted: permitted_restriction)
    end

    context "when validating empty array" do
      subject do
        constraint.validate(resource_restrictions: [])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating without the permitted restriction" do
      subject do
        constraint.validate(resource_restrictions: not_permitted_restrictions)
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(not_permitted_restrictions.to_s)
        expect(response.exception.message).to include(permitted_restriction.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end

    context "when validating with only the permitted restriction" do
      subject do
        constraint.validate(resource_restrictions: permitted_restriction)
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with the permitted restriction and more" do
      subject do
        constraint.validate(resource_restrictions: permitted_restriction + not_permitted_restrictions)
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(not_permitted_restrictions.to_s)
        expect(response.exception.message).to include(permitted_restriction.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end
  end

  context "Given PermittedConstraint initialized with 2 restrictions" do
    let(:permitted_two_restrictions) { %w[permitted_first permitted_second] }
    let(:not_permitted_restrictions) { %w[not_permitted_first not_permitted_second] }
    let(:raised_error) { ::Errors::Authentication::Constraints::ConstraintNotSupported }
    let(:expected_error_message) { /'#{Regexp.escape(not_permitted_restrictions.to_s)}'.*#{Regexp.escape(permitted_two_restrictions.to_s)}/ }

    subject(:constraint) do
      Authentication::Constraints::PermittedConstraint.new(permitted: permitted_two_restrictions)
    end

    context "when validating empty array" do
      subject do
        constraint.validate(resource_restrictions: [])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating without any of the permitted restrictions" do
      subject do
        constraint.validate(resource_restrictions: not_permitted_restrictions)
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(not_permitted_restrictions.to_s)
        expect(response.exception.message).to include(permitted_two_restrictions.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end

    context "when validating with the first permitted restriction" do
      subject do
        constraint.validate(resource_restrictions: [permitted_two_restrictions.first])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with the second permitted restriction" do
      subject do
        constraint.validate(resource_restrictions: [permitted_two_restrictions.second])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with both of the permitted restrictions" do
      subject do
        constraint.validate(resource_restrictions: permitted_two_restrictions)
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with both of the permitted restrictions and more" do
      subject do
        constraint.validate(resource_restrictions: permitted_two_restrictions + not_permitted_restrictions)
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(not_permitted_restrictions.to_s)
        expect(response.exception.message).to include(permitted_two_restrictions.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end
  end
end
