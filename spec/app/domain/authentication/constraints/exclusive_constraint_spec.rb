# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::Constraints::ExclusiveConstraint) do
  context "Given ExclusiveConstraint initialized with 3 restriction" do
    let(:exclusive_three_restriction) { %w[exclusive_one exclusive_two exclusive_three] }
    let(:additional_restriction) { "additional-required" }
    let(:raised_error) { ::Errors::Authentication::Constraints::IllegalConstraintCombinations }

    subject(:constraint) do
      Authentication::Constraints::ExclusiveConstraint.new(exclusive: exclusive_three_restriction)
    end

    context "when validating empty array" do
      subject do
        constraint.validate(resource_restrictions: [])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating without any of the required restrictions" do
      subject do
        constraint.validate(resource_restrictions: [additional_restriction])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with one of the exclusive restrictions" do
      subject do
        constraint.validate(resource_restrictions: [exclusive_three_restriction.first])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with two of the exclusive restrictions" do
      let(:resource_restrictions) { exclusive_three_restriction[1, 2] }

      subject do
        constraint.validate(resource_restrictions: resource_restrictions)
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(resource_restrictions.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end

    context "when validating with all of the exclusive restrictions" do
      subject do
        constraint.validate(resource_restrictions: exclusive_three_restriction)
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(exclusive_three_restriction.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end

    context "when validating with all of the exclusive restrictions and more" do
      subject do
        constraint.validate(resource_restrictions: exclusive_three_restriction + [additional_restriction])
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(exclusive_three_restriction.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end
  end
end
