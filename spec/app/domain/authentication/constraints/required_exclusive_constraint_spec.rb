# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::Constraints::RequiredExclusiveConstraint) do
  context "Given RequiredExclusiveConstraint initialized with 3 restrictions" do
    let(:reqx_restrictions) { %w[reqx_one reqx_two reqx_three] }
    let(:additional_restriction) { "additional" }
    let(:raised_error) { ::Errors::Authentication::Constraints::IllegalRequiredExclusiveCombination }

    subject(:constraint) do
      Authentication::Constraints::RequiredExclusiveConstraint.new(required_exclusive: reqx_restrictions)
    end

    context "when validating with no ReqX restrictions" do
      subject do
        constraint.validate(resource_restrictions: [additional_restriction])
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(reqx_restrictions.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end

    context "when validating with one ReqX restriction" do
      subject do
        constraint.validate(resource_restrictions: [reqx_restrictions.first, additional_restriction])
      end

      it "returns a success response" do
        expect(subject.success?).to be(true)
      end
    end

    context "when validating with many ReqX restrictions" do
      let(:resource_restrictions) { reqx_restrictions[1, 2] }

      subject do
        constraint.validate(resource_restrictions: resource_restrictions + [additional_restriction])
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(resource_restrictions.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end

    context "when validating with all ReqX restrictions" do
      subject do
        constraint.validate(resource_restrictions: reqx_restrictions + [additional_restriction])
      end

      it "returns a failure response" do
        response = subject
        expect(response.success?).to be(false)
        expect(response.exception.class).to be(raised_error)
        expect(response.exception.message).to include(reqx_restrictions.to_s)
        expect(response.status).to eq(:unauthorized)
      end
    end
  end
end
