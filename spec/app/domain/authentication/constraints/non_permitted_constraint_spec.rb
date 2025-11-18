# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::Constraints::NonPermittedConstraint) do
  let(:non_permitted_constraint) { %w[iat nbf exp iss] }
  let(:raised_error) { ::Errors::Authentication::Constraints::NonPermittedRestrictionGiven }

  subject(:constraint) do
    Authentication::Constraints::NonPermittedConstraint.new(non_permitted: non_permitted_constraint)
  end

  context "when validating empty array" do
    subject do
      constraint.validate(resource_restrictions: [])
    end

    it "returns a success response" do
      expect(subject.success?).to be(true)
    end
  end

  context "when validating one allowed restriction" do
    subject do
      constraint.validate(resource_restrictions: ["ref"])
    end

    it "returns a success response" do
      expect(subject.success?).to be(true)
    end
  end

  context "when validating one restriction that contains a non permitted substring" do
    subject do
      constraint.validate(resource_restrictions: ["iatnbfexpiss"])
    end

    it "returns a success response" do
      expect(subject.success?).to be(true)
    end
  end

  context "when validating two allowed restriction" do
    subject do
      constraint.validate(resource_restrictions: %w[ref sub])
    end

    it "returns a success response" do
      expect(subject.success?).to be(true)
    end
  end

  context "when validating one non permitted restriction" do
    subject do
      constraint.validate(resource_restrictions: ["exp"])
    end

    it "returns a failure response" do
      response = subject
      expect(response.success?).to be(false)
      expect(response.exception.class).to be(raised_error)
      expect(response.status).to eq(:unauthorized)
    end
  end

  context "when validating two non permitted restrictions" do
    subject do
      constraint.validate(resource_restrictions: %w[exp iat])
    end

    it "returns a failure response" do
      response = subject
      expect(response.success?).to be(false)
      expect(response.exception.class).to be(raised_error)
      expect(response.status).to eq(:unauthorized)
    end
  end

  context "when validating one non permitted and one permitted restriction" do
    subject do
      constraint.validate(resource_restrictions: %w[exp ref])
    end

    it "returns a failure response" do
      response = subject
      expect(response.success?).to be(false)
      expect(response.exception.class).to be(raised_error)
      expect(response.status).to eq(:unauthorized)
    end
  end

  context "when validating one permitted and one non permitted restriction" do
    subject do
      constraint.validate(resource_restrictions: %w[ref nbf])
    end

    it "returns a failure response" do
      response = subject
      expect(response.success?).to be(false)
      expect(response.exception.class).to be(raised_error)
      expect(response.status).to eq(:unauthorized)
    end
  end
end
