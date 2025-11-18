# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::Constraints::NotEmptyConstraint) do
  let(:right_email) { "admin@example.com" }
  let(:username) { "admin" }

  let(:no_restrictions){ [] }

  let(:one_restriction) do
    [
      Authentication::ResourceRestrictions::ResourceRestriction.new(name: "user_email", value: right_email)
    ]
  end

  let(:two_restrictions) do
    [
      Authentication::ResourceRestrictions::ResourceRestriction.new(name: "user_email", value: right_email),
      Authentication::ResourceRestrictions::ResourceRestriction.new(name: "username", value: username)
    ]
  end

  context "NotEmptyConstraint" do
    subject do
      ::Authentication::Constraints::NotEmptyConstraint.new
    end

    it "validate runs successfully for one restriction" do
      response = subject.validate(resource_restrictions: one_restriction)
      expect(response.success?).to be(true)
    end

    it "validate runs successfully for two restrictions" do
      response = subject.validate(resource_restrictions: two_restrictions)
      expect(response.success?).to be(true)
    end

    it "validate returns a EmptyAnnotationsListConfigured failure response when there are not annotations" do
      response = subject.validate(resource_restrictions: no_restrictions)
      expect(response.success?).to be(false)
      expect(response.exception.class).to be(Errors::Authentication::Constraints::RoleMissingAnyRestrictions)
      expect(response.status).to eq(:unauthorized)
    end
  end
end
