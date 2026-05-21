require 'spec_helper'

RSpec.describe("status/index") do
  # The title text, 'Conjur Status', is a well-known
  # string that Conjur health probes are configured to
  # inspect the response for.
  it "includes the text 'Conjur Status'" do
    render

    expect(rendered).to include('Conjur Status')
  end

  it "includes the version number" do
    render

    expect(rendered).to include('Version')
    expect(rendered).to include(ENV['CONJUR_VERSION_DISPLAY'].to_s) unless ENV['CONJUR_VERSION_DISPLAY'].nil?
  end

  it "includes the version number in JSON" do
    render template: "status/index", formats: [:json]

    expect(rendered).to include("\"version\":\"#{ENV['CONJUR_VERSION_DISPLAY']}\"")
  end
end
