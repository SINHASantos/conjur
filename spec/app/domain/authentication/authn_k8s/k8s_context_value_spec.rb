# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnK8s::K8sContextValue) do
  let(:file_contents) { "MockFileContents" }
  let(:good_file) { double("MockExistentFile") }
  let(:bad_file) { double("MockNonexistentFile") }

  let(:good_resource_id) { "MockSecretIdGood" }
  let(:bad_resource_id) { "MockSecretIdBad" }

  let(:webservice) { double("MockWebservice") }
  let(:secret) { double("MockSecret", value: "MockSecret") }
  let(:resource) { double("MockResource", secret: secret) }

  before(:each) do
    # Use and_call_original to allow unmocked calls to File methods to work
    allow(File).to receive(:exist?).and_call_original
    allow(File).to receive(:exist?)
      .with(good_file)
      .and_return(true)

    allow(File).to receive(:exist?)
      .with(bad_file)
      .and_return(false)

    allow(File).to receive(:read).and_call_original
    allow(File).to receive(:read)
      .with(good_file)
      .and_return(file_contents)

    allow(webservice).to receive(:variable)
      .with(good_resource_id)
      .and_return(resource)

    allow(webservice).to receive(:variable)
      .with(bad_resource_id)
      .and_return(nil)
  end

  subject { Authentication::AuthnK8s::K8sContextValue }

  describe "get" do
    it "returns the value of a variable if it exists" do
      # Policy/variable configuration takes precedence
      expect(subject.get(webservice, good_file, good_resource_id)).to eq(secret.value)
    end

    it "returns the value of a file if the variable does not exist" do
      # Fall back to file when variable is not available
      expect(subject.get(webservice, good_file, bad_resource_id)).to eq(file_contents)
    end

    it "returns nil when neither exist" do
      expect(subject.get(webservice, bad_file, bad_resource_id)).to be_nil
    end

    it "returns nil when file doesnt exist and variable does but webservice is nil" do
      expect(subject.get(nil, bad_file, good_resource_id)).to be_nil
    end
  end

  describe "get when variable value is blank (empty string)" do
    let(:blank_resource_id) { "MockSecretIdBlank" }
    let(:blank_secret) { double("MockBlankSecret", value: "") }
    let(:blank_resource) { double("MockBlankResource", secret: blank_secret) }

    before do
      allow(webservice).to receive(:variable)
        .with(blank_resource_id)
        .and_return(blank_resource)
    end

    it "falls back to file when variable value is empty string" do
      # Empty string is treated as blank (not configured), so file takes over
      expect(subject.get(webservice, good_file, blank_resource_id)).to eq(file_contents)
    end

    it "returns nil when variable value is empty string and no file exists" do
      expect(subject.get(webservice, bad_file, blank_resource_id)).to be_nil
    end
  end

  describe "get when both file and variable exist" do
    let(:both_file_path) { "/path/to/file" }
    let(:both_resource_id) { "variable/resource/id" }
    let(:file_value) { "FileValue" }
    let(:variable_value) { "VariableValue" }
    let(:both_webservice) { double("Webservice") }
    let(:both_secret) { double("Secret", value: variable_value) }
    let(:both_resource) { double("Resource", secret: both_secret) }

    before do
      allow(File).to receive(:exist?)
        .with(both_file_path)
        .and_return(true)

      allow(File).to receive(:read)
        .with(both_file_path)
        .and_return(file_value)

      allow(both_webservice).to receive(:variable)
        .with(both_resource_id)
        .and_return(both_resource)
    end

    it "returns the variable value instead of file value" do
      # Policy/variable configuration should take precedence over mounted files
      expect(subject.get(both_webservice, both_file_path, both_resource_id)).to eq(variable_value)
    end
  end
end
