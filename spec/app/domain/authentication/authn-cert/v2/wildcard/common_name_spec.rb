# frozen_string_literal: true

require 'spec_helper'

RSpec.describe(Authentication::AuthnCert::V2::Wildcard::CommonName) do
  let(:logger) { double("logger") }
  let(:dns_matcher) { double("DnsName") }
  let(:success_response) { double("Success", success?: true, result: true) }
  let(:failure_response) { double("Failure", success?: false, message: "error") }

  subject { described_class.new(logger: logger) }

  before do
    stub_const("Authentication::AuthnCert::V2::Wildcard::DnsName", dns_matcher)
    allow(logger).to receive(:debug)
  end

  describe "#valid?" do
    context "when pattern is a valid DNS name" do
      let(:pattern) { "example.com" }

      before do
        allow(dns_matcher).to receive(:new).with(logger: logger).and_return(dns_matcher)
      end

      context "when DNS validation succeeds" do
        before do
          allow(dns_matcher).to receive(:valid?).with(pattern).and_return(success_response)
        end

        it "delegates to DNS matcher and returns success" do
          result = subject.valid?(pattern)
          expect(dns_matcher).to have_received(:new).with(logger: logger)
          expect(dns_matcher).to have_received(:valid?).with(pattern)
          expect(result).to eq(success_response)
        end

        it "logs successful validation" do
          expect(logger).to receive(:debug).with(
            an_instance_of(LogMessages::Authentication::AuthnCert::CommonNamePatternValidationSucceeded)
          )
          subject.valid?(pattern)
        end
      end

      context "when DNS validation fails" do
        before do
          allow(dns_matcher).to receive(:valid?).with(pattern).and_return(failure_response)
        end

        it "wraps DNS failure in new failure response" do
          result = subject.valid?(pattern)
          expect(result).to be_a(Responses::Failure)
          expect(result.success?).to be(false)
          expect(result.message).to be_an_instance_of(
            LogMessages::Authentication::AuthnCert::CommonNamePatternValidationFailed
          )
        end

        it "does not log successful validation" do
          expect(logger).not_to receive(:debug)
          subject.valid?(pattern)
        end
      end
    end

    context "when pattern is not a valid DNS name" do
      context "when pattern is not blank" do
        let(:pattern) { "non-dns-pattern" }

        it "returns success for non-blank non-DNS pattern" do
          result = subject.valid?(pattern)
          expect(result).to be_a(Responses::Success)
          expect(result.result).to be(true)
        end

        it "logs successful validation" do
          expect(logger).to receive(:debug).with(
            an_instance_of(LogMessages::Authentication::AuthnCert::CommonNamePatternValidationSucceeded)
          )
          subject.valid?(pattern)
        end
      end

      context "when pattern is blank" do
        let(:pattern) { "" }

        it "returns failure for blank pattern" do
          result = subject.valid?(pattern)
          expect(result).to be_a(Responses::Failure)
          expect(result.success?).to be(false)
        end

        it "includes validation failed message" do
          result = subject.valid?(pattern)
          expect(result.message).to be_an_instance_of(
            LogMessages::Authentication::AuthnCert::CommonNamePatternValidationFailed
          )
        end

        it "does not log successful validation" do
          expect(logger).not_to receive(:debug)
          subject.valid?(pattern)
        end
      end
    end

    context "with various non-DNS patterns" do
      [
        'simple-string',
        'database-name',
        'app_service_1',
        '123-numeric',
        'UPPERCASE',
        'mixed_Case-123',
        'With Spaces'
      ].each do |test_pattern|
        it "validates non-blank non-DNS pattern '#{test_pattern}'" do
          result = subject.valid?(test_pattern)
          expect(result).to be_a(Responses::Success)
          expect(result.result).to be(true)
        end
      end

      [nil, "", "   "].each do |blank_pattern|
        it "fails validation for blank pattern #{blank_pattern.inspect}" do
          result = subject.valid?(blank_pattern)
          expect(result).to be_a(Responses::Failure)
          expect(result.success?).to be(false)
        end
      end
    end
  end

  describe "#match?" do
    let(:pattern) { "example.com" }
    let(:common_name) { "example.com" }

    context "when pattern is a valid DNS name" do
      before do
        # allow(PublicSuffix).to receive(:valid?).with(pattern).and_return(true)
        allow(dns_matcher).to receive(:new).with(logger: logger).and_return(dns_matcher)
      end

      context "when DNS matching succeeds" do
        before do
          allow(dns_matcher).to receive(:match?).with(pattern, common_name).and_return(success_response)
        end

        it "delegates to DNS matcher and returns success" do
          result = subject.match?(pattern, common_name)
          expect(dns_matcher).to have_received(:new).with(logger: logger)
          expect(dns_matcher).to have_received(:match?).with(pattern, common_name)
          expect(result).to eq(success_response)
        end

        it "logs successful matching" do
          expect(logger).to receive(:debug).with(
            an_instance_of(LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingSucceeded)
          )
          subject.match?(pattern, common_name)
        end
      end

      context "when DNS matching fails" do
        before do
          allow(dns_matcher).to receive(:match?).with(pattern, common_name).and_return(failure_response)
        end

        it "wraps DNS failure in new failure response" do
          result = subject.match?(pattern, common_name)
          expect(result).to be_a(Responses::Failure)
          expect(result.success?).to be(false)
          expect(result.message).to be_an_instance_of(
            LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingFailed
          )
        end

        it "does not log successful matching" do
          expect(logger).not_to receive(:debug)
          subject.match?(pattern, common_name)
        end
      end
    end

    context "when pattern is not a valid DNS name" do
      before do
        # allow(PublicSuffix).to receive(:valid?).with(pattern).and_return(false)
      end

      context "when pattern matches common_name exactly" do
        let(:pattern) { "database-service" }
        let(:common_name) { "database-service" }

        it "returns success" do
          result = subject.match?(pattern, common_name)
          expect(result).to be_a(Responses::Success)
          expect(result.result).to be(true)
        end

        it "logs successful matching" do
          expect(logger).to receive(:debug).with(
            an_instance_of(LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingSucceeded)
          )
          subject.match?(pattern, common_name)
        end
      end

      context "when pattern does not match common_name" do
        let(:pattern) { "service-a" }
        let(:common_name) { "service-b" }

        it "returns failure" do
          result = subject.match?(pattern, common_name)
          expect(result).to be_a(Responses::Failure)
          expect(result.success?).to be(false)
        end

        it "includes failure message" do
          result = subject.match?(pattern, common_name)
          expect(result.message).to be_an_instance_of(
            LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingFailed
          )
        end

        it "does not log successful matching" do
          expect(logger).not_to receive(:debug)
          subject.match?(pattern, common_name)
        end
      end

      context "with various non-DNS patterns" do
        [
          { pattern: "exact-match", common_name: "exact-match", should_match: true },
          { pattern: "service", common_name: "service", should_match: true },
          { pattern: "app_1", common_name: "app_1", should_match: true },
          { pattern: "service", common_name: "different", should_match: false },
          { pattern: "case-sensitive", common_name: "Case-Sensitive", should_match: false },
          { pattern: "spaces not allowed", common_name: "spaces not allowed", should_match: true },
          { pattern: "special-chars_123", common_name: "special-chars_123", should_match: true }
        ].each do |test_case|
          it "#{test_case[:should_match] ? 'matches' : 'does not match'} '#{test_case[:pattern]}' with '#{test_case[:common_name]}'" do
            # allow(PublicSuffix).to receive(:valid?).with(test_case[:pattern]).and_return(false)

            result = subject.match?(test_case[:pattern], test_case[:common_name])

            if test_case[:should_match]
              expect(result).to be_a(Responses::Success)
              expect(result.result).to be(true)
            else
              expect(result).to be_a(Responses::Failure)
              expect(result.success?).to be(false)
            end
          end
        end
      end
    end
  end

  describe "integration with PublicSuffix" do
    context "with real DNS names" do
      it "identifies valid DNS names correctly" do
        %w[example.com subdomain.example.com www.github.io].each do |dns_name|
          allow(dns_matcher).to receive(:new).and_return(dns_matcher)
          allow(dns_matcher).to receive(:valid?).and_return(success_response)

          subject.valid?(dns_name)
        end
      end
    end

    context "with non-DNS strings" do
      it "identifies non-DNS strings correctly" do
        %w[service database-1 app_name 123456].each do |non_dns|
          result = subject.valid?(non_dns)
          expect(result).to be_a(Responses::Success)
        end
      end
    end
  end

  describe "log message creation" do
    let(:pattern) { "test-pattern" }

    context "for validation success" do
      it "creates log message with correct pattern" do
        log_message_class = LogMessages::Authentication::AuthnCert::CommonNamePatternValidationSucceeded
        expect(log_message_class).to receive(:new).with(pattern)

        subject.valid?(pattern)
      end
    end

    context "for matching success" do
      let(:common_name) { "test-pattern" }

      it "creates log message with pattern and common name" do
        log_message_class = LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingSucceeded
        expect(log_message_class).to receive(:new).with(pattern, common_name)

        subject.match?(pattern, common_name)
      end
    end

    context "for matching failure" do
      let(:common_name) { "test-name" }

      it "creates failure log message with pattern and common name" do
        log_message_class = LogMessages::Authentication::AuthnCert::CommonNamePatternMatchingFailed
        expect(log_message_class).to receive(:new).with(pattern, common_name).and_call_original

        result = subject.match?(pattern, common_name)
        expect(result.message).to be_an_instance_of(log_message_class)
      end
    end
  end
end
