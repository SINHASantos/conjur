require 'spec_helper'
require 'conjur/rack/authenticator'
require 'conjur/rack/auth_paths'

describe Conjur::Rack::AuthPaths do
  let(:app) { double(:app) }
  let(:logger) { double("Rails.logger", info: nil) }
  let(:authenticator) do
    Conjur::Rack::Authenticator.new(
      app,
      { except: described_class::EXCEPT, optional: described_class::OPTIONAL },
      logger
    )
  end

  def rack_env_for(path)
    { 'SCRIPT_NAME' => '', 'PATH_INFO' => path }
  end

  def call_without_auth(path)
    authenticator.call(rack_env_for(path))
  end

  # ── EXCEPT (middleware skips auth entirely — app always called) ───────────

  shared_examples "an excepted path" do |path|
    it "passes through to the app without requiring auth for #{path}" do
      expect(app).to receive(:call).with(rack_env_for(path))
      call_without_auth(path)
    end

    it "does not set identity for #{path}" do
      call_without_auth(path)
      expect(Conjur::Rack.identity?).to be(false)
    end
  end

  describe "EXCEPT paths (no auth enforced)" do
    before do
      allow(app).to receive(:call).and_return([200, {}, ['ok']])
    end

    include_examples "an excepted path", '/'
    include_examples "an excepted path", '/authenticators'
    include_examples "an excepted path", '/assets/application.js'
    include_examples "an excepted path", '/host_factories/hosts'

    include_examples "an excepted path", '/authn/myaccount/admin/authenticate'
    include_examples "an excepted path", '/authn-oidc/my-oidc/myaccount/authenticate'
    include_examples "an excepted path", '/authn-jwt/prod-jwt/myaccount/authenticate'
    include_examples "an excepted path", '/authn-jwt/prod-jwt/myaccount/somehost/authenticate'
    include_examples "an excepted path", '/authn-ldap/my-ldap/myaccount/admin/authenticate'
    include_examples "an excepted path", '/authn-gcp/myaccount/authenticate'
    include_examples "an excepted path", '/authn-k8s/my-k8s/myaccount/myhost/authenticate'
    include_examples "an excepted path", '/authn-iam/my-iam/myaccount/authenticate'
    include_examples "an excepted path", '/authn-azure/my-azure/myaccount/authenticate'

    include_examples "an excepted path", '/authn/myaccount/login'
    include_examples "an excepted path", '/authn-ldap/my-ldap/myaccount/login'

    # OIDC provider discovery
    include_examples "an excepted path", '/authn-oidc/my-oidc/providers'

    # Version endpoint
    include_examples "an excepted path", '/version'
  end

  describe "OPTIONAL paths" do
    before do
      allow(app).to receive(:call).and_return([200, {}, ['ok']])
    end

    include_examples "an excepted path", '/authn/myaccount/api_key'
    include_examples "an excepted path", '/authn-jwt/myaccount/api_key'
    include_examples "an excepted path", '/authn/myaccount/password'
    include_examples "an excepted path", '/authn-k8s/id/inject_client_cert'
  end

  describe "REQUIRED paths (returns 401 without auth)" do
    shared_examples "a required path" do |path|
      it "returns 401 for #{path} without auth" do
        status, _headers, body = call_without_auth(path)
        expect(status).to eq(401)
        expect(body.join).to eq("Authorization missing")
      end
    end

    include_examples "a required path", '/authn-jwt/prod-jwt/myaccount/status'
    include_examples "a required path", '/authn-oidc/my-oidc/myaccount/status'
    include_examples "a required path", '/authn/myaccount/status'
    include_examples "a required path", '/authn-jwt/prod-jwt/myaccount'
    include_examples "a required path", '/resources'
    include_examples "a required path", '/whoami'
  end
end
