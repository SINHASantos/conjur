# frozen_string_literal: true

require 'spec_helper'
require 'parallel'

describe AuthenticateController, type: :request do
  let(:account) { 'rspec' }
  let(:admin_access_token) { Slosilo["authn:#{account}"].signed_token('admin').to_json }
  let(:admin_request_env) { { 'HTTP_AUTHORIZATION' => "Token token=\"#{Base64.strict_encode64(admin_access_token)}\"" } }

  let(:service_id) { 'my-service' }
  let(:trust_domain) { 'trust.com' }

  let(:host_id) { 'my/workload/id' }
  let(:host_policy_branch) { 'spiffe/workloads' }
  let(:host_annotations) { nil }

  # This will be either given the value :policy or :v2_api.
  # Dictates how the certificate authenticator instance is created and configured.
  let(:create_mode) { nil }
  let(:variable_data) { {} }
  # Some states can only be reached through policy load operations. This flag is
  # used to indicate that a test case is expected to failure during creation,
  # and that further test steps should be skipped.
  let(:expect_creation_failure) { false }

  let(:saas_authn_url) { Rails.application.config.conjur_config.saas_authenticator_url }

  let(:sample_ca_pem) do
    "-----BEGIN CERTIFICATE-----\nbXktcGVtLWNlcnQ=\n-----END CERTIFICATE-----"
  end

  def default_config_variables
    %w[ca-cert]
  end

  def default_spiffe_config_variables
    default_config_variables + %w[host-mode trust-domain identity-path]
  end

  def default_global_restriction_config_variables
    default_config_variables + %w[san-uri san-dns san-ip cn]
  end

  def create_authenticator
    if create_mode == :policy
      load_policy(
        account: account,
        branch: 'root',
        yaml: authenticator_policy(
          service_id: service_id,
          config_variables: flatten_variable_data.keys.map { |k| sym_to_s(k) }
        )
      )

      flatten_variable_data.each do |key, value|
        load_variable_value(
          account: account,
          resource_id: "conjur/authn-cert/#{service_id}/#{sym_to_s(key)}",
          value: value
        )
      end
    elsif create_mode == :v2_api
      load_policy(
        account: account,
        branch: 'root',
        yaml: authenticator_base_branch
      )

      post(
        "/authenticators/#{account}",
        env: admin_request_env.merge(
          'ACCEPT' => 'application/x.secretsmgr.v2beta+json',
          'CONTENT_TYPE' => 'application/json',
          'RAW_POST_DATA' => v2_create_object.to_json
        )
      )
      expect(response.code).to eq(expect_creation_failure ? '422' : '201')
      skip('Skipping rest of test due to expected creation failure w/ V2 API') if expect_creation_failure
    end
  end

  def flatten_variable_data(map: variable_data, flat: {})
    map.each do |key, value|
      if value.is_a?(Hash)
        flatten_variable_data(map: value, flat: flat)
      elsif value.is_a?(Array)
        flat[key] = value.join(',')
      else
        flat[key] = value
      end
    end
    flat
  end

  def sym_to_s(key)
    key.to_s.gsub('_', '-')
  end

  def v2_create_object
    {
      type: 'certificate',
      name: service_id,
      enabled: true,
      data: variable_data
    }
  end

  describe 'POST /authn-cert/${service_id}/${account}/${id}/authenticate' do
    shared_examples 'authentication' do
      before do
        DatabaseCleaner.clean_with(:truncation)
        Slosilo["authn:#{account}"] ||= Slosilo::Key.new
        Role.create(role_id: "#{account}:user:admin") if Role["#{account}:user:admin"].nil?

        args = capture_args(Rails.logger, :info, :debug, :error)
        @info_logs = args[:info]

        # Enable certificate authentication feature flag for these tests
        allow_any_instance_of(Conjur::FeatureFlags::Features)
          .to receive(:enabled?)
          .and_call_original
        allow_any_instance_of(Conjur::FeatureFlags::Features)
          .to receive(:enabled?)
          .with(:certificate_authentication)
          .and_return(true)

        create_authenticator

        allow_any_instance_of(DB::Repository::AuthenticatorConfigRepository)
          .to receive(:enabled_authenticators)
          .and_return(["authn-cert/#{service_id}"])

        load_policy(
          account: account,
          branch: 'root',
          yaml: workloads_policy(
            id: host_policy_branch
          )
        )

        load_policy(
          account: account,
          branch: host_policy_branch,
          yaml: host_policy(
            id: host_id,
            annotations: host_annotations
          )
        )

        load_policy(
          account: account,
          branch: 'root',
          yaml: grant_policy(
            service_id: service_id,
            host_id: "#{host_policy_branch}/#{host_id}"
          )
        )
      end

      context 'when "ca-cert" variable is missing' do
        let(:variable_data) { {} }
        let(:expect_creation_failure) { true}

        it 'fails to authenticate' do
          @info_logs.clear
          authenticate(
            account: account,
            service_id: service_id,
            host_id: "#{host_policy_branch}/#{host_id}",
            client_certificate: 'my-cert-pem'
          )
          expect(response).to have_http_status(:unauthorized)
          expect(@info_logs).to satisfy do |logs|
            logs.any? do |log|
              log.to_s.include?('CONJ00037E Missing value for resource: rspec:variable:conjur/authn-cert/my-service/ca-cert')
            end
          end
        end
      end

      context 'when "ca-cert" variable is present' do
        let(:variable_data) { { ca_cert: sample_ca_pem } }

        before do
          stub_request(:post, "#{saas_authn_url}/authentications/cert").to_return(
            status: saas_authn_code,
            body: saas_authn_response.to_json
          )
        end

        context 'when client certificate is deemed invalid by external service' do
          let(:saas_authn_code) { 401 }
          let(:saas_authn_response) do
            {
              'errors' => [
                'code': 'CONJ00000E',
                'message': 'Message from SaaS service'
              ]
            }
          end

          it 'fails to authenticate' do
            @info_logs.clear
            authenticate(
              account: account,
              service_id: service_id,
              host_id: "#{host_policy_branch}/#{host_id}",
              client_certificate: 'my-cert-pem'
            )
            expect(response).to have_http_status(:unauthorized)
            expect(@info_logs).to satisfy do |logs|
              logs.any? do |log|
                log.to_s.include?('CONJ00000E Message from SaaS service')
              end
            end
          end
        end

        context 'when client certificate is signed by the ca bundle' do
          let(:saas_authn_code) { 200 }
          let(:saas_authn_response) { { 'attributes' => { 'some-attr' => 'some-value' } } }

          context 'when operating in "request" host mapping mode' do
            let(:common_name) { 'onprem.secretsmanager.cyberark.com' }
            let(:saas_authn_response) do
              {
                'attributes' => {
                  'sans_uri' => [ 'https://conjur.org/secrets-manager' ],
                  'sans_dns' => [ 'conjur.org' ],
                  'sans_ip' => [ '127.255.255.1' ],
                  'common_name' => common_name
                }
              }
            end

            context 'when authenticating role does not include any relevant annotations' do
              let(:host_annotations) { nil }

              it 'fails to authenticate' do
                @info_logs.clear
                authenticate(
                  account: account,
                  service_id: service_id,
                  host_id: "#{host_policy_branch}/#{host_id}",
                  client_certificate: 'my-cert-pem'
                )
                expect(response).to have_http_status(:unauthorized)
                expect(@info_logs).to satisfy do |logs|
                  logs.any? do |log|
                    log.to_s.include?('CONJ00069E Role must have at least one of the following constraints: ["san-uri", "san-dns", "san-ip", "cn"]')
                  end
                end
              end
            end

            context 'when authenticating role includes at least one relevant annotation' do
              context 'when certificate attributes do not match annotation restrictions' do
                context 'statically' do
                  let(:host_annotations) do
                    {
                      "authn-cert/#{service_id}/san-uri" => 'https://conjur.org/secrets-manager',
                      "authn-cert/#{service_id}/san-dns" => 'unrecognized.org'
                    }
                  end

                  it 'fails to authenticate' do
                    @info_logs.clear
                    authenticate(
                      account: account,
                      service_id: service_id,
                      host_id: "#{host_policy_branch}/#{host_id}",
                      client_certificate: 'my-cert-pem'
                    )
                    expect(response).to have_http_status(:unauthorized)
                    expect(@info_logs).to satisfy do |logs|
                      logs.any? do |log|
                        log.to_s.include?('CONJ00049E Resource restriction \'san-dns\' does not match with the corresponding value in the request')
                      end
                    end
                  end
                end

                context 'with wildcards' do
                  let(:host_annotations) do
                    {
                      "authn-cert/#{service_id}/san-uri" => 'https://conjur.org/secrets-manager/*',
                      "authn-cert/#{service_id}/san-dns" => '*.conjur.org'
                    }
                  end

                  it 'fails to authenticate' do
                    @info_logs.clear
                    authenticate(
                      account: account,
                      service_id: service_id,
                      host_id: "#{host_policy_branch}/#{host_id}",
                      client_certificate: 'my-cert-pem'
                    )
                    expect(response).to have_http_status(:unauthorized)
                    expect(@info_logs).to satisfy do |logs|
                      logs.any? do |log|
                        log.to_s.include?('CONJ00049E Resource restriction \'san-dns\' does not match with the corresponding value in the request')
                      end
                    end
                  end
                end
              end

              context 'when certificate attributes match annotation restrictions' do
                context 'statically' do
                  let(:host_annotations) do
                    {
                      "authn-cert/#{service_id}/san-uri" => 'https://conjur.org/secrets-manager',
                      "authn-cert/#{service_id}/san-dns" => 'conjur.org',
                      "authn-cert/#{service_id}/san-ip" => '127.255.255.1',
                      "authn-cert/#{service_id}/cn" => 'Static Non-DNS'
                    }
                  end
                  let(:common_name) { 'Static Non-DNS' }

                  it 'authenticates successfully' do
                    @info_logs.clear
                    authenticate(
                      account: account,
                      service_id: service_id,
                      host_id: "#{host_policy_branch}/#{host_id}",
                      client_certificate: 'my-cert-pem'
                    )
                    expect(response).to have_http_status(:success)
                  end
                end

                context 'with wildcards' do
                  let(:host_annotations) do
                    {
                      "authn-cert/#{service_id}/san-uri" => 'https://conjur.org/*',
                      "authn-cert/#{service_id}/san-dns" => 'conjur.org',
                      "authn-cert/#{service_id}/san-ip" => '127.255.255.1',
                      "authn-cert/#{service_id}/cn" => '*.*.cyberark.com'
                    }
                  end

                  it 'authenticates successfully' do
                    @info_logs.clear
                    authenticate(
                      account: account,
                      service_id: service_id,
                      host_id: "#{host_policy_branch}/#{host_id}",
                      client_certificate: 'my-cert-pem'
                    )
                    expect(response).to have_http_status(:success)
                  end
                end
              end
            end
          end

          context 'when operating in "spiffe" host mapping mode' do
            let(:variable_data) do
              {
                ca_cert: sample_ca_pem,
                identity: {
                  host_mode: 'spiffe',
                  trust_domain: trust_domain,
                  identity_path: host_policy_branch
                }
              }
            end

            context 'when missing required variables' do
              let(:expect_creation_failure) { true }
              let(:variable_data) do
                {
                  ca_cert: sample_ca_pem,
                  identity: {
                    host_mode: 'spiffe',
                    # trust_domain: trust_domain,
                    identity_path: host_policy_branch
                  }
                }
              end

              it 'fails to authenticate' do
                @info_logs.clear
                authenticate(
                  account: account,
                  service_id: service_id,
                  host_id: "#{host_policy_branch}/#{host_id}",
                  client_certificate: 'my-cert-pem'
                )

                expect(response).to have_http_status(:unauthorized)
                expect(@info_logs).to satisfy do |logs|
                  logs.any? do |log|
                    log.to_s.include?('CONJ00179E Variable \'trust-domain\' is required when variable \'host-mode\' is set to \'spiffe\'')
                  end
                end
              end
            end

            context 'when all required variables are present' do
              context 'when the client certificate does not include a SPIFFE ID' do
                let(:saas_authn_response) do
                  {
                    'attributes' => {
                      'sans_uri' => [ 'https://conjur.org/secrets-manager' ],
                      'sans_dns' => [ 'conjur.org' ],
                      'sans_ip': '127.255.255.1'
                    }
                  }
                end

                it 'fails to authenticate' do
                  @info_logs.clear
                  authenticate(
                    account: account,
                    service_id: service_id,
                    host_id: "#{host_policy_branch}/#{host_id}",
                    client_certificate: 'my-cert-pem'
                  )
                  expect(response).to have_http_status(:unauthorized)
                  expect(@info_logs).to satisfy do |logs|
                    logs.any? do |log|
                      log.to_s.include?('CONJ00183E Client certificate SPIFFE ID https://conjur.org/secrets-manager does not meet requirements: scheme must be \'spiffe://\'')
                    end
                  end
                end
              end

              context 'when the SPIFFE ID does not match authenticator config' do
                let(:saas_authn_response) do
                  {
                    'attributes' => {
                      'sans_uri' => [ "spiffe://distrust.org/#{host_id}" ],
                      'sans_dns' => [ 'conjur.org' ],
                      'sans_ip': '127.255.255.1'
                    }
                  }
                end

                it 'fails to authenticate' do
                  @info_logs.clear
                  authenticate(
                    account: account,
                    service_id: service_id,
                    host_id: "#{host_policy_branch}/#{host_id}",
                    client_certificate: 'my-cert-pem'
                  )
                  expect(response).to have_http_status(:unauthorized)
                  expect(@info_logs).to satisfy do |logs|
                    logs.any? do |log|
                      log.to_s.include?('CONJ00184E Client certificate SPIFFE ID spiffe://distrust.org/my/workload/id does not match expected trust domain trust.com')
                    end
                  end
                end
              end

              context 'when the SPIFFE ID matches authenticator config' do
                let(:saas_authn_response) do
                  {
                    'attributes' => {
                      'sans_uri' => [ "spiffe://#{trust_domain}/#{host_id}" ],
                      'sans_dns' => [ 'conjur.org' ],
                      'sans_ip': '127.255.255.1'
                    }
                  }
                end

                it 'authenticates successfully' do
                  @info_logs.clear
                  authenticate(
                    account: account,
                    service_id: service_id,
                    host_id: "#{host_policy_branch}/#{host_id}",
                    client_certificate: 'my-cert-pem'
                  )
                  expect(response).to have_http_status(:success)
                end
              end
            end
          end

          context 'when global restrictions are set' do
            let(:variable_data) do
              {
                ca_cert: sample_ca_pem,
                identity: {
                  san_uri: ['https://conjur.org/*'],
                  san_dns: ['conjur.org'],
                  san_ip: ['127.255.255.1'],
                  cn: 'onprem.secretsmanager.cyberark.com'
                }
              }
            end

            let(:host_annotations) do
              {
                "authn-cert/#{service_id}/san-dns" => 'conjur.org'
              }
            end
            before do
              stub_request(:post, "#{saas_authn_url}/authentications/cert").to_return(
                status: saas_authn_code,
                body: saas_authn_response.to_json
              )
            end

            context 'when client certificate attributes match' do
              let(:saas_authn_response) do
                {
                  'attributes' => {
                    'sans_uri' => ['https://conjur.org/secrets-manager'],
                    'sans_dns' => ['conjur.org'],
                    'sans_ip' => ['127.255.255.1'],
                    'common_name' => 'onprem.secretsmanager.cyberark.com'
                  }
                }
              end

              it 'authenticates successfully' do
                @info_logs.clear
                authenticate(
                  account: account,
                  service_id: service_id,
                  host_id: "#{host_policy_branch}/#{host_id}",
                  client_certificate: 'my-cert-pem'
                )
                expect(response).to have_http_status(:success)
              end
            end

            context 'when client certificate attributes mismatch' do
              let(:saas_authn_response) do
                {
                  'attributes' => {
                    'sans_uri' => ['https://conjur.org/secrets-manager/foo'],
                    'sans_dns' => ['conjur.org'],
                    'sans_ip' => ['127.255.255.1'],
                    'common_name' => 'onprem.secretsmanager.cyberark.com'
                  }
                }
              end

              it 'fails to authenticate' do
                @info_logs.clear
                authenticate(
                  account: account,
                  service_id: service_id,
                  host_id: "#{host_policy_branch}/#{host_id}",
                  client_certificate: 'my-cert-pem'
                )
                expect(response).to have_http_status(:unauthorized)
                expect(@info_logs).to satisfy do |logs|
                  logs.any? do |log|
                    log.to_s.include?('CONJ00176E Certificate URI Subject Alternative Name is missing or mismatched with webservice-scoped restriction')
                  end
                end
              end
            end
          end
        end
      end
    end

    context 'when using policy to create and configure authenticator' do
      let(:create_mode) { :policy }
      include_examples 'authentication'
    end

    context 'when using V2 API to create and configure authenticator' do
      let(:create_mode) { :v2_api }
      include_examples 'authentication'
    end
  end
end

def load_policy(account:, branch:, yaml:)
  post("/policies/#{account}/policy/#{branch}", env: admin_request_env.merge({ 'RAW_POST_DATA' => yaml }))
  expect(response).to have_http_status(:success)
end

def load_variable_value(account:, resource_id:, value:)
  post("/secrets/#{account}/variable/#{resource_id}", env: admin_request_env.merge({ 'RAW_POST_DATA' => value }))
  expect(response).to have_http_status(:success)
end

def authenticator_base_branch
  "
- !policy conjur/authn-cert
  "
end

def authenticator_policy(service_id:, config_variables:)
  variables = ""
  config_variables.each do |variable|
    variables += "    - !variable #{variable}\n"
  end

  "
- !policy
  id: conjur/authn-cert/#{service_id}
  body:
    - !webservice
#{variables}

    - !group apps
    - !permit
      role: !group apps
      privilege: [ read, authenticate ]
      resource: !webservice
  "
end

def workloads_policy(id:)
  "
- !policy #{id}
  "
end

def host_policy(id:, annotations: nil)
  annotations_yaml = ""
  unless annotations.nil?
    annotations_yaml += "annotations:\n"
    annotations.each do |k, v|
      annotations_yaml += "    #{k}: \"#{v}\"\n"
    end
  end

  "
- !host
  id: #{id}
  #{annotations_yaml}
  "
end

def grant_policy(service_id:, host_id:)
  "
- !grant
  role: !group conjur/authn-cert/#{service_id}/apps
  member: !host #{host_id}
  "
end

def authenticate(account:, service_id:, client_certificate:, host_id: nil)
  payload = { 'HTTP_X_SSL_CLIENT_CERTIFICATE' => CGI.escape(client_certificate) }
  if host_id.nil?
    post("/authn-cert/#{service_id}/#{account}/authenticate", env: payload)
  else
    post("/authn-cert/#{service_id}/#{account}/#{CGI.escape("host/#{host_id}")}/authenticate", env: payload)
  end
end

def capture_args(obj, *methods)
  args = { all: [] }

  methods.each do |method|
    original_method = obj.method(method)
    args[method] = []

    allow(obj).to receive(method) { |arg|
      args[method].push(arg)
      args[:all].push([method, arg])

      original_method.call(arg)
    }
  end

  args
end
