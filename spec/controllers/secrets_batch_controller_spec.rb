# frozen_string_literal: true

require 'spec_helper'
require 'parallel'

DatabaseCleaner.allow_remote_database_url = true
DatabaseCleaner.strategy = :truncation

describe(SecretsBatchController, type: :request) do
  let(:db) { instance_double(Sequel::Model.db) }
  let(:admin_user) { Role.find_or_create(role_id: 'rspec:user:admin') }
  let(:alice_user_id) { 'rspec:user:alice' }
  let(:alice_user) { Role.find_or_create(role_id: 'rspec:user:alice') }
  let(:batch_url) { '/secrets/rspec/values' }
  let(:batch_url_with_base64_encoding) { "#{batch_url}?encode_values=base64" }
  let(:expected_event_object) { instance_double(Audit::Event::Policy) }
  let(:log_object) { instance_double(::Audit::Log::SyslogAdapter, log: expected_event_object) }

  let(:test_policy) do
    <<~POLICY
      - !user alice

      - !policy
        id: data
        body:
        - !variable var1
        - !variable var2
        - !variable var_secret_not_set
        - !variable var_without_exec_permission
        - !variable var_without_any_permission

      - !permit
        role: !user alice
        privileges: [ read, execute ]
        resource: !variable data/var1
      - !permit
        role: !user alice
        privileges: [ read, execute ]
        resource: !variable data/var2
      - !permit
        role: !user alice
        privileges: [ read, execute ]
        resource: !variable data/var_secret_not_set
      - !permit
        role: !user alice
        privileges: [ read ]
        resource: !variable data/var_without_exec_permission
    POLICY
  end

  let(:batch_read_body) { { ids: ['data/var1'] }.to_json }

  before do
    Slosilo["authn:rspec"] ||= Slosilo::Key.new

    post('/policies/rspec/policy/root',
         env: token_auth_header(role: admin_user).merge(RAW_POST_DATA: test_policy))
    assert_response :success

    load Rails.root.join('config/routes.rb')

    post("/secrets/rspec/variable/data/var1",
         env: token_auth_header(role: admin_user).merge(
           { 'RAW_POST_DATA' => "secret_value1",
             'CONTENT_TYPE' => "text/plain" }
         ))
    assert_response :created
    post("/secrets/rspec/variable/data/var2",
         env: token_auth_header(role: admin_user).merge(
           { 'RAW_POST_DATA' => "secret_value2",
             'CONTENT_TYPE' => "text/plain" }
         ))
    assert_response :created
    post("/secrets/rspec/variable/data/var_without_exec_permission",
         env: token_auth_header(role: admin_user).merge(
           { 'RAW_POST_DATA' => "secret_value3",
             'CONTENT_TYPE' => "text/plain" }
         ))
    assert_response :created
    post("/secrets/rspec/variable/data/var_without_any_permission",
         env: token_auth_header(role: admin_user).merge(
           { 'RAW_POST_DATA' => "secret_value4",
             'CONTENT_TYPE' => "text/plain" }
         ))

    allow(Audit).to receive(:logger).and_return(log_object)
  end

  def headers_with_auth(payload = nil)
    headers = { 'Accept' => V2RestController::API_V2_BETA_HEADER }
    headers.merge!({ 'RAW_POST_DATA' => payload }, 'Content-Type' => 'application/json') if payload
    token_auth_header(role: alice_user).merge(headers)
  end

  def post_payload(payload, url = batch_url, headers = {})
    post(url, env: headers_with_auth(payload).merge(headers))
  end

  context 'beta header' do
    let(:body) { '{"ids":["data/var1"]}' }

    it 'denies access when header is not present' do
      post_payload(body, batch_url, { 'Accept' => "" })
      assert_response :bad_request
      response_data = JSON.parse(response.body)
      expect(response_data['message']).to eq('CONJ00194W The api belongs to v2 APIs but it missing the version "application/x.secretsmgr.v2beta+json" in the accept header')
    end

    it 'denies access when only v2 header is present' do
      post_payload(body, batch_url, v2_api_header)
      assert_response :bad_request
      response_data = JSON.parse(response.body)
      expect(response_data['message']).to eq('CONJ00194W The api belongs to v2 APIs but it missing the version "application/x.secretsmgr.v2beta+json" in the accept header')
    end

    it 'allows access when header is present' do
      post_payload(body)
      assert_response :multi_status
    end
  end

  context 'with valid ids' do
    it 'returns values for valid ids' do
      post_payload('{"ids":["data/var1","data/var2"]}')

      assert_response :multi_status
      response_data = JSON.parse(response.body)['secrets']

      expect(response_data.length).to eq(2)
      expect(response_data[0]['id']).to eq("data/var1")
      expect(response_data[0]['value']).to eq('secret_value1')
      expect(response_data[0]['status']).to eq(200)
      expect(response_data[1]['id']).to eq("data/var2")
      expect(response_data[1]['value']).to eq('secret_value2')
      expect(response_data[1]['status']).to eq(200)

      audit_message = "#{alice_user_id} successfully fetched fetch-secrets  with URI path: '/secrets/rspec/values' and JSON object: {\"ids\":[\"data/var1\",\"data/var2\"]}"
      verify_audit_message(audit_message)
    end

    it 'returns base64 encoded values when requested' do
      post_payload('{"ids":["data/var1","data/var2"]}',
                   batch_url_with_base64_encoding)

      assert_response :multi_status
      response_data = JSON.parse(response.body)['secrets']

      expect(response_data.length).to eq(2)
      expect(response_data[0]['id']).to eq("data/var1")
      expect(response_data[0]['value']).to eq(Base64.strict_encode64("secret_value1"))
      expect(response_data[0]['status']).to eq(200)
      expect(response_data[1]['id']).to eq("data/var2")
      expect(response_data[1]['value']).to eq(Base64.strict_encode64("secret_value2"))
      expect(response_data[1]['status']).to eq(200)
    end

    it 'accepts ids with leading slash' do
      post_payload('{"ids":["data/var1","/data/var2"]}')

      assert_response :multi_status
      response_data = JSON.parse(response.body)['secrets']

      expect(response_data.length).to eq(2)
      # Order should follow requested ids after normalization
      expect(response_data[0]['id']).to eq("data/var1")
      expect(response_data[0]['value']).to eq('secret_value1')
      expect(response_data[0]['status']).to eq(200)
      expect(response_data[1]['id']).to eq("data/var2")
      expect(response_data[1]['value']).to eq('secret_value2')
      expect(response_data[1]['status']).to eq(200)

      audit_message = "#{alice_user_id} successfully fetched fetch-secrets  with URI path: '/secrets/rspec/values' and JSON object: {\"ids\":[\"data/var1\",\"/data/var2\"]}"
      verify_audit_message(audit_message)
    end

    it 'accepts all ids when they all have leading slashes' do
      post_payload('{"ids":["/data/var1","/data/var2"]}')

      assert_response :multi_status
      response_data = JSON.parse(response.body)['secrets']

      expect(response_data.length).to eq(2)
      expect(response_data[0]['id']).to eq("data/var1")
      expect(response_data[0]['value']).to eq('secret_value1')
      expect(response_data[0]['status']).to eq(200)
      expect(response_data[1]['id']).to eq("data/var2")
      expect(response_data[1]['value']).to eq('secret_value2')
      expect(response_data[1]['status']).to eq(200)

      audit_message = "#{alice_user_id} successfully fetched fetch-secrets  with URI path: '/secrets/rspec/values' and JSON object: {\"ids\":[\"/data/var1\",\"/data/var2\"]}"
      verify_audit_message(audit_message)
    end

    it 'returns values for variables with different permissions and ordered correctly' do
      post_payload('{"ids":["data/var1",
                            "data/var_secret_not_set",
                            "data/var_without_exec_permission",
                            "data/var1",
                            "data/var_without_any_permission",
                            "data/var_secret_not_exist",
                            "data/var_secret_not_exist1",
                            "data/var2",
                            "conjur/prohibited_1",
                            "/conjur/prohibited_2"]}')
      assert_response :multi_status
      response_data = JSON.parse(response.body)['secrets']

      expect(response_data.length).to eq(10)
      expect(response_data[0]['id']).to eq("data/var1")
      expect(response_data[0]['value']).to eq('secret_value1')
      expect(response_data[0]['status']).to eq(200)
      expect(response_data[1]['id']).to eq("data/var_secret_not_set")
      expect(response_data[1]['value']).to eq('') # No value set
      expect(response_data[1]['status']).to eq(204)
      expect(response_data[2]['id']).to eq("data/var_without_exec_permission")
      expect(response_data[2]['status']).to eq(403) # Forbidden, no execute permission
      expect(response_data[2]['description']).to eq('Forbidden')
      expect(response_data[3]['id']).to eq("data/var1")
      expect(response_data[3]['value']).to eq('secret_value1')
      expect(response_data[3]['status']).to eq(200)
      expect(response_data[4]['id']).to eq("data/var_without_any_permission")
      expect(response_data[4]['status']).to eq(404) # Not found, no permissions
      expect(response_data[4]['description']).to eq("Variable data/var_without_any_permission not found")
      expect(response_data[5]['id']).to eq("data/var_secret_not_exist")
      expect(response_data[5]['status']).to eq(404) # Not found, variable does not exist
      expect(response_data[5]['description']).to eq("Variable data/var_secret_not_exist not found")
      expect(response_data[6]['id']).to eq("data/var_secret_not_exist1")
      expect(response_data[6]['status']).to eq(404) # Not found, variable does not exist
      expect(response_data[6]['description']).to eq("Variable data/var_secret_not_exist1 not found")
      expect(response_data[7]['id']).to eq("data/var2")
      expect(response_data[7]['value']).to eq('secret_value2')
      expect(response_data[7]['status']).to eq(200)
      expect(response_data[8]['id']).to eq("conjur/prohibited_1")
      expect(response_data[8]['description']).to eq('Variable conjur/prohibited_1 not found')
      expect(response_data[8]['status']).to eq(404)
      expect(response_data[9]['id']).to eq("conjur/prohibited_2")
      expect(response_data[9]['description']).to eq('Variable conjur/prohibited_2 not found')
      expect(response_data[9]['status']).to eq(404)
    end
  end

  context 'with multiple secret versions' do
    it 'returns only the latest version, not one entry per version' do
      # Update var1 twice more so it has 3 versions total
      post("/secrets/rspec/variable/data/var1",
           env: token_auth_header(role: admin_user).merge(
             { 'RAW_POST_DATA' => 'secret_value1_v2', 'CONTENT_TYPE' => 'text/plain' }
           ))
      assert_response :created
      post("/secrets/rspec/variable/data/var1",
           env: token_auth_header(role: admin_user).merge(
             { 'RAW_POST_DATA' => 'secret_value1_v3', 'CONTENT_TYPE' => 'text/plain' }
           ))
      assert_response :created

      post_payload('{"ids":["data/var1"]}')

      assert_response :multi_status
      response_data = JSON.parse(response.body)['secrets']

      expect(response_data.length).to eq(1)
      expect(response_data[0]['id']).to eq('data/var1')
      expect(response_data[0]['status']).to eq(200)
      expect(response_data[0]['value']).to eq('secret_value1_v3')
    end
  end

  context 'invalid input' do
    it 'returns error when request body is empty - handled by body parser' do
      post_payload(nil)

      assert_response :unprocessable_content
    end

    it 'returns error when request body is empty and application/json header is missing' do
      post(batch_url, env: token_auth_header(role: alice_user)
                             .merge(v2_beta_api_header)
                             .merge('RAW_POST_DATA' => ''))
      assert_response :unprocessable_content
    end

    it 'returns error when request body is missing and application/json header is missing' do
      post_payload(nil, batch_url, env: token_auth_header(role: alice_user)
                                          .merge(v2_beta_api_header))
      assert_response :unprocessable_content
    end

    it 'returns error when dynamic secret is included in ids' do
      post_payload('{"ids":["data/var1","data/var2","data/dynamic/var1"]}')

      assert_response :unprocessable_content
      response_data = JSON.parse(response.body)
      expect(response_data['message']).to eq("The request cannot contain dynamic secrets")
    end

    it 'returns error when ids parameter is missing' do
      post_payload('{"foo":"bar"}')
      assert_response :unprocessable_content
      response_data = JSON.parse(response.body)
      expect(response_data['message']).to eq("CONJ00190W Missing required parameter: ids")
    end

    it 'returns error when id has double leading slashes' do
      post_payload('{"ids":["//data/var1"]}')
      assert_response :unprocessable_content
      response_data = JSON.parse(response.body)
      expect(response_data['message']).to eq("Ids The id '//data/var1' is invalid")
    end
  end

  describe 'query param validation' do
    # Regression: valid requests should never be blocked by query param validation.
    context 'batch_read_values' do
      it 'permits the declared encode_values param' do
        post_payload(batch_read_body, "#{batch_url}?encode_values=base64")
        expect(response).not_to have_http_status(:unprocessable_content)
      end

      it 'blocks an unknown query param and names it in the response' do
        post_payload(batch_read_body, "#{batch_url}?badParam=true")
        expect(response).to have_http_status(:unprocessable_content)
        expect(response.body).to include('badParam')
      end
    end
  end
end
