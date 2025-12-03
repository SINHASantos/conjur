# frozen_string_literal: true

require 'spec_helper'
require 'time'

DatabaseCleaner.strategy = :truncation

describe WorkloadsController, :type => :request do
  let(:workloads_controller) { described_class.new }
  let(:admin_user) { Role.find_or_create(role_id: 'rspec:user:admin') }
  let(:alice_user_id) { 'rspec:user:alice' }
  let(:alice_user) { Role.find_or_create(role_id: alice_user_id) }
  let(:roby_user_id) { 'rspec:user:roby' }
  let(:roby_user) { Role.find_or_create(role_id: roby_user_id) }
  let(:read_only_user_id) { 'rspec:user:read_only_user' }
  let(:read_only_user) { Role.find_or_create(role_id: read_only_user_id) }
  let(:random_user_id) { 'rspec:user:random_user' }
  let(:random_user) { Role.find_or_create(role_id: random_user_id) }

  let(:test_policy) do
    <<~POLICY
      - !user alice
      - !user read_only_user
      - !user random_user
      - !user roby

      - !policy
        id: data
    POLICY
  end

  let(:gcp_policy) do
    <<~POLICY
      - !policy
        id: conjur/authn-gcp
        body:
        - !webservice
        - !group apps
        - !permit
          role: !group apps
          privilege: [ read, authenticate ]
          resource: !webservice
    POLICY
  end

  let(:azure_policy) do
    <<~POLICY
      - !policy
        id: conjur
        body:
        - !policy
          id: authn-azure
          body:
          - !policy
            id: AzureWS1
            body:
               - !webservice
               - !group
                 id: apps
               - !permit
                 role: !group apps
                 privilege: [ read, authenticate ]
                 resource: !webservice

    POLICY
  end

  let(:jwt_policy) do
    <<~POLICY
      - !policy
       id: conjur
       body:
       - !policy
         id: authn-jwt
         body:
         - !policy
           id: jwtservice
           body:
             - !webservice status
             - !webservice
               annotations:
                 description: "this is my jwt authenticator"
             - !group apps
             - !permit
               role: !group apps
               privilege: [ read, authenticate ]
               resource: !webservice
    POLICY
  end

  let(:certificate_policy) do
    <<~POLICY
      - !policy
        id: conjur
        body:
        - !policy
          id: authn-cert
          body:
          - !policy
            id: x509-cert-authn
            body:
               - !webservice
               - !group
                 id: apps
               - !permit
                 role: !group apps
                 privilege: [ read, authenticate ]
                 resource: !webservice

    POLICY
  end

  def setup_authenticator_policy(policy)
    return unless policy
    post('/policies/rspec/policy/root',
         env: token_auth_header(role: admin_user)
                .merge({ 'RAW_POST_DATA' => policy }))

    assert_response :success
  end

  def create_workload_with_authenticator(type, service_id, data, role = nil, workload_type = nil, owner = nil)
    allow(Rails.application.config.conjur_config).to receive(:conjur_pubsub_enabled).and_return(true)

    # Use admin_user as default if role is not provided
    role ||= admin_user

    params = valid_params.clone
    params[:type] = workload_type if workload_type
    params[:owner] = owner if owner
    params[:authn_descriptors] = [{ type: type,
                                    service_id: service_id,
                                    data: data }]

    post(url, env: token_auth_header(role: role)
                     .merge(v2_beta_api_header)
                     .merge({ 'CONTENT_TYPE' => "application/json",
                              'RAW_POST_DATA' => params.to_json }))

    assert_response :created
    [params, JSON.parse(response.body)]
  end

  # Helper to verify response basics
  def verify_response(response_body, params, type = 'other')
    expect(response_body['name']).to eq(name)
    expect(response_body['branch']).to eq(branch)
    expect(response_body['type']).to eq(type)
    expect(response_body['annotations']).to eq(params[:annotations].stringify_keys)
    expect(response_body['restricted_to']).to eq(params[:restricted_to])

    # Verify authn descriptor structure
    expect(response_body['authn_descriptors']).to be_an(Array)
    expect(response_body['authn_descriptors'].length).to eq(1)

    descriptor = response_body['authn_descriptors'][0]
    expect(descriptor['type']).to eq(params[:authn_descriptors][0][:type])
    expect(descriptor['service_id']).to eq(params[:authn_descriptors][0][:service_id])
    expect(descriptor['data']).to include(params[:authn_descriptors][0][:data].stringify_keys)
  end

  before do
    Slosilo["authn:rspec"] ||= Slosilo::Key.new

    post('/policies/rspec/policy/root',
         env: token_auth_header(role: admin_user).merge(RAW_POST_DATA: test_policy))
    assert_response :success

    load Rails.root.join('config/routes.rb')
  end

  describe 'POST #add_workload' do
    let(:branch) { 'data/work' }
    let(:name) { 'new-workload' }
    let(:url) { "/workloads/rspec" }

    # Define creator host
    let(:creator_host_id) { 'rspec:host:data/creator-host' }
    let(:creator_host) { Role.find_or_create(role_id: creator_host_id) }

    # Define a host with read-only access
    let(:read_host_id) { 'rspec:host:data/read-only-host' }
    let(:read_host) { Role.find_or_create(role_id: read_host_id) }

    # Define a host with no relevant permissions
    let(:unprivileged_host_id) { 'rspec:host:data/no-access-host' }
    let(:unprivileged_host) { Role.find_or_create(role_id: unprivileged_host_id) }

    let(:valid_params) do
      {
        name: name,
        branch: branch,
        authn_descriptors: [
          type: "api_key"
        ],
        annotations: {
          "app": "web",
          "env": "test"
        },
        restricted_to: ["192.168.1.0/24", "192.163.1.0/24"]
      }
    end

    let(:workload_policy_work) do
      <<~POLICY
        - !policy
          id: work
      POLICY
    end

    let(:aws_valid_params) do
      <<~BODY
        {
          "type": "aws",
          "name": "testAuthenticator", 
          "enabled": true,
          "owner": { "id" : "data/creator-host", "kind": "host" }
        }
      BODY
    end

    let(:permission_policy) do
      <<~POLICY
        - !policy
          id: conjur
          body:
            - !policy
              id: authn-iam
              body:
                - !policy
                  id: testAuthenticator
                  body:
                    - !webservice

        - !permit
          resource: !policy conjur/authn-iam/testAuthenticator
          privileges: [ update ]
          role: !host data/creator-host
      POLICY
    end

    let(:host_policy) do
      <<~POLICY
        # Creator host with full permissions
        - !host
          id: data/creator-host
          
        # Read-only host
        - !host
          id: data/read-only-host
          
        # No access host
        - !host
          id: data/no-access-host

        # Grant permissions to creator host
        - !permit
          role: !host data/creator-host
          privileges: [ read, update, create ]
          resource: !policy data/work

        # Grant read-only permissions to read host
        - !permit
          role: !host data/read-only-host
          privileges: [ read ]
          resource: !policy data/work

        - !policy
          id: conjur
          body:
            - !policy
              id: authn-iam

      POLICY
    end

    def expect_workload_resources_created(workload_name, branch, authn_type, authn_name, annotations_input, claims, workload_type, owner)
      resource_id = "rspec:host:#{branch}/#{workload_name}"
      group_id = "rspec:group:conjur/#{authn_type}/#{authn_name}/apps"

      # Directly use model classes
      resource = Resource[resource_id]
      role = Role[resource_id]
      annotations = Annotation.where(resource_id: resource_id)
                              .each_with_object({}) { |a, h| h[a.name] = a.value }
      group = Resource[group_id]
      membership = RoleMembership.where(role_id: group_id, member_id: resource_id).first

      claims_with_prefix = claims.transform_keys { |k| "#{authn_type}/#{authn_name}/#{k}" }
      expected_annotations = annotations_input.stringify_keys
                                              .merge(claims_with_prefix.stringify_keys)
                                              .merge({ "type" => workload_type })

      expect(resource.owner_id).to eq("rspec:host:#{owner[:id]}") if owner.present?
      expect(resource).not_to be_nil
      expect(role).not_to be_nil
      expect(annotations).to include(expected_annotations)
      expect(group).not_to be_nil
      expect(membership).not_to be_nil
    end


    before do
      allow(Rails.application.config.conjur_config)
        .to receive(:conjur_restricted_ip_enabled).and_return(true)
      # Create the policy structure
      post('/policies/rspec/policy/data',
           env: token_auth_header(role: admin_user)
                  .merge({ 'RAW_POST_DATA' => workload_policy_work }))
      assert_response :success

      # Create hosts and grant permissions
      post('/policies/rspec/policy/root',
           env: token_auth_header(role: admin_user)
                  .merge({ 'RAW_POST_DATA' => host_policy }))
      assert_response :success

      post("/authenticators/rspec",
           env: token_auth_header(role: admin_user)
                  .merge(v2_beta_api_header)
                  .merge('RAW_POST_DATA' => aws_valid_params,
                         'CONTENT_TYPE' => "application/json"))
      assert_response :created

      # permission policy
      post('/policies/rspec/policy/root',
           env: token_auth_header(role: admin_user)
                  .merge({ 'RAW_POST_DATA' => host_policy }))
      assert_response :success
    end

    context 'when the request is valid' do
      it 'creates a workload using another host and returns a success response' do

        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => "application/json",
                                  'RAW_POST_DATA' => valid_params.to_json }))

        assert_response :created

        # Verify the workload was created
        response_body = JSON.parse(response.body)
        expect(response_body['name']).to eq(name)
        expect(response_body['branch']).to eq(branch)
        expect(response_body['annotations']).to eq(valid_params[:annotations].stringify_keys)
        expect(response_body['restricted_to']).to eq(valid_params[:restricted_to])

        # Check API key structure
        expect(response_body['authn_descriptors']).to be_an(Array)
        expect(response_body['authn_descriptors'].length).to eq(1)
        api_key_descriptor = response_body['authn_descriptors'][0]
        expect(api_key_descriptor['type']).to eq('api_key')
        expect(api_key_descriptor['data']['value']).to be_present
      end
    end

    context 'when the host lacks permissions' do
      it 'returns forbidden when host has only read permissions' do
        post(url, env: token_auth_header(role: read_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'RAW_POST_DATA' => valid_params.to_json,
                                  'CONTENT_TYPE' => "application/json" }))

        assert_response :not_found
      end

      it 'returns not found when host has no permissions' do
        post(url, env: token_auth_header(role: unprivileged_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'RAW_POST_DATA' => valid_params.to_json,
                                  'CONTENT_TYPE' => "application/json" })
        )

        assert_response :not_found
      end

      it 'returns forbidden when host has read branch permission no create permission' do
        # Define authenticator without permission for creator host
        unauthorized_service_id = "unauthorized-service"

        # Create an authenticator policy without granting permissions to creator_host
        no_permission_policy = <<~POLICY
          - !policy
            id: conjur
            body:
              - !policy
                id: authn-iam
                body:
                  - !policy
                    id: #{unauthorized_service_id}
                    body:
                      - !webservice
          - !permit
            resource: !policy conjur/authn-iam/#{unauthorized_service_id}
            privileges: [ read ]
            role: !host data/creator-host
        POLICY

        setup_authenticator_policy(no_permission_policy)

        # AWS IAM authenticator data
        aws_data = { account: "123456789012", role: "my-role-name" }

        params = valid_params.clone
        params[:authn_descriptors] = [{ type: "aws",
                                        service_id: unauthorized_service_id,
                                        data: aws_data }]

        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => "application/json",
                                  'RAW_POST_DATA' => params.to_json }))

        assert_response :not_found
      end
    end
    context 'when the host has permissions' do
      it 'succeeds when host has create permissions on authenticator policy' do
        authorized_service_id = "authorized-service"

        # Create an authenticator policy with create permissions granted to creator_host
        permission_policy = <<~POLICY
          - !policy
            id: conjur
            body:
              - !policy
                id: authn-iam
                body:
                  - !policy
                    id: #{authorized_service_id}
                    body:
                      - !webservice
                      - !group apps
          - !permit
            resource: !policy conjur/authn-iam/#{authorized_service_id}
            privileges: [ create ]
            role: !host data/creator-host
        POLICY

        setup_authenticator_policy(permission_policy)

        # AWS IAM authenticator data
        aws_data = { account: "123456789012", role: "my-role-name" }

        params = valid_params.clone
        params[:authn_descriptors] = [{ type: "aws",
                                        service_id: authorized_service_id,
                                        data: aws_data }]

        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => "application/json",
                                  'RAW_POST_DATA' => params.to_json }))

        expect(response).to have_http_status(:created)
        response_body = JSON.parse(response.body)
        expect(response_body['name']).to eq(name)
        expect(response_body['branch']).to eq(branch)
        expect(response_body['authn_descriptors'].first['type']).to eq('aws')
        expect(response_body['authn_descriptors'].first['service_id']).to eq(authorized_service_id)
      end
    end

    context 'when the request is invalid' do
      it 'returns unprocessable entity when required parameters are missing' do
        # Missing branch and authn_descriptor
        invalid_params = { name: name }

        post(url, params: invalid_params.to_json,
             env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :unprocessable_entity
      end

      it 'returns unprocessable entity when workload already exists' do
        # Create the workload first
        post(url, env: token_auth_header(role: creator_host).merge(v2_beta_api_header).
          merge({ 'CONTENT_TYPE' => 'application/json',
                  'RAW_POST_DATA' => valid_params.to_json }))

        assert_response :created

        # Try to create it again
        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => 'application/json',
                                  'RAW_POST_DATA' => valid_params.to_json }))

        assert_response :conflict
      end

      it 'returns unprocessable entity when annotation value has invalid format' do
        params = valid_params.merge(annotations: { foo: "bad<lue" })
        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => "application/json",
                                  'RAW_POST_DATA' => params.to_json }))

        expect(response).to have_http_status(:unprocessable_entity)
        expect(JSON.parse(response.body))
          .to eq({ "code" => "422",
                   "message" => "Annotations Foo Invalid 'annotation value'." })
      end

      it 'returns bad request with invalid authn_descriptors' do
        invalid_authn_params = valid_params.clone
        invalid_authn_params[:authn_descriptors] = [type: 'invalid_type']

        post(url, params: invalid_authn_params.to_json,
             env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :unprocessable_entity
      end

      it 'returns unprocessable entity when restricted to disabled' do
        allow(Rails.application.config.conjur_config).to receive(:conjur_restricted_ip_enabled).and_return(false)
        authn_params = valid_params.clone

        post(url, params: authn_params.to_json,
             env: token_auth_header(role: creator_host)
                    .merge(v2_beta_api_header))

        assert_response :unprocessable_entity
      end
    end

    context 'create workload with authenticator' do
      it 'creates a workload with AWS IAM authenticator' do
        # AWS IAM authenticator data
        aws_data = { account: "123456789012", role: "my-role-name" }

        # Create workload with AWS authenticator
        aws_params, response_body = create_workload_with_authenticator(
          "aws", "testAuthenticator", aws_data, creator_host)

        # Verify response structure
        verify_response(response_body, aws_params)
      end

      it 'creates a workload with GCP authenticator' do
        # Setup GCP authenticator policy
        setup_authenticator_policy(gcp_policy)

        # GCP authenticator data
        gcp_data = { instance_name: "web-app-01",
                     project_id: "my-gcp-project",
                     service_account_email: "com-np-int-h-cloudsec-cnjcloud@appspot.gserviceaccount.com",
                     service_account_id: "77777777777777778" }

        # Create workload with GCP authenticator
        gcp_params, response_body = create_workload_with_authenticator(
          "gcp", "default", gcp_data)

        # Verify response structure
        verify_response(response_body, gcp_params)

        # Verify database annotations
        host_id = "rspec:host:#{branch}/#{name}"
        gcp_params[:annotations].each do |key, value|
          annotation = Annotation.where(resource_id: host_id, name: key.to_s).first
          expect(annotation).not_to be_nil
          expect(annotation.value).to eq(value.to_s)
        end
      end

      it 'creates a workload with JWT authenticator' do
        # Setup JWT authenticator policy
        setup_authenticator_policy(jwt_policy)

        # Add owner to params
        owner = { id: 'data/creator-host', kind: 'host' }

        # JWT authenticator data
        jwt_data = { sub: "system:serviceaccount:jwttoken" }

        # Create workload with JWT authenticator
        jwt_params, response_body = create_workload_with_authenticator(
          "jwt", "jwtservice", jwt_data, admin_user, "jenkins", owner)

        expect_workload_resources_created(name, branch, "authn-jwt", "jwtservice", valid_params[:annotations], jwt_data, "jenkins", owner)
        # Verify response structure
        verify_response(response_body, jwt_params, 'jenkins')
      end

      it 'creates a workload with AZURE authenticator' do
        # Setup Azure authenticator policy
        setup_authenticator_policy(azure_policy)

        # Azure authenticator data
        azure_data = {
          "subscription_id": "subscr1pt10n-1dmy-subsc-r1pt10n1d",
          "resource_group": "myResourceGroup",
          "system_assigned_identity": "0000aaaa-00aa-00aa-00aa-00000aaaaa",
          "user_assigned_identity": "test-ua-managed-identity"
        }

        # Create workload with Azure authenticator
        azure_params, response_body = create_workload_with_authenticator(
          "azure", "AzureWS1", azure_data)

        # Verify response structure
        verify_response(response_body, azure_params)
      end

      it 'creates a workload with kubernetes type' do
        allow(Rails.application.config.conjur_config).to receive(:conjur_pubsub_enabled).and_return(true)

        kubernetes_params = valid_params.clone
        kubernetes_params[:type] = "kubernetes"

        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => "application/json",
                                  'RAW_POST_DATA' => kubernetes_params.to_json }))

        assert_response :created
        # Verify the workload was created with kubernetes type
        response_body = JSON.parse(response.body)
        expect(response_body['name']).to eq(name)
        expect(response_body['branch']).to eq(branch)
        expect(response_body['type']).to eq('kubernetes')
        expect(response_body['subtype']).to eq('openshift')
        expect(response_body['annotations']).to eq(kubernetes_params[:annotations].stringify_keys)
      end

      it 'creates a workload with Certificate authenticator' do
        setup_authenticator_policy(certificate_policy)
        # cert authenticator data
        cert_data = { "cn": "data/cert-apps/secretAppD", "san_uri": ["spiffe://example.com/ns/prod/sa/secret-app-d"], "san_dns": ["tests.example.com"], "san_ip": ["127.0.0.1", "127.0.0.2"] }

        cert_params, response_body = create_workload_with_authenticator(
          "cert", "x509-cert-authn", cert_data)

        # Verify response structure
        verify_response(response_body, cert_params)
      end

      it 'returns not found when branch does not exist' do
        nonexistent_params = valid_params.clone
        nonexistent_params[:branch] = 'data/test'

        post(url, env: token_auth_header(role: creator_host)
                         .merge(v2_beta_api_header)
                         .merge({ 'CONTENT_TYPE' => 'application/json',
                                  'RAW_POST_DATA' => nonexistent_params.to_json }))

        assert_response :not_found
      end
    end
  end

  describe 'DELETE #destroy' do
    let(:branch) { 'data/work' }
    let(:name) { 'workload-to-delete' }
    let(:url) { "/workloads/rspec" }
    let(:delete_url) { "/workloads/rspec/#{branch}/#{name}" }

    # Define creator host
    let(:creator_host_id) { 'rspec:host:data/creator-host' }
    let(:creator_host) { Role.find_or_create(role_id: creator_host_id) }

    # Define a host with read-only access
    let(:read_host_id) { 'rspec:host:data/read-only-host' }
    let(:read_host) { Role.find_or_create(role_id: read_host_id) }

    # Define a host with no relevant permissions
    let(:unprivileged_host_id) { 'rspec:host:data/no-access-host' }
    let(:unprivileged_host) { Role.find_or_create(role_id: unprivileged_host_id) }

    let(:valid_params) do
      {
        name: name,
        branch: branch,
        owner: {
          kind: "host",
          id: "data/creator-host"
        },
        authn_descriptors: [
          type: "api_key"
        ],
        annotations: {
          "app": "web",
          "env": "test"
        },
        restricted_to: ["192.168.1.0/24", "192.163.1.0/24"]
      }
    end

    let(:workload_policy_work) do
      <<~POLICY
        - !policy
          id: work
      POLICY
    end

    let(:host_policy) do
      <<~POLICY
        # Creator host with full permissions
        - !host
          id: data/creator-host
          
        # Read-only host
        - !host
          id: data/read-only-host
          
        # No access host
        - !host
          id: data/no-access-host

        # Grant permissions to creator host
        - !permit
          role: !host data/creator-host
          privileges: [ read, update, create ]
          resource: !policy data/work

        # Grant read-only permissions to read host
        - !permit
          role: !host data/read-only-host
          privileges: [ read ]
          resource: !policy data/work

        - !policy
          id: conjur
          body:
            - !policy
              id: authn-iam

      POLICY
    end

    # Helper to create a workload for deletion tests
    def create_test_workload(role = creator_host, params = valid_params)
      post("/workloads/rspec",
           env: token_auth_header(role: role)
                  .merge(v2_beta_api_header)
                  .merge({ 'CONTENT_TYPE' => "application/json",
                           'RAW_POST_DATA' => params.to_json }))
      assert_response :created
    end

    # Helper to verify workload exists in database
    def workload_exists?(branch, name)
      resource_id = "rspec:host:#{branch}/#{name}"
      ::Resource[resource_id].present? && ::Role[resource_id].present?
    end

    # Helper to get workload resource
    def get_workload_resource(branch, name)
      resource_id = "rspec:host:#{branch}/#{name}"
      ::Resource[resource_id]
    end

    # Helper to get workload role
    def get_workload_role(branch, name)
      resource_id = "rspec:host:#{branch}/#{name}"
      ::Role[resource_id]
    end

    before do
      allow(Rails.application.config.conjur_config)
        .to receive(:conjur_restricted_ip_enabled).and_return(true)

      # Create the policy structure
      post('/policies/rspec/policy/data',
           env: token_auth_header(role: admin_user)
                  .merge({ 'RAW_POST_DATA' => workload_policy_work }))
      assert_response :success

      # Create hosts and grant permissions
      post('/policies/rspec/policy/root',
           env: token_auth_header(role: admin_user)
                  .merge({ 'RAW_POST_DATA' => host_policy }))
      assert_response :success
    end

    context 'when the workload exists' do
      before do
        create_test_workload
      end

      it 'deletes the workload and returns no content' do
        expect(workload_exists?(branch, name)).to be true

        delete(delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content
        expect(workload_exists?(branch, name)).to be false
      end

      it 'removes the workload from database completely' do
        resource_id = "rspec:host:#{branch}/#{name}"

        # Verify workload exists before deletion
        expect(::Resource[resource_id]).not_to be_nil
        expect(::Role[resource_id]).not_to be_nil
        expect(::Annotation.where(resource_id: resource_id).count).to be > 0

        delete(delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify complete removal
        expect(::Resource[resource_id]).to be_nil
        expect(::Role[resource_id]).to be_nil
        expect(::Annotation.where(resource_id: resource_id).count).to eq(0)
      end

      it 'deletes workload with special characters in name' do
        special_name = 'workload_with-special.chars'
        special_params = valid_params.merge(name: special_name)
        create_test_workload(creator_host, special_params)

        special_delete_url = "/workloads/rspec/#{branch}/#{special_name}"

        expect(workload_exists?(branch, special_name)).to be true

        delete(special_delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content
        expect(workload_exists?(branch, special_name)).to be false
      end

      it 'returns forbidden when host has only read permissions' do
        delete(delete_url,
               env: token_auth_header(role: read_host).merge(v2_beta_api_header))

        assert_response :not_found
        expect(workload_exists?(branch, name)).to be true
      end

      it 'returns not found when host has no permissions' do
        delete(delete_url,
               env: token_auth_header(role: unprivileged_host).merge(v2_beta_api_header))

        assert_response :not_found
        expect(workload_exists?(branch, name)).to be true
      end

      it 'successfully deletes workload using admin user' do
        expect(workload_exists?(branch, name)).to be true

        delete(delete_url,
               env: token_auth_header(role: admin_user).merge(v2_beta_api_header))

        assert_response :no_content
        expect(workload_exists?(branch, name)).to be false
      end
    end

    context 'when the workload does not exist' do
      it 'returns not found for non-existent workload' do
        nonexistent_url = "/workloads/rspec/#{branch}/nonexistent-workload"

        delete(nonexistent_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :not_found
      end

      it 'returns not found when branch does not exist' do
        nonexistent_branch_url = "/workloads/rspec/data/nonexistent-branch/#{name}"

        delete(nonexistent_branch_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :not_found
      end
    end

    context 'when workload has owned resources' do
      let(:owned_resource_policy) do
        <<~POLICY
          - !host
            id: owned-host
            owner: !host #{name}
          
          # Grant update permission to creator_host on the owned resource
          - !permit
            role: !host ../creator-host
            privileges: [ update ]
            resource: !host owned-host
        POLICY
      end

      before do
        create_test_workload

        # Create a resource owned by the workload
        post("/policies/rspec/policy/#{branch}",
             env: token_auth_header(role: admin_user)
                    .merge({ 'RAW_POST_DATA' => owned_resource_policy }))
        assert_response :success
      end

      it 'deletes workload and all owned resources recursively' do
        workload_id = "rspec:host:#{branch}/#{name}"
        owned_id = "rspec:host:#{branch}/owned-host"

        # Verify both exist
        expect(::Resource[workload_id]).not_to be_nil
        expect(::Resource[owned_id]).not_to be_nil
        expect(::Resource[owned_id].owner_id).to eq(workload_id)

        delete(delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify both are deleted
        expect(::Resource[workload_id]).to be_nil
        expect(::Resource[owned_id]).to be_nil
      end
    end

    context 'when deleting workload with different authenticators' do
      it 'deletes workload with JWT authenticator' do
        # Setup JWT authenticator policy
        setup_authenticator_policy(jwt_policy)

        # JWT authenticator data
        jwt_data = { sub: "system:serviceaccount:jwttoken" }

        # Create workload with JWT authenticator
        jwt_params, response_body = create_workload_with_authenticator(
          "jwt", "jwtservice", jwt_data)

        # Verify workload was created successfully
        expect(response_body['name']).to eq(name)

        # Verify membership in JWT apps group
        group_id = "rspec:group:conjur/authn-jwt/jwtservice/apps"
        workload_id = "rspec:host:#{branch}/#{name}"
        expect(::RoleMembership.where(role_id: group_id, member_id: workload_id).count).to eq(1)

        # Delete the workload
        jwt_delete_url = "/workloads/rspec/#{branch}/#{name}"
        delete(jwt_delete_url,
               env: token_auth_header(role: admin_user).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify workload and membership are deleted
        expect(workload_exists?(branch, name)).to be false
        expect(::RoleMembership.where(role_id: group_id, member_id: workload_id).count).to eq(0)
      end

      it 'deletes workload with API key authenticator' do
        api_key_params = valid_params.clone
        api_key_name = 'api-key-workload'
        api_key_params[:name] = api_key_name
        api_key_delete_url = "/workloads/rspec/#{branch}/#{api_key_name}"

        create_test_workload(creator_host, api_key_params)

        workload_id = "rspec:host:#{branch}/#{api_key_name}"
        role = ::Role[workload_id]

        # Verify API key exists
        expect(role.api_key).not_to be_nil

        delete(api_key_delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify complete deletion
        expect(::Role[workload_id]).to be_nil
      end

      it 'deletes workload with Azure authenticator' do
        # Setup Azure authenticator policy
        setup_authenticator_policy(azure_policy)

        # Azure authenticator data
        azure_data = {
          "subscription_id": "subscr1pt10n-1dmy-subsc-r1pt10n1d",
          "resource_group": "myResourceGroup",
          "system_assigned_identity": "0000aaaa-00aa-00aa-00aa-00000aaaaa",
          "user_assigned_identity": "test-ua-managed-identity"
        }

        # Create workload with Azure authenticator
        azure_params, response_body = create_workload_with_authenticator(
          "azure", "AzureWS1", azure_data)

        # Verify workload was created successfully
        expect(response_body['name']).to eq(name)

        # Verify membership in Azure apps group
        group_id = "rspec:group:conjur/authn-azure/AzureWS1/apps"
        workload_id = "rspec:host:#{branch}/#{name}"
        expect(::RoleMembership.where(role_id: group_id, member_id: workload_id).count).to eq(1)


        # Delete the workload
        azure_delete_url = "/workloads/rspec/#{branch}/#{name}"
        delete(azure_delete_url,
               env: token_auth_header(role: admin_user).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify workload, membership, and annotations are deleted
        expect(workload_exists?(branch, name)).to be false
        expect(::RoleMembership.where(role_id: group_id, member_id: workload_id).count).to eq(0)
        expect(::Annotation.where(resource_id: workload_id).count).to eq(0)
      end

      it 'deletes workload with GCP authenticator' do
        # Setup GCP authenticator policy
        setup_authenticator_policy(gcp_policy)

        # GCP authenticator data
        gcp_data = {
          instance_name: "web-app-01",
          project_id: "my-gcp-project",
          service_account_email: "com-np-int-h-cloudsec-cnjcloud@appspot.gserviceaccount.com",
          service_account_id: "77777777777777778"
        }

        # Create workload with GCP authenticator
        gcp_params, response_body = create_workload_with_authenticator(
          "gcp", "default", gcp_data)

        # Verify workload was created successfully
        expect(response_body['name']).to eq(name)

        # Verify membership in GCP apps group
        group_id = "rspec:group:conjur/authn-gcp/apps"
        workload_id = "rspec:host:#{branch}/#{name}"
        expect(::RoleMembership.where(role_id: group_id, member_id: workload_id).count).to eq(1)


        # Delete the workload
        gcp_delete_url = "/workloads/rspec/#{branch}/#{name}"
        delete(gcp_delete_url,
               env: token_auth_header(role: admin_user).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify workload, membership, and annotations are deleted
        expect(workload_exists?(branch, name)).to be false
        expect(::RoleMembership.where(role_id: group_id, member_id: workload_id).count).to eq(0)
        expect(::Annotation.where(resource_id: workload_id).count).to eq(0)
      end
    end

    context 'when deleting workload with annotations and role data' do
      before do
        create_test_workload
      end

      it 'deletes all annotations with the workload' do
        workload_id = "rspec:host:#{branch}/#{name}"

        # Verify annotations exist
        annotations = ::Annotation.where(resource_id: workload_id).all
        expect(annotations.count).to be > 0

        delete(delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify annotations are deleted
        expect(::Annotation.where(resource_id: workload_id).count).to eq(0)
      end

      it 'deletes restricted_to with the workload role' do
        workload_id = "rspec:host:#{branch}/#{name}"
        role = ::Role[workload_id]

        # Verify restricted_to exists
        expect(role.restricted_to).not_to be_nil
        expect(role.restricted_to.length).to be > 0

        delete(delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content

        # Verify role is deleted
        expect(::Role[workload_id]).to be_nil
      end
    end

    context 'when the URL is misconfigured' do
      it 'returns unprocessable entity for workload without branch' do
        invalid_url = "/workloads/rspec/#{name}"

        delete(invalid_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :unprocessable_entity
      end
    end

    context 'admin protection' do
      it 'allows admin to delete admin-created workload' do
        # Create workload as admin
        admin_params = valid_params.merge(name: 'admin-workload')
        create_test_workload(admin_user, admin_params)

        admin_delete_url = "/workloads/rspec/#{branch}/admin-workload"

        delete(admin_delete_url,
               env: token_auth_header(role: admin_user).merge(v2_beta_api_header))

        assert_response :no_content
        expect(workload_exists?(branch, 'admin-workload')).to be false
      end

      it 'allows non-admin to delete their own workload' do
        # Create workload as creator_host
        create_test_workload(creator_host, valid_params)

        delete(delete_url,
               env: token_auth_header(role: creator_host).merge(v2_beta_api_header))

        assert_response :no_content
        expect(workload_exists?(branch, name)).to be false
      end
    end
  end
end