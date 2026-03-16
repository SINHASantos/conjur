@api
Feature: Workloads APIv2 tests - create empty

  Background:
    Given I am the super-user
    And I can POST "/policies/cucumber/policy/root" with body from file "policy_workloads.yml"

  @acceptance
  Scenario: As admin I can create a workload with minimal set of data
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    And I save my place in the audit log file for remote
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "workload-api-key",
      "branch": "/",
      "type": "jenkins",
      "authn_descriptors": [
        { "type": "api_key" } ] }
    """
    Then there is an audit record matching:
    """
    <85>1 * * conjur * workload\s
    [auth@43868 user="cucumber:user:admin"]
    [subject@43868 edge=""]
    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
    [action@43868 result="success" operation="create"]\s
    cucumber:user:admin successfully created workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"workload-api-key","branch":"/","type":"jenkins","authn_descriptors":[{"type":"api_key"}]}
    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,0,data,value" contains:
    """
    { "name": "workload-api-key",
      "branch": "/",
      "type": "jenkins",
      "owner": { "kind": "user", "id": "admin" },
      "authn_descriptors": [
        { "type": "api_key", "data": {} } ],
        "annotations": {} }
    """

  @acceptance
  Scenario: As admin I can create a workload with owner
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "workload-api-key",
      "branch": "/",
      "type": "jenkins",
      "owner": { "kind": "user", "id": "alice@data-safe1" },
      "authn_descriptors": [
        { "type": "api_key" } ] }
    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,0,data,value" contains:
    """
    { "name": "workload-api-key",
      "branch": "/",
      "type": "jenkins",
      "owner": { "kind": "user", "id": "alice@data-safe1" },
        "authn_descriptors": [
          { "type": "api_key", "data": {} } ],
      "annotations": {} }
    """

  @acceptance
  Scenario: Admin cannot create a workload for existing host
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    When I POST "/workloads/cucumber" with body:
    """
    { "name": "myhost",
      "branch": "/data",
      "type": "jenkins",
      "authn_descriptors": [
        { "type": "api_key" } ] }
    """
    Then the HTTP response status code is 409
    And the HTTP response content type is APIv2
    And the JSON should be:
    """
    { "code": "409",
      "message": "workload \"/data/myhost\" already exists" }
    """

  @acceptance
  Scenario: As admin I can create a workload with gcp type
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "new-workload",
      "branch": "data/work",
      "authn_descriptors": [
        { "type": "gcp",
          "service_id": "default",
          "data": { "instance_name": "web-app-01",
          "project_id": "my-gcp-project",
          "service_account_email": "com-np-int-h-cloudsec-cnjcloud@appspot.gserviceaccount.com",
          "service_account_id": "77777777777777778"}}],
      "annotations": { "app": "web", "env": "test"}}
    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,0,data,value" contains:
    """
    { "name": "new-workload",
      "branch": "data/work",
      "type": "other",
      "owner": { "kind": "policy", "id": "data/work" },
      "authn_descriptors": [{
        "type": "gcp",
        "service_id": "default",
        "data": { "instance_name": "web-app-01",
        "project_id": "my-gcp-project",
        "service_account_email": "com-np-int-h-cloudsec-cnjcloud@appspot.gserviceaccount.com",
        "service_account_id": "77777777777777778"}}],
      "annotations": { "app": "web", "env": "test"}}
    """

  @acceptance
  Scenario: As admin I can create a workload with cert type
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    When I can POST "/workloads/cucumber" with body:
    """
    { "name":"new-workload",
      "branch":"data/work",
      "authn_descriptors":[{
        "type":"cert",
        "service_id":"x509-cert-authn",
        "data":{"cn":"data/cert-apps/secretAppD",
        "san_uri":["spiffe://example.com/ns/prod/sa/secret-app-d"],
        "san_dns":["tests.example.com"],
        "san_ip":["127.0.0.1","127.0.0.2"]}}],
        "annotations":{"app":"web","env":"test"} }
    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,0,data,value" contains:
    """
    { "name":"new-workload",
      "branch":"data/work",
      "owner": { "id": "data/work", "kind": "policy"},
      "type": "other",
      "authn_descriptors":[{
        "type":"cert",
        "service_id":"x509-cert-authn",
        "data":{"cn":"data/cert-apps/secretAppD",
        "san_uri":["spiffe://example.com/ns/prod/sa/secret-app-d"],
        "san_dns":["tests.example.com"],
        "san_ip":["127.0.0.1","127.0.0.2"]}}],
        "annotations":{"app":"web","env":"test"} }
    """

  @acceptance
  Scenario: As admin I can create a workload with cert type
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    When I can POST "/workloads/cucumber" with body:
    """
    { "name":"new-workload",
      "branch":"data/work",
      "authn_descriptors":[
        { "type": "api_key" },
        { "type":"cert",
          "service_id":"x509-cert-authn",
          "data":{"cn":"data/cert-apps/secretAppD",
          "san_uri":["spiffe://example.com/ns/prod/sa/secret-app-d"],
          "san_dns":["tests.example.com"],
          "san_ip":["127.0.0.1","127.0.0.2"]}}],
          "annotations":{"app":"web","env":"test"} }
    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,1,data,value" contains:
    """
    { "name": "new-workload",
        "branch": "data/work",
        "type": "other",
        "owner": { "kind": "policy", "id": "data/work" },
        "annotations": { "app": "web", "env": "test" },
        "authn_descriptors": [
          { "type": "cert",
            "service_id": "x509-cert-authn",
             "data": {
              "cn": "data/cert-apps/secretAppD",
               "san_dns": [ "tests.example.com" ],
                    "san_ip": [ "127.0.0.1", "127.0.0.2" ],
                    "san_uri": [ "spiffe://example.com/ns/prod/sa/secret-app-d" ] } },
                { "type": "api_key", "data": {} } ] }
    """


  @acceptance
  Scenario: As admin I cannot create a workload with more than 2 authn descriptors
    Given I set the Accept header to APIv2
    And I save my place in the audit log file for remote
    And I set the "Content-Type" header to "application/json"
    When I POST "/workloads/cucumber" with body:
    """
    { "name":"new-workload",
      "branch":"data/work",
      "authn_descriptors":[
        { "type": "api_key" },
        { "type": "api_key" },
        { "type":"cert",
          "service_id":"x509-cert-authn",
          "data":{"cn":"data/cert-apps/secretAppD",
          "san_uri":["spiffe://example.com/ns/prod/sa/secret-app-d"],
          "san_dns":["tests.example.com"],
          "san_ip":["127.0.0.1","127.0.0.2"]}}],
          "annotations":{"app":"web","env":"test"} }
    """
    Then the HTTP response status code is 422
    And the HTTP response content type is APIv2
    And the JSON should be:
    """
    { "code": "422",
      "message": "Authn descriptors 'authn_descriptors' must be an array with one or two descriptors. Each authn type (except 'jwt', 'certificate', and 'azure') can appear at most once." }
    """
    Then there is an audit record matching:
    """
    <85>1 * * conjur * workload\s
    [auth@43868 user="cucumber:user:admin"]
    [subject@43868 edge=""]
    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
    [action@43868 result="failure" operation="create"]\s
    cucumber:user:admin failed to create workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"new-workload","branch":"data/work","authn_descriptors":[{"type":"api_key"},{"type":"api_key"},{"type":"cert","service_id":"x509-cert-authn","data":{"cn":"data/cert-apps/secretAppD","san_uri":["spiffe://example.com/ns/prod/sa/secret-app-d"],"san_dns":["tests.example.com"],"san_ip":["127.0.0.1","127.0.0.2"]}}],"annotations":{"app":"web","env":"test"}}: Authn descriptors 'authn_descriptors' must be an array with one or two descriptors. Each authn type \(except 'jwt', 'certificate', and 'azure'\) can appear at most once.
    """

  @acceptance
  Scenario: As admin I cannot create a workload with more than 1 chosen authn descriptors
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    When I POST "/workloads/cucumber" with body:
    """
    { "name":"new-workload",
      "branch":"data/work",
      "authn_descriptors":[
        { "type": "api_key" },
        { "type": "api_key" }] }
    """
    Then the HTTP response status code is 422
    And the HTTP response content type is APIv2
    And the JSON should be:
    """
    { "code": "422",
      "message": "Authn descriptors 'authn_descriptors' must be an array with one or two descriptors. Each authn type (except 'jwt', 'certificate', and 'azure') can appear at most once." }
    """
