@api
Feature: Workloads APIv2 tests - read one

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
        { "type": "api_key" }
      ]
    }
    """
#    Then there is an audit record matching:
#    """
#    <85>1 * * conjur * workload\s
#    [auth@43868 user="cucumber:user:admin"]
#    [subject@43868 edge=""]
#    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
#    [action@43868 result="success" operation="create"]\s
#    cucumber:user:admin successfully created workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"workload-api-key","branch":"/","type":"jenkins","authn_descriptors":[{"type":"api_key"}]}
#    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    Then I can GET "/workloads/cucumber/workload-api-key"
    And the HTTP response status code is 200
    And the HTTP response content type is APIv2
#    And the JSON result except "authn_descriptors,0,data,value" contains:
#    And the JSON result except "authn_descriptors,0,data,value" contains:
    And the JSON should be:
    """
    { "name": "workload-api-key",
      "branch": "/",
      "type": "jenkins",
      "owner": { "kind": "user", "id": "admin" },
      "authn_descriptors": [ { "type": "api_key" } ],
      "annotations": {} }
    """

  @acceptance
  Scenario: As admin I can create a workload iam
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
#    And I save my place in the audit log file for remote
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "new-workload",
      "branch": "data/work",
      "authn_descriptors": [{
        "type": "aws",
        "service_id": "authorized-service",
        "data": {
          "account": "123456789012",
          "role": "my-role-name"}}],
      "annotations": { "app": "web", "env": "test" } }
    """
#  "restricted_to": ["192.168.1.0/24", "192.163.1.0/24"] }
#    Then there is an audit record matching:
#    """
#    <85>1 * * conjur * workload\s
#    [auth@43868 user="cucumber:user:admin"]
#    [subject@43868 edge=""]
#    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
#    [action@43868 result="success" operation="create"]\s
#    cucumber:user:admin successfully created workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"workload-api-key","branch":"/","type":"jenkins","authn_descriptors":[{"type":"api_key"}]}
#    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    Then I can GET "/workloads/cucumber/data/work/new-workload"
    And the HTTP response status code is 200
    And the HTTP response content type is APIv2
#    And the JSON result except "authn_descriptors,0,data,value" contains:
    And the JSON should be:
    """
    { "name": "new-workload",
      "branch": "data/work",
      "type": "other",
      "owner": { "kind":"policy","id":"data/work" },
      "authn_descriptors": [{
        "type": "aws",
        "service_id": "authorized-service",
        "data": { "account": "123456789012", "role": "my-role-name"}}],
      "annotations": { "app": "web", "env": "test" } }
    """
#  "restricted_to": ["192.168.1.0/24", "192.163.1.0/24"] }

  @acceptance
  Scenario: As admin I can create a workload jwt
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
#    And I save my place in the audit log file for remote
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "new-workload",
      "branch": "data/work",
      "authn_descriptors": [{
        "type": "jwt",
        "service_id": "jwtservice",
        "data": { "sub/sub1": "system:serviceaccount:jwttoken"}}],
      "annotations": {"app": "web", "env": "test"},
      "type": "jenkins",
      "owner": { "id": "data/creator-host", "kind": "host" }}
    """
#  "restricted_to": ["192.168.1.0/24", "192.163.1.0/24"],

#    Then there is an audit record matching:
#    """
#    <85>1 * * conjur * workload\s
#    [auth@43868 user="cucumber:user:admin"]
#    [subject@43868 edge=""]
#    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
#    [action@43868 result="success" operation="create"]\s
#    cucumber:user:admin successfully created workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"workload-api-key","branch":"/","type":"jenkins","authn_descriptors":[{"type":"api_key"}]}
#    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    Then I can GET "/workloads/cucumber/data/work/new-workload"
    And the HTTP response status code is 200
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,0,data,value" contains:
#  "owner": { "kind": "host", "id": "data/creator-host"},
    """
    { "name": "new-workload",
      "branch": "data/work",
      "authn_descriptors": [{
        "type": "jwt",
        "service_id": "jwtservice",
        "data": { "sub/sub1": "system:serviceaccount:jwttoken"}}],
      "annotations": {"app": "web", "env": "test"},
      "type": "jenkins",
      "owner": { "id": "data/creator-host", "kind": "host" }}
    """

  @acceptance
  Scenario: As admin I can create a workload jwt
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
#    And I save my place in the audit log file for remote
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "new-workload",
      "branch": "data/work",
      "authn_descriptors": [{"type": "api_key"}],
      "annotations": {"app": "web", "env": "test"},
      "type": "kubernetes"}
    """
#      "restricted_to": ["192.168.1.0/24", "192.163.1.0/24"],

#    Then there is an audit record matching:
#    """
#    <85>1 * * conjur * workload\s
#    [auth@43868 user="cucumber:user:admin"]
#    [subject@43868 edge=""]
#    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
#    [action@43868 result="success" operation="create"]\s
#    cucumber:user:admin successfully created workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"workload-api-key","branch":"/","type":"jenkins","authn_descriptors":[{"type":"api_key"}]}
#    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    Then I can GET "/workloads/cucumber/data/work/new-workload"
    And the HTTP response status code is 200
    And the HTTP response content type is APIv2
#    And the JSON result except "authn_descriptors,0,data,value" contains:
#  "owner": { "kind": "host", "id": "data/creator-host"},
    And the JSON should be:
    """
      { "name": "new-workload",
        "branch": "data/work",
        "owner": { "id": "data/work", "kind": "policy" },
        "subtype": "openshift",
        "type": "kubernetes",
        "annotations": { "app": "web", "env": "test" },
        "authn_descriptors": [ { "type": "api_key" }]}
    """
