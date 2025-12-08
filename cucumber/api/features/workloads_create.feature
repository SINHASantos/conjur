@api
Feature: Branches APIv2 tests - create empty

  Background:
    Given I am the super-user
    And I can POST "/policies/cucumber/policy/root" with body from file "policy_data.yml"

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
    {
        "name": "workload-api-key",
        "branch": "/",
        "type": "jenkins",
        "owner": {
          "kind": "user",
          "id": "admin"
        },
        "authn_descriptors": [
          {
            "type": "api_key",
            "data": {}
          }
        ],
        "annotations": {},
        "restricted_to": []
      }
    """
#    And I clear the "Content-Type" header
#    And I can GET "/branches/cucumber/branch1"
#    And the HTTP response status code is 200
#    And the HTTP response content type is APIv2

  @acceptance
  Scenario: As admin I can create a workload with owner
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    And I save my place in the audit log file for remote
    When I can POST "/workloads/cucumber" with body:
    """
    { "name": "workload-api-key",
      "branch": "/",
      "type": "jenkins",
      "owner": { "kind": "user", "id": "alice@data-safe1" },
      "authn_descriptors": [
        { "type": "api_key" }
      ]
    }
    """
    And the HTTP response status code is 201
    And the HTTP response content type is APIv2
    And the JSON result except "authn_descriptors,0,data,value" contains:
    """
    {
        "name": "workload-api-key",
        "branch": "/",
        "type": "jenkins",
        "owner": {
          "kind": "user",
          "id": "alice@data-safe1"
        },
        "authn_descriptors": [
          {
            "type": "api_key",
            "data": {}
          }
        ],
        "annotations": {},
        "restricted_to": []
      }
    """
#    And I clear the "Content-Type" header
#    And I can GET "/branches/cucumber/branch1"
#    And the HTTP response status code is 200
#    And the HTTP response content type is APIv2

  @acceptance
  Scenario: Admin cannot create a workload for existing host
    Given I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    And I save my place in the audit log file for remote
    When I POST "/workloads/cucumber" with body:
    """
    { "name": "myhost",
      "branch": "/data",
      "type": "jenkins",
      "authn_descriptors": [
        { "type": "api_key" }
      ]
    }
    """
    Then the HTTP response status code is 409
    And the HTTP response content type is APIv2
    And the JSON should be:
    """
    { "code": "409",
      "message": "workload \"/data/myhost\" already exists" }
    """
    Then there is an audit record matching:
    """
    <85>1 * * conjur * workload\s
    [auth@43868 user="cucumber:user:admin"]
    [subject@43868 edge=""]
    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
    [action@43868 result="failure" operation="create"]\s
    cucumber:user:admin failed to create workload  with URI path: '/workloads/cucumber' and JSON object: {"name":"myhost","branch":"/data","type":"jenkins","authn_descriptors":[{"type":"api_key"}]}: workload "/data/myhost" already exists
    """
