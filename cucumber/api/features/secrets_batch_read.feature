@api
Feature: Secrets APIv2 tests - batch read

  Background:
    Given I am the super-user
    And I can POST "/policies/cucumber/policy/root" with body:
    """
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
    """
    And I can POST "/secrets/cucumber/variable/data/var1" with body:
    """
      secret_value1
    """
    And I can POST "/secrets/cucumber/variable/data/var2" with body:
    """
      secret_value2
    """
    And I can POST "/secrets/cucumber/variable/data/var_without_exec_permission" with body:
    """
      secret_value3
    """
    And I can POST "/secrets/cucumber/variable/data/var_without_any_permission" with body:
    """
      secret_value4
    """

  @acceptance
  Scenario: As alice I can read secrets in batch
    Given I login as "alice"
    And I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    And I save my place in the audit log file for remote
    When I can POST "/secrets/cucumber/values" with body:
    """
    { "ids":["data/var1",
            "data/var2",
            "data/var_secret_not_set",
            "data/var_without_exec_permission",
            "data/var_without_any_permission",
            "data/var_secret_not_exist"] }
    """
    Then there is an audit record matching:
    """
    <85>1 * * conjur * fetch-secrets\s
    [auth@43868 user="cucumber:user:alice"]
    [subject@43868 edge=""]
    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
    [action@43868 result="success" operation="fetch"]\s
  cucumber:user:alice successfully fetched fetch-secrets  with URI path: '/secrets/cucumber/values' and JSON object: {"ids":["data/var1","data/var2","data/var_secret_not_set","data/var_without_exec_permission","data/var_without_any_permission","data/var_secret_not_exist"]}
    """
    And the HTTP response status code is 207
    And the HTTP response content type is APIv2
    And the JSON should be:
    """
      {
        "secrets": [
          {
            "expires_at": null,
            "id": "data/var1",
            "status": 200,
            "value": "  secret_value1"
          },
          {
            "expires_at": null,
            "id": "data/var2",
            "status": 200,
            "value": "  secret_value2"
          },
          {
            "id": "data/var_secret_not_set",
            "status": 204,
            "value": ""
          },
          {
            "description": "Forbidden",
            "id": "data/var_without_exec_permission",
            "status": 403
          },
          {
            "description": "Variable data/var_without_any_permission not found",
            "id": "data/var_without_any_permission",
            "status": 404
          },
          {
            "description": "Variable data/var_secret_not_exist not found",
            "id": "data/var_secret_not_exist",
            "status": 404
          }
        ]
       }
    """

  @acceptance
  Scenario: As alice I cannot read secrets in batch without ids parameter
    Given I login as "alice"
    And I set the Accept header to APIv2
    And I set the "Content-Type" header to "application/json"
    And I save my place in the audit log file for remote
    When I POST "/secrets/cucumber/values" with body:
    """
    { "identifiers":["data/var1",
            "data/var2",
            "data/var_secret_not_set",
            "data/var_without_exec_permission",
            "data/var_without_any_permission",
            "data/var_secret_not_exist"] }
    """
    Then there is an audit record matching:
    """
    <85>1 * * conjur * fetch-secrets\s
    [auth@43868 user="cucumber:user:alice"]
    [subject@43868 edge=""]
    [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
    [action@43868 result="failure" operation="fetch"]\s
    cucumber:user:alice failed to fetch fetch-secrets  with URI path: '/secrets/cucumber/values' and JSON object: {"identifiers":["data/var1","data/var2","data/var_secret_not_set","data/var_without_exec_permission","data/var_without_any_permission","data/var_secret_not_exist"]}: CONJ00190W Missing required parameter: ids
    """
    And the HTTP response status code is 422
    And the HTTP response content type is APIv2
    And the JSON should be:
    """
      {
        "code": "422",
        "message": "CONJ00190W Missing required parameter: ids"
      }
    """
