@api
Feature: Retrieve the role graph for a given role

  The full graph of ancestor and descendent roles for a given
  role can be retrieved throug the api

  Background:
    Given I am the super-user
    And I successfully PUT "/policies/cucumber/policy/root" with body:
    """

    - !group internal
    - !layer applications
    - !group shipping
    - !user alice

    - !grant
      role: !group internal
      member: !layer applications

    - !grant
      role: !layer applications
      member: !group shipping

    - !grant
      role: !group shipping
      member: !user alice
    """

  @smoke
  Scenario: Retrieve role graph
    Given I save my place in the audit log file for remote
    When I successfully GET "/roles/cucumber/group/internal?graph"
    Then the JSON should be:
        """
        [
          {
            "parent": "cucumber:group:internal",
            "child": "cucumber:layer:applications"
          },
          {
            "parent": "cucumber:group:internal",
            "child": "cucumber:user:admin"
          },
          {
            "parent": "cucumber:group:shipping",
            "child": "cucumber:user:admin"
          },
          {
            "parent": "cucumber:group:shipping",
            "child": "cucumber:user:alice"
          },
          {
            "parent": "cucumber:layer:applications",
            "child": "cucumber:group:shipping"
          },
          {
            "parent": "cucumber:layer:applications",
            "child": "cucumber:user:admin"
          },
          {
            "parent": "cucumber:user:alice",
            "child": "cucumber:user:admin"
          }
        ]
        """
    And there is an audit record matching:
    """
      <86>1 * * conjur * role
      [auth@43868 user="cucumber:user:admin"]
      [subject@43868 role="cucumber:group:internal"]
      [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
      [action@43868 result="success" operation="get"]
      cucumber:user:admin successfully fetched role graph.
    """

  @smoke @negative
  Scenario: Retrieving graph of non-existent group returns an error
    Given I save my place in the audit log file for remote
    When I GET "/roles/cucumber/group/non-existent?graph"
    Then the HTTP response status code is 404
    And there is an audit record matching:
    """
      <84>1 * * conjur * role
      [auth@43868 user="cucumber:user:admin"]
      [subject@43868 role="cucumber:group:non-existent"]
      [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
      [action@43868 result="failure" operation="get"]
      cucumber:user:admin failed to fetch role graph: Group 'non-existent' not found in account 'cucumber'
    """