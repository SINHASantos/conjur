@api
Feature: List roles which have a specific permission on a resource

  The `permitted_roles` query parameter can be used to list all the roles which have
  a specified privilege on some resource.

  Background:
    Given I am a user named "alice"
    And I create a new resource

  @smoke
  Scenario: Initial permitted roles is just the owner, and the roles which have the owner.
    When I successfully GET "/resources/cucumber/:resource_kind/:resource_id" with parameters:
    """
    permitted_roles: true
    privilege: fry
    """
    Then the JSON should be:
    """
    [
      "cucumber:user:admin",
      "cucumber:user:alice"
    ]
    """

  @smoke
  Scenario: An additional user with the specified privilege is included in the list
    Given I create a new user "bob"
    And I save my place in the audit log file for remote
    And I permit user "bob" to "fry" it
    When I successfully GET "/resources/cucumber/:resource_kind/:resource_id" with parameters:
    """
    permitted_roles: true
    privilege: fry
    """
    Then the JSON should be:
    """
    [
      "cucumber:user:admin",
      "cucumber:user:alice",
      "cucumber:user:bob"
    ]
    """
    And there is an audit record matching:
    """
      <86>1 * * conjur * cucumber:variable:*
      [auth@43868 user="cucumber:user:alice"]
      [subject@43868 resource="cucumber:variable:*" privilege="fry"]
      [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
      [action@43868 result="success" operation="get"]
      cucumber:user:alice successfully fetched permitted roles of cucumber:variable:*.
    """

  @smoke @negative
  Scenario: An additional user with the specified privilege is included in the list
    Given I save my place in the audit log file for remote
    When I GET "/resources/cucumber/variable/non-existent" with parameters:
    """
    permitted_roles: true
    privilege: fry
    """
    Then the HTTP response status code is 404
    And there is an audit record matching:
    """
      <84>1 * * conjur * cucumber:variable:non-existent
      [auth@43868 user="cucumber:user:alice"]
      [subject@43868 resource="cucumber:variable:non-existent" privilege="fry"]
      [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
      [action@43868 result="failure" operation="get"]
      cucumber:user:alice failed to fetch permitted roles of cucumber:variable:non-existent: Variable 'non-existent' not found in account 'cucumber'
    """

  @acceptance
  Scenario: An additional user with an unrelated privilege is not included in the list
    Given I create a new user "bob"
    And I permit user "bob" to "freeze" it
    When I successfully GET "/resources/cucumber/:resource_kind/:resource_id" with parameters:
    """
    permitted_roles: true
    privilege: fry
    """
    Then the JSON should be:
    """
    [
      "cucumber:user:admin",
      "cucumber:user:alice"
    ]
    """

  @smoke
  Scenario: An additional owner role is included in the list
    Given I create a new user "bob"
    And I grant my role to user "bob"
    When I successfully GET "/resources/cucumber/:resource_kind/:resource_id" with parameters:
    """
    permitted_roles: true
    privilege: fry
    """
    Then the JSON should be:
    """
    [
      "cucumber:user:admin",
      "cucumber:user:alice",
      "cucumber:user:bob"
    ]
    """
