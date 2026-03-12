@api
Feature: List direct members of a role

  If a role A is granted to a role B, then role A is said to have role B as a
  member.

  Unlike role memberships, role members are not expanded recursively.

  Background:
    Given I create a new user "bob"
    And I create a new user "alice"
    And I am the super-user

  @smoke
  Scenario: Initial roles members is just the initial role admin.

    At the time a new role ("alice") is created, the role is granted
    with admin option to the "creating" role ("admin"). Thus the initial
    members of role "alice" is the set containing only role "admin".

    When I successfully GET "/roles/cucumber/user/alice"
    Then the JSON at "members" should be:
    """
    [
      {
        "admin_option": true,
        "member": "cucumber:user:admin",
        "ownership": true,
        "role": "cucumber:user:alice"
      }
    ]
    """

  @smoke
  Scenario: New member roles appear in the role list.

    Granting a role ("alice") to a new role ("bob") results in
    "bob" appearing in the set of members of "alice".

    Given I grant user "alice" to user "bob"
    And I save my place in the audit log file for remote
    When I successfully GET "/roles/cucumber/user/alice"
    Then the JSON at "members" should be:
    """
    [
      {
        "admin_option": true,
        "member": "cucumber:user:admin",
        "ownership": true,
        "role": "cucumber:user:alice"
      },
      {
        "admin_option": false,
        "member": "cucumber:user:bob",
        "ownership": false,
        "role": "cucumber:user:alice"
      }
    ]
    """
    And there is an audit record matching:
    """
      <86>1 * * conjur * role
      [auth@43868 user="cucumber:user:admin"]
      [subject@43868 role="cucumber:user:alice"]
      [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
      [action@43868 result="success" operation="get"]
      cucumber:user:admin successfully fetched role details.
    """

  @smoke @negative
  Scenario: Retrieving non existent role returns an error
    Given I save my place in the audit log file for remote
    When I GET "/roles/cucumber/user/non-existent"
    Then the HTTP response status code is 404
    And there is an audit record matching:
    """
      <84>1 * * conjur * role
      [auth@43868 user="cucumber:user:admin"]
      [subject@43868 role="cucumber:user:non-existent"]
      [client@43868 ip="\d+\.\d+\.\d+\.\d+"]
      [action@43868 result="failure" operation="get"]
      cucumber:user:admin failed to fetch role details: User 'non-existent' not found in account 'cucumber'
    """
