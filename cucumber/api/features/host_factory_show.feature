@api
@logged-in
Feature: Display information about a host factory.

  Background:
    Given I create a new user "alice"
    And I create a host factory for layer "the-layer"
    And I permit user "alice" to "read" it
    And I login as "alice"

  @acceptance
  Scenario: When a host factory is retrieved specifically, the response displays
    set of normal resource fields plus the list of layers and token hashes.

    Given I create a host factory token
    When I successfully GET "/resources/cucumber/host_factory/the-layer-factory"
    Then the host factory JSON should be:
    """
    {
      "annotations" : [ ],
      "id": "cucumber:host_factory:the-layer-factory",
      "owner": "cucumber:user:admin",
      "permissions": [ 
        {
          "privilege": "read",
          "role": "cucumber:user:alice"
        }
      ],
      "layers": [
        "cucumber:layer:the-layer"
      ],
      "tokens": [
        {
          "cidr": [],
          "expiration": "@host_factory_token_expiration@"
        }
      ]
    }
    """

  @acceptance
  Scenario: When a host factory is retrieved as a member of a list of resources,
    the response displays the normal resource fields plus the list of layers and
    token hashes.

    Given I create a host factory token
    When I successfully GET "/resources/cucumber"
    Then the response is an array that contains the resource "cucumber:host_factory:the-layer-factory"
    And the host factory JSON should be:
    """
    {
      "annotations" : [ ],
      "id": "cucumber:host_factory:the-layer-factory",
      "owner": "cucumber:user:admin",
      "permissions": [ 
        {
          "privilege": "read",
          "role": "cucumber:user:alice"
        }
      ],
      "layers": [
        "cucumber:layer:the-layer"
      ],
      "tokens": [
        {
          "cidr": [],
          "expiration": "@host_factory_token_expiration@"
        }
      ]
    }
    """
