@authenticators_cert
Feature: Certificate Authenticator
  Background:
    Given Certificate authentication is enabled
    And I create a CA certificate
    And I generate a client certificate signed by the CA
    And I load a policy:
    """
      - !policy
        id: conjur/authn-cert/my-service
        body:
          - !webservice
          - !variable ca-cert
          - !group users
          - !permit
            role: !group users
            privilege: [ read, authenticate ]
            resource: !webservice

      - !user alice
      - !grant
        role: !group conjur/authn-cert/my-service/users
        member: !user alice
    """
    And I set the following conjur variables:
      | variable_id                          | context_variable | default_value |
      | conjur/authn-cert/my-service/ca-cert | ca_cert_string   |               |
    

    @smoke
    Scenario: A valid client certificate can be exchanged for a Conjur access token
      Given I have a "variable" resource called "test-variable"
      And I permit user "alice" to "execute" it
      And I add the secret value "test-secret" to the resource "cucumber:variable:test-variable"
      And I save my place in the audit log file
      And I authenticate via Certificate with service-id "my-service" and role id "alice"
      Then user "alice" has been authorized by Conjur
      And I successfully GET "/secrets/cucumber/variable/test-variable" with authorized user
      And The following appears in the audit log after my savepoint:
      """
      cucumber:user:alice successfully authenticated with authenticator authn-cert service cucumber:webservice:conjur/authn-cert/my-service
      """
