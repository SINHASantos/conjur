@policy
Feature: Policies with public_keys attribute are accepted but keys are not stored.

  The public_keys endpoint has been removed, policies that
  include the public_keys attribute on !user records should still load
  successfully to maintain backward compatibility with existing policies
  and LDAP sync, but no public_key resources should be created.

  @smoke
  Scenario: A policy with public_keys loads without error and no public_key resources are created.
    Given I load a policy:
    """
    - !user
      id: pk-test-user
      public_keys:
      - ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDtest pk-test-user@laptop
    """
    Then user "pk-test-user" exists
    And public_key "user/pk-test-user/pk-test-user@laptop" does not exist

