Feature: A permitted Conjur host can login with a valid application identity
  that is defined in annotations

  Scenario: Authenticate as a Pod.
    Given I login to pod matching "app=inventory-pod" to authn-k8s as "test-app-pod" with prefix "host/some-policy"
    Then I can authenticate pod matching "pod/inventory-pod" with authn-k8s as "test-app-pod" with prefix "host/some-policy"

  Scenario: Authenticate as a Namespace.
    Given I can login to pod matching "app=inventory-pod" to authn-k8s as "test-app-namespace" with prefix "host/some-policy"
    Then I can authenticate pod matching "pod/inventory-pod" with authn-k8s as "test-app-namespace" with prefix "host/some-policy"

  Scenario: Authenticate as a ServiceAccount.
    Given I can login to pod matching "app=inventory-pod" to authn-k8s as "test-app-service-account" with prefix "host/some-policy"
    Then I can authenticate pod matching "pod/inventory-pod" with authn-k8s as "test-app-service-account" with prefix "host/some-policy"

  Scenario: Authenticate as a Deployment.
    Given I can login to pod matching "app=inventory-deployment" to authn-k8s as "test-app-deployment" with prefix "host/some-policy"
    Then I can authenticate pod matching "pod/inventory-deployment" with authn-k8s as "test-app-deployment" with prefix "host/some-policy"

  Scenario: Authenticate as a StatefulSet.
    Given I can login to pod matching "app=inventory-stateful" to authn-k8s as "test-app-stateful-set" with prefix "host/some-policy"
    Then I can authenticate pod matching "pod/inventory-stateful" with authn-k8s as "test-app-stateful-set" with prefix "host/some-policy"

  @k8s_skip
  Scenario: Authenticate as a DeploymentConfig.
    Given I can login to pod matching "app=inventory-deployment-cfg" to authn-k8s as "test-app-deployment-config" with prefix "host/some-policy"
    Then I can authenticate pod matching "pod/inventory-deployment-cfg" with authn-k8s as "test-app-deployment-config" with prefix "host/some-policy"
