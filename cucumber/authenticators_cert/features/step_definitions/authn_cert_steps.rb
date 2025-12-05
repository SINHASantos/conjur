require 'cucumber/authenticators_cert/features/support/authn_cert_helper'

Given(/^Certificate authentication is enabled$/) do
  ENV['CONJUR_FEATURE_CERTIFICATE_AUTHENTICATION_ENABLED'] = 'true'
end

Given(/^I create a CA certificate$/) do
  ca_cert, ca_key = generate_ca_certificate(common_name: 'CN=Test CA')
  @scenario_context.add(:ca_cert, ca_cert)
  @scenario_context.add(:ca_key, ca_key)
  @scenario_context.add(:ca_cert_string, ca_cert.to_pem)
  @scenario_context.add(:spiffe_trust_domain, AuthnCertHelper::TRUST_DOMAIN)
end

Given(/^I generate a client certificate signed by the CA$/) do
  client_cert, client_key = generate_client_certificate(
    ca_cert: @scenario_context.get(:ca_cert),
    ca_key: @scenario_context.get(:ca_key),
    common_name: 'CN=Test Client'
  )
  @scenario_context.add(:client_cert, client_cert)
  @scenario_context.add(:client_key, client_key)
end

Given(/^I generate a client certificate signed by a different CA$/) do
  ca_cert, ca_key = generate_ca_certificate(common_name: 'CN=Test CA 2')
  client_cert, client_key = generate_client_certificate(
    ca_cert: ca_cert,
    ca_key: ca_key,
    common_name: 'CN=Test Client 2'
  )
  @scenario_context.add(:client_cert, client_cert)
  @scenario_context.add(:client_key, client_key)
end

When(/^I authenticate via Certificate with service-id "([^"]*)" and role id "([^"]*)"$/) do |service_id, role_id|
  authenticate_with_certificate(
    service_id: service_id,
    account: AuthnCertHelper::ACCOUNT,
    client_cert: @scenario_context.get(:client_cert),
    client_key: @scenario_context.get(:client_key),
    role_id: role_id
  )
end

When(/^I authenticate via Certificate with service-id "([^"]*)"$/) do |service_id|
  authenticate_with_certificate(
    service_id: service_id,
    account: AuthnCertHelper::ACCOUNT,
    client_cert: @scenario_context.get(:client_cert),
    client_key: @scenario_context.get(:client_key)
  )
end
