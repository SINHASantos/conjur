# frozen_string_literal: true

require 'spec_helper'

# This spec is a compile-time safety net for the QueryParamValidation concern.
#
# == Why this exists ==
#
# The QueryParamValidation concern (app/controllers/concerns/query_param_validation.rb)
# enforces query parameter allowlists on every controller action that inherits
# from RestController. When an action receives a request, check_query_params
# (a before_action) looks up the allowlist for that action and:
#
#   - raises 400 if no allowlist is declared (strict failure)
#   - raises 400 if an unknown param is present and strict: true (new endpoints)
#   - logs a warning if an unknown param is present and strict: false (legacy v1)
#
# The problem: that enforcement is runtime-only. A developer could add a new
# controller action, forget to call validate_query_params, and not discover the
# error until the endpoint is actually hit in production.
#
# == What this spec does ==
#
# It enumerates every action registered in the Rails router, checks whether the
# responsible controller includes QueryParamValidation, and asserts that the
# action has a declared allowlist. If the allowlist is missing, the spec fails
# with a clear message identifying the exact controller#action that needs a
# validate_query_params declaration.
#
# This turns a runtime 400 into a CI failure, making it impossible to ship a
# new endpoint that bypasses query parameter validation.
#
# == Adding a new endpoint ==
#
# If this spec fails after you add a new endpoint, fix it by adding:
#
#   validate_query_params :your_action, %i[param1 param2]          # strict (new endpoints)
#   validate_query_params :your_action, %i[param1 param2], strict: false  # permissive (legacy)
#
# to your controller class body. See the existing controllers for examples.

RSpec.describe('QueryParamValidation completeness') do
  # Build a set of (controller_class, action_name) pairs from the live Rails
  # router. We skip:
  #   - Routes with no controller or action (e.g. mounted engines, redirects)
  #   - Controllers that don't include QueryParamValidation (they opt out of
  #     the validation system entirely, e.g. AuthenticateController)
  let(:routed_validated_actions) do
    Rails.application.routes.routes.filter_map do |route|
      controller_str = route.defaults[:controller]
      action_str     = route.defaults[:action]

      next unless controller_str && action_str

      # Rails stores controller names as snake_case strings like "resources"
      # or "secrets_batch". Constantize to get the class.
      controller_class = begin
        "#{controller_str}_controller".camelize.constantize
      rescue NameError
        next
      end

      # Only check controllers that have opted in to QueryParamValidation.
      next unless controller_class.ancestors.include?(QueryParamValidation)

      # RestController and V2RestController are base classes; they have no
      # direct routed actions of their own.
      next if controller_class == RestController
      next if controller_class == V2RestController

      [controller_class, action_str.to_sym]
    end.uniq
  end

  it 'every routed action in a QueryParamValidation controller has a declared allowlist' do
    missing = routed_validated_actions.reject do |controller_class, action|
      controller_class._query_param_allowlists.key?(action)
    end

    expect(missing).to be_empty,
      "The following controller actions have no validate_query_params declaration.\n" \
      "Add one to each controller to prevent query parameter validation from being\n" \
      "silently bypassed. Use strict: true (default) for new endpoints, or\n" \
      "strict: false for legacy v1 endpoints that should only warn on unknown params.\n\n" \
      "Missing declarations:\n" +
      missing.map { |klass, action| "  #{klass}##{action}" }.join("\n")
  end
end
