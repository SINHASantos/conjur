# frozen_string_literal: true

# QueryParamValidation provides per-controller or per-action query parameter allowlists.
#
# Two modes are supported:
#
#   - strict (default for V2 endpoints)
#     Any unknown query parameter raises Errors::Conjur::UnexpectedParameter
#     (rendered as 422 via ApplicationController handling). Controllers opt in by calling:
#   - permissive (default for V1 endpoints, tied to CONJUR_FEATURE_STRICT_PARAMS_ENABLED feature flag)
#     Any unknown query parameter logs a CONJ00545W warning but the
#     request continues. Controllers opt in by calling:
#     validate_query_params [allowed param names]
#
# Controllers opt in by calling:
#     - per-controller:
#         validate_query_params [allowed param names]
#
#     - per-action (takes priority over controller default):
#         validate_query_params_for_action :action_name, %i[allowed param names]
#
# An empty list means no query parameters are supported.
#
# Actions without an action-specific declaration and without a controller default
# are treated as strict-unknown: an error is raised to force developers to
# explicitly declare query params for every new endpoint.

module QueryParamValidation
  extend ActiveSupport::Concern

  included do
    before_action :check_query_params
  end

  module ClassMethods
    # @param allowed [Array<Symbol>] default allowlist for actions without a
    # explicit per-action declaration.
    def validate_query_params(allowed)
      @_default_query_param_allowlist = {
        allowed: Array(allowed).map(&:to_sym),
        strict: strict_query_params?
      }
    end

    # @param action [Symbol] the controller action this allowlist applies to
    # @param allowed [Array<Symbol>] permitted query parameter names
    def validate_query_params_for_action(action, allowed)
      _query_param_allowlists[action.to_sym] = {
        allowed: allowed.map(&:to_sym),
        strict: strict_query_params?
      }
    end

    def strict_query_params?
      return true if v2_rest_controller?

      Rails.application.config.respond_to?(:feature_flags) &&
        Rails.application.config.feature_flags.enabled?(:strict_params)
    end

    def v2_rest_controller?
      defined?(V2RestController) && self <= V2RestController
    end

    def _query_param_allowlists
      @_query_param_allowlists ||= {}
    end

    def _default_query_param_allowlist
      @_default_query_param_allowlist
    end

    def query_param_allowlist_for(action_name)
      _query_param_allowlists[action_name.to_sym] || _default_query_param_allowlist
    end
  end

  private

  def check_query_params
    action = action_name.to_sym
    allowlist_entry = self.class.query_param_allowlist_for(action)

    if allowlist_entry.nil?
      # No allowlist declared and no controller default — this endpoint is not
      # yet annotated. New endpoints must either declare their params directly or
      # set a default.
      raise Errors::Conjur::UnexpectedParameter,
            "(no allowlist declared for #{controller_name}##{action})"
    end

    unknown = unknown_query_params(allowlist_entry[:allowed])
    return if unknown.empty?

    if allowlist_entry[:strict]
      raise Errors::Conjur::UnexpectedParameter, unknown.join(', ')
    end

    Rails.logger.warn(
      LogMessages::Conjur::UnexpectedParameter.new(
        "#{controller_name}##{action}",
        unknown.join(', ')
      ).to_s
    )
  end

  # Returns query parameter keys not declared in the allowlist.
  # Route segment params (e.g. :account, :id) appear in request.parameters
  # but not in request.query_parameters, so we use query_parameters here.
  def unknown_query_params(allowed)
    received = request.query_parameters.keys.map(&:to_sym)
    received - allowed
  end
end
