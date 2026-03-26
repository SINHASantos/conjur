# frozen_string_literal: true

# QueryParamValidation provides per-action query parameter allowlists.
#
# Two modes are supported:
#
#   strict (default for new V2 endpoints)
#     Any unknown query parameter raises Errors::Conjur::UnexpectedParameter
#     (400 Bad Request). Controllers opt in by calling:
#
#       validate_query_params :action_name, %i[allowed param names]
#
#   permissive (for legacy V1 endpoints)
#     Unknown query parameters are logged as a CONJ00545W warning but the
#     request continues. Controllers opt in by calling:
#
#       validate_query_params :action_name, %i[allowed param names],
#                             strict: false
#
# Actions with no declared allowlist are treated as strict-unknown: an
# error is raised to force developers to explicitly declare params for
# every new endpoint.
#
# Rails always injects :controller, :action, and route-segment parameters
# (e.g. :account, :id) into request.parameters. Those are excluded from
# the unknown-param check automatically via RAILS_INTERNAL_PARAMS.
module QueryParamValidation
  extend ActiveSupport::Concern

  RAILS_INTERNAL_PARAMS = %i[controller action format].freeze

  included do
    before_action :check_query_params
  end

  module ClassMethods
    # @param action [Symbol] the controller action this allowlist applies to
    # @param allowed [Array<Symbol>] permitted query parameter names
    # @param strict [Boolean] when false, unknown params warn instead of error
    def validate_query_params(action, allowed, strict: true)
      _query_param_allowlists[action] = {
        allowed: allowed.map(&:to_sym),
        strict: strict
      }
    end

    def _query_param_allowlists
      @_query_param_allowlists ||= {}
    end
  end

  private

  def check_query_params
    action = action_name.to_sym
    allowlist_entry = self.class._query_param_allowlists[action]

    if allowlist_entry.nil?
      # No allowlist declared — this endpoint is not yet annotated.
      # New endpoints must declare their params explicitly, so raise to
      # prevent silent omissions during development.
      raise Errors::Conjur::UnexpectedParameter,
            "(no allowlist declared for #{controller_name}##{action})"
    end

    unknown = unknown_query_params(allowlist_entry[:allowed])
    return if unknown.empty?

    if allowlist_entry[:strict]
      raise Errors::Conjur::UnexpectedParameter, unknown.join(', ')
    else
      Rails.logger.warn(
        LogMessages::Conjur::UnexpectedParameter.new(
          "#{controller_name}##{action}",
          unknown.join(', ')
        ).to_s
      )
    end
  end

  # Returns query param keys not in the allowlist or Rails internals.
  # Route segment params (e.g. :account, :id) appear in request.parameters
  # but not in request.query_parameters, so we use query_parameters here.
  def unknown_query_params(allowed)
    received = request.query_parameters.keys.map(&:to_sym)
    received - allowed - RAILS_INTERNAL_PARAMS
  end
end
