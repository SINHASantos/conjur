# frozen_string_literal: true

require 'spec_helper'

# Minimal stub controller that includes the concern, allowing tests to
# control the action name, allowed params, and query string independently.
class DummyQueryParamController
  # Must be defined before `include` so the concern's `included` hook can call
  # `before_action` (same load order as a real ActionController::Base subclass).
  def self.before_action(*); end

  include QueryParamValidation

  attr_reader :action_name, :controller_name

  def initialize(action:, query_params: {}, controller_name: 'dummy')
    @action_name = action.to_s
    @controller_name = controller_name
    @request = OpenStruct.new(query_parameters: query_params.stringify_keys)
  end

  def request
    @request
  end
end

RSpec.describe(QueryParamValidation) do
  # Helper that declares an allowlist on the dummy class and runs the check.
  def controller_for(action:, allowed:, strict:, query_params: {})
    klass = Class.new(DummyQueryParamController) do
      include QueryParamValidation
      def self.before_action(*); end

      validate_query_params action, allowed, strict: strict
    end
    klass.new(action: action, query_params: query_params)
  end

  def run_check(controller)
    controller.send(:check_query_params)
  end

  def controller_for_default_strict(
    action:,
    allowed:,
    query_params: {},
    use_v2_rest: false
  )
    if use_v2_rest
      klass = Class.new(DummyQueryParamController) do
        def self.before_action(*); end
        def self.v2_rest_controller?
          true
        end

        include QueryParamValidation
        validate_query_params action, allowed
      end
    else
      klass = Class.new(DummyQueryParamController) do
        def self.before_action(*); end
        include QueryParamValidation
        validate_query_params action, allowed
      end
    end

    klass.new(action: action, query_params: query_params)
  end

  def with_config_strict_params(value)
    previous_config = Rails.application.config.conjur_config
    config_double = instance_double(
      Conjur::ConjurConfig,
      strict_params: value
    )
    allow(Rails.application.config).to receive(:conjur_config).and_return(config_double)
    yield
  ensure
    allow(Rails.application.config).to receive(:conjur_config).and_return(previous_config)
  end

  context 'when action has no declared allowlist' do
    subject do
      klass = Class.new(DummyQueryParamController) do
        include QueryParamValidation
        def self.before_action(*); end
        # intentionally no validate_query_params call
      end
      klass.new(action: :index, query_params: {})
    end

    it 'raises Errors::Conjur::UnexpectedParameter' do
      expect { run_check(subject) }
        .to raise_error(Errors::Conjur::UnexpectedParameter)
    end
  end

  context 'when strict mode is enabled (new endpoints)' do
    context 'when all query params are in the allowlist' do
      subject do
        controller_for(
          action: :show,
          allowed: %i[account kind],
          strict: true,
          query_params: { account: 'myaccount', kind: 'variable' }
        )
      end

      it 'does not raise and does not warn' do
        expect(Rails.logger).not_to receive(:warn)
        expect { run_check(subject) }.not_to raise_error
      end
    end

    context 'when an unknown query param is present' do
      subject do
        controller_for(
          action: :show,
          allowed: %i[account],
          strict: true,
          query_params: { account: 'myaccount', dryRun: 'true' }
        )
      end

      it 'raises Errors::Conjur::UnexpectedParameter' do
        expect { run_check(subject) }
          .to raise_error(Errors::Conjur::UnexpectedParameter, /dryRun/)
      end
    end

    context 'when the allowlist is empty' do
      subject do
        controller_for(
          action: :index,
          allowed: [],
          strict: true,
          query_params: {}
        )
      end

      it 'does not raise when no params are sent' do
        expect { run_check(subject) }.not_to raise_error
      end
    end
  end

  context 'when permissive mode is enabled (legacy endpoints)' do
    context 'when all query params are known' do
      subject do
        controller_for(
          action: :index,
          allowed: %i[account kind limit],
          strict: false,
          query_params: { account: 'a', kind: 'variable', limit: '10' }
        )
      end

      it 'does not raise and does not warn' do
        expect(Rails.logger).not_to receive(:warn)
        expect { run_check(subject) }.not_to raise_error
      end
    end

    context 'when an unknown query param is present' do
      subject do
        controller_for(
          action: :index,
          allowed: %i[account kind],
          strict: false,
          query_params: { account: 'a', unknownThing: 'x' }
        )
      end

      it 'does not raise' do
        expect { run_check(subject) }.not_to raise_error
      end

      it 'logs a warning containing the unknown parameter name' do
        expect(Rails.logger).to receive(:warn).with(/unknownThing/)
        run_check(subject)
      end

      it 'logs CONJ00545W in the warning message' do
        expect(Rails.logger).to receive(:warn).with(/CONJ00545W/)
        run_check(subject)
      end
    end

    context 'when multiple unknown params are present' do
      subject do
        controller_for(
          action: :index,
          allowed: %i[account],
          strict: false,
          query_params: { account: 'a', foo: 'x', bar: 'y' }
        )
      end

      it 'includes all unknown param names in a single warning' do
        expect(Rails.logger).to receive(:warn).once.with(/foo.*bar|bar.*foo/)
        run_check(subject)
      end
    end
  end

  describe 'RAILS_INTERNAL_PARAMS exclusion' do
    # Rails injects :controller, :action, :format into parameters.
    # These must never be treated as unknown even in strict mode.
    subject do
      controller_for(
        action: :show,
        allowed: %i[account],
        strict: true,
        query_params: { account: 'a' }
      )
    end

    it 'does not raise for Rails internal params in the query string' do
      # Simulate them being present in query_parameters keys by overriding
      # the request stub.
      allow(subject.request).to receive(:query_parameters)
        .and_return({ 'account' => 'a', 'controller' => 'dummy', 'action' => 'show', 'format' => 'json' })
      expect { run_check(subject) }.not_to raise_error
    end
  end

  context 'when strictness is not explicitly declared' do
    context 'for V2 controllers' do
      subject do
        controller_for_default_strict(
          action: :show,
          allowed: %i[account],
          query_params: { account: 'myaccount', dryRun: 'true' },
          use_v2_rest: true
        )
      end

      it 'defaults to strict and raises on unknown query params' do
        expect { run_check(subject) }
          .to raise_error(Errors::Conjur::UnexpectedParameter, /dryRun/)
      end
    end

    context 'for V1 controllers when strict_params config is false' do
      subject do
        controller_for_default_strict(
          action: :show,
          allowed: %i[account],
          query_params: { account: 'myaccount', dryRun: 'true' }
        )
      end

      it 'defaults to permissive and warns on unknown query params' do
        with_config_strict_params(false) do
          expect(Rails.logger).to receive(:warn).with(/dryRun/)
          expect { run_check(subject) }.not_to raise_error
        end
      end
    end

    context 'for V1 controllers when strict_params config is true' do
      subject do
        controller_for_default_strict(
          action: :show,
          allowed: %i[account],
          query_params: { account: 'myaccount', dryRun: 'true' }
        )
      end

      it 'defaults to strict and raises on unknown query params' do
        with_config_strict_params(true) do
          expect { run_check(subject) }
            .to raise_error(Errors::Conjur::UnexpectedParameter, /dryRun/)
        end
      end
    end
  end
end

# =============================================================================
# Allowlist Completeness Check
# =============================================================================
#
# The runtime guard in `check_query_params` raises when a routed action has no
# `validate_query_params` declaration — but only when that action is actually
# invoked. A developer could add a new action, skip the declaration, write no
# test that hits it, and ship code that would only fail on the first real
# production request.
#
# These examples close that gap. They walk the live Rails route table at spec
# load time and assert that every action routed to a qualifying controller has
# a declared allowlist entry. A failure here means exactly one thing:
#
#   "A routed action was added without calling validate_query_params."
#
# ----- What "qualifying" means -----
#
# A route is checked when ALL of the following apply:
#
#   1. The controller class includes QueryParamValidation.
#      Controllers that inherit directly from ApplicationController
#      (e.g. AuthenticateController, CredentialsController) manage their
#      own param handling and are excluded.
#
#   2. The controller is NOT a V2RestController subclass.
#      V2 controllers call `skip_before_action :check_query_params` because
#      their `permit_url_params` mechanism already raises on unknown params.
#      They will be added to this check once the v1/v2 validation framework
#      is fully unified (see the comment in v2_rest_controller.rb).
#
#   3. The controller has at least one existing validate_query_params
#      declaration. Brand-new controllers with zero declarations are assumed
#      to be in the process of being annotated. The runtime guard will surface
#      the missing annotation immediately when any action is first hit. Once
#      ANY validate_query_params call lands on a controller, ALL of its routed
#      actions automatically fall under this completeness check.
#
RSpec.describe 'QueryParamValidation allowlist completeness' do
  # Enumerate unique controller/action pairs from the live route table. Done
  # at spec load time so each pair becomes its own named example in the output.
  routed_actions =
    Rails.application.routes.routes
         .filter_map do |route|
           controller = route.defaults[:controller]
           action     = route.defaults[:action]
           [controller, action] if controller && action
         end
         .uniq

  routed_actions.each do |controller_name, action_name|
    it "#{controller_name}##{action_name} has a validate_query_params declaration" do
      # -----------------------------------------------------------------------
      # Resolve the constant. Some routes target engine controllers whose
      # constants live under a namespace or in a gem (e.g. conjur_audit/…).
      # Skip those gracefully rather than failing with a NameError.
      # -----------------------------------------------------------------------
      controller_class = begin
        "#{controller_name.camelize}Controller".constantize
      rescue NameError
        skip "Controller class not resolved for route '#{controller_name}'"
      end

      # -----------------------------------------------------------------------
      # Qualification check 1: must include QueryParamValidation.
      # -----------------------------------------------------------------------
      unless controller_class.include?(QueryParamValidation)
        skip "#{controller_class} does not include QueryParamValidation"
      end

      # -----------------------------------------------------------------------
      # Qualification check 2: must not be a V2RestController subclass.
      # Remove this guard once skip_before_action is removed from
      # V2RestController and all v2 actions have declarations.
      # -----------------------------------------------------------------------
      if controller_class.ancestors.include?(V2RestController)
        skip "#{controller_class} is a V2RestController subclass (skip_before_action " \
             "still in place — will be enforced after v1/v2 unification)"
      end

      # -----------------------------------------------------------------------
      # Qualification check 3: must have at least one declaration already.
      # Controllers with zero entries are either brand-new or partially
      # migrated; the runtime guard handles them until they opt in fully.
      # -----------------------------------------------------------------------
      unless controller_class._query_param_allowlists.any?
        skip "#{controller_class} has no validate_query_params declarations yet " \
             "(add declarations for all actions when opting this controller in)"
      end

      # -----------------------------------------------------------------------
      # The actual assertion: the specific action must have an allowlist entry.
      # -----------------------------------------------------------------------
      expect(controller_class._query_param_allowlists).to(
        have_key(action_name.to_sym),
        <<~MSG
          #{controller_class}##{action_name} is reachable via a route but has
          no validate_query_params declaration. Each routed action on a
          QueryParamValidation-enabled controller must declare its allowed
          query parameters. Add one of the following to #{controller_class}:

            # New/strict endpoint — returns 400 Bad Request on unknown params:
            validate_query_params :#{action_name}, %i[param1 param2]

            # Legacy/permissive endpoint — logs CONJ00545W, request continues:
            validate_query_params :#{action_name}, %i[param1 param2], strict: false
        MSG
      )
    end
  end
end
