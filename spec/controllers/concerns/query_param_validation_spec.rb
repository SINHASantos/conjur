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
  def controller_for(action:, allowed:, query_params: {}, use_v2_rest: false, default: nil)
    klass = Class.new(DummyQueryParamController) do
      define_singleton_method(:v2_rest_controller?) { use_v2_rest }

      validate_query_params default if default
      validate_query_params_for_action action, allowed
    end
    klass.new(action: action, query_params: query_params)
  end

  def run_check(controller)
    controller.send(:check_query_params)
  end

  def with_config_strict_params(value)
    previous_flags = Rails.application.config.feature_flags
    flags_double = instance_double(Conjur::FeatureFlags::Features)
    allow(flags_double).to receive(:enabled?).with(:strict_params).and_return(value)
    allow(Rails.application.config).to receive(:feature_flags).and_return(flags_double)
    yield
  ensure
    allow(Rails.application.config).to receive(:feature_flags).and_return(previous_flags)
  end

  context 'when action has no declared allowlist' do
    subject do
      klass = Class.new(DummyQueryParamController) do
        # intentionally no query-param validation declarations
      end
      klass.new(action: :index, query_params: {})
    end

    it 'raises Errors::Conjur::UnexpectedParameter' do
      expect { run_check(subject) }
        .to raise_error(Errors::Conjur::UnexpectedParameter)
    end
  end

  context 'when action has no declared allowlist but controller default exists' do
    subject do
      klass = Class.new(DummyQueryParamController) do
        define_singleton_method(:v2_rest_controller?) { false }
        validate_query_params []
      end
      klass.new(action: :index, query_params: { badParam: 'true' })
    end

    context 'when default is permissive (feature flag disabled)' do
      it 'does not raise and logs a warning' do
        with_config_strict_params(false) do
          expect(Rails.logger).to receive(:warn).with(/badParam/)
          expect { run_check(subject) }.not_to raise_error
        end
      end
    end
  end

  context 'when strict mode is active (V2 controller)' do
    context 'when all query params are in the allowlist' do
      subject do
        controller_for(
          action: :show,
          allowed: %i[account kind],
          use_v2_rest: true,
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
          use_v2_rest: true,
          query_params: { account: 'myaccount', badParam: 'true' }
        )
      end

      it 'raises Errors::Conjur::UnexpectedParameter' do
        expect { run_check(subject) }
          .to raise_error(Errors::Conjur::UnexpectedParameter, /badParam/)
      end
    end

    context 'when the allowlist is empty' do
      subject do
        controller_for(
          action: :index,
          allowed: [],
          use_v2_rest: true,
          query_params: {}
        )
      end

      it 'does not raise when no params are sent' do
        expect { run_check(subject) }.not_to raise_error
      end
    end
  end

  context 'when permissive mode is active (feature flag disabled)' do
    context 'when all query params are known' do
      subject do
        controller_for(
          action: :index,
          allowed: %i[account kind limit],
          query_params: { account: 'a', kind: 'variable', limit: '10' }
        )
      end

      it 'does not raise and does not warn' do
        with_config_strict_params(false) do
          expect(Rails.logger).not_to receive(:warn)
          expect { run_check(subject) }.not_to raise_error
        end
      end
    end

    context 'when an unknown query param is present' do
      subject do
        controller_for(
          action: :index,
          allowed: %i[account kind],
          query_params: { account: 'a', unknownThing: 'x' }
        )
      end

      it 'does not raise' do
        with_config_strict_params(false) do
          expect { run_check(subject) }.not_to raise_error
        end
      end

      it 'logs a warning containing the unknown parameter name' do
        with_config_strict_params(false) do
          expect(Rails.logger).to receive(:warn).with(/unknownThing/)
          run_check(subject)
        end
      end

      it 'logs CONJ00545W in the warning message' do
        with_config_strict_params(false) do
          expect(Rails.logger).to receive(:warn).with(/CONJ00545W/)
          run_check(subject)
        end
      end
    end

    context 'when multiple unknown params are present' do
      subject do
        controller_for(
          action: :index,
          allowed: %i[account],
          query_params: { account: 'a', foo: 'x', bar: 'y' }
        )
      end

      it 'includes all unknown param names in a single warning' do
        with_config_strict_params(false) do
          expect(Rails.logger).to receive(:warn).once.with(/foo.*bar|bar.*foo/)
          run_check(subject)
        end
      end
    end
  end

  context 'when strictness is not explicitly declared' do
    context 'for V2 controllers' do
      subject do
        controller_for(
          action: :show,
          allowed: %i[account],
          query_params: { account: 'myaccount', badParam: 'true' },
          use_v2_rest: true
        )
      end

      it 'defaults to strict and raises on unknown query params' do
        expect { run_check(subject) }
          .to raise_error(Errors::Conjur::UnexpectedParameter, /badParam/)
      end
    end

    context 'for V1 controllers when strict_params feature flag is false (default)' do
      subject do
        controller_for(
          action: :show,
          allowed: %i[account],
          query_params: { account: 'myaccount', badParam: 'true' }
        )
      end

      it 'is permissive and warns on unknown query params' do
        with_config_strict_params(false) do
          expect(Rails.logger).to receive(:warn).with(/badParam/)
          expect { run_check(subject) }.not_to raise_error
        end
      end
    end

    context 'for V1 controllers when strict_params feature flag is true' do
      subject do
        controller_for(
          action: :show,
          allowed: %i[account],
          query_params: { account: 'myaccount', badParam: 'true' }
        )
      end

      it 'is strict and raises on unknown query params' do
        with_config_strict_params(true) do
          expect { run_check(subject) }
            .to raise_error(Errors::Conjur::UnexpectedParameter, /badParam/)
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
# query-parameter allowlist — via declaration or controller default — but only when
# that action is actually invoked. A developer could add a new action, skip the
# test that hits it, and ship code that would only fail on the first real
# production request.
#
# These examples close that gap. They walk the live Rails route table at spec
# load time and assert that every action routed to a qualifying controller has
# an allowlist entry. A failure here means exactly one thing:
#
#   "A routed action was added without query-parameter allowlist coverage."
#
# ----- What "qualifying" means -----
#
# A route is checked when ALL of the following apply:
#
#   1. The controller class includes QueryParamValidation.
#      All API controllers (through ApplicationController) are expected to be
#      covered by this check. V2 and V1 are both validated here; V2 inherits
#      strict defaults while V1 uses the CONJUR_STRICT_PARAMS default unless
#      explicit per-endpoint overrides are provided.
#
#   3. The controller has either:
#      - at least one validate_query_params_for_action declaration, or
#      - one controller-level validate_query_params declaration.
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
    it "#{controller_name}##{action_name} has query-param validation coverage" do
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
      # The actual assertion: the specific action must resolve an allowlist entry
      # via action-specific declaration or controller default.
      # -----------------------------------------------------------------------
      expect(controller_class.query_param_allowlist_for(action_name.to_sym)).to(
        be_truthy,
        <<~MSG
          #{controller_class}##{action_name} is reachable via a route but has
          no query-parameter allowlist coverage. Add one of the following to #{controller_class}:

            # Returns 422 Unprocessable Entity params not in the allowlist:
            validate_query_params_for_action :#{action_name}, %i[param1 param2]
            # or use a controller-level default (no query parameters allowed):
            validate_query_params []
        MSG
      )
    end
  end
end
