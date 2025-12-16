# frozen_string_literal: true

module Authentication
  module Util
    module V2
      class AuthenticatorLoader
        class << self
          def all
            certificate_authenticator_enabled = Rails.application.config.feature_flags.enabled?(:certificate_authentication)

            {}.tap do |rtn|
              group_authenticators(authenticator_klasses).each do |authn_type, authn_klasses|
                next if authn_klasses[:strategy].nil? || authn_klasses[:authenticator].nil?
                next if authn_type == 'authn-cert' && !certificate_authenticator_enabled

                rtn[authn_type] = authn_klasses
              end
            end
          end

          def authenticator_klasses
            results = []

            # Authenticator business logic is implemented in the Authentication
            # module. Authenticator data models are defined in the AuthenticatorsV2
            # module. For an authenticator to be considered "installed", it must
            # consist of both a model and its associated business logic.
            load_klasses(mod: Authentication, klasses: results)
            load_klasses(mod: AuthenticatorsV2, klasses: results)

            results.flatten.compact.uniq
          end

          private

          def group_authenticators(klasses)
            grouped_files = {}
            process_authenticator_models(klasses, grouped_files)
            process_strategy_implementations(klasses, grouped_files)
            grouped_files
          end

          # Processes AuthenticatorsV2 model classes and maps them to their type.
          # These are the data model definitions for authenticators.
          def process_authenticator_models(klasses, groups)
            klasses.each do |klass|
              parts = klass.to_s.split('::')

              next unless parts[0] == 'AuthenticatorsV2'
              next if parts[1] == 'AuthenticatorTypeFactory'

              type = AuthenticatorsV2::AuthenticatorTypeFactory.module_to_type(klass)

              groups[type] ||= {}
              groups[type][:authenticator] = klass
            end
          end

          # Processes Authentication::Authn*::V2::Strategy classes.
          # These are the business logic implementations for authenticators.
          def process_strategy_implementations(klasses, groups)
            klasses.each do |klass|
              parts = klass.to_s.split('::')

              next unless parts[1].match(/^Authn/)
              next unless parts[2] == 'V2'
              next unless parts.last == 'Strategy'

              type = Authentication::Util::NamespaceSelector.module_to_type(parts[1])

              groups[type] ||= {}
              groups[type][:strategy] = klass
            end
          end

          # Recursively loads all classes in the provided Module. This is
          # used to "auto-magically" find and use relevant authenticators.
          def load_klasses(mod:, klasses:)
            mod.constants.each do |constant|
              constant = mod.const_get(constant)
              case constant
              when Class
                klasses << constant
              when Module
                load_klasses(mod: constant, klasses: klasses)
              end
            end
          end
        end
      end
    end
  end
end
