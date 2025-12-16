# frozen_string_literal: true

module Authentication
  module AuthnCert
    module V2
      module Validations
        class Constraints
          def initialize(logger: Rails.logger)
            @multiple_constraint = Authentication::Constraints::MultipleConstraint
            @any_constraint = Authentication::Constraints::AnyConstraint
            @permitted_constraint = Authentication::Constraints::PermittedConstraint
            @logger = logger
          end

          def run(annotations:, authenticator:)
            host_mode = authenticator.variables[:host_mode]
            constraints = host_mode == 'spiffe' ? spiffe_mode_constraints : request_mode_constraints
            result = constraints.validate(resource_restrictions: annotations.keys.map(&:to_s))
            if result.success?
              @logger.info(LogMessages::Authentication::AuthnCert::ConstraintsValidationSucceeded.new(authenticator.service_id, host_mode))
            else
              @logger.info(LogMessages::Authentication::AuthnCert::ConstraintsValidationFailed.new(authenticator.service_id, host_mode))
            end
            result
          end

          private

          def request_mode_constraints
            @multiple_constraint.new(
              only_accept_applicable_restrictions,
              require_at_least_one_applicable_restriction
            )
          end

          def spiffe_mode_constraints
            @multiple_constraint.new(
              only_accept_applicable_restrictions
            )
          end

          def only_accept_applicable_restrictions
            @permitted_constraint.new(
              permitted: permitted_restrictions
            )
          end

          def require_at_least_one_applicable_restriction
            @any_constraint.new(
              any: permitted_restrictions
            )
          end

          def permitted_restrictions
            %w[san-uri san-dns san-ip cn]
          end
        end
      end
    end
  end
end
