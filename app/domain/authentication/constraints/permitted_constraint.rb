module Authentication
  module Constraints

    # This constraint is initialized with an array of strings.
    # They represent the only resource restrictions that may be present.
    # Calling `validate` enforces this constraint on the given list of resource restrictions.
    class PermittedConstraint

      def initialize(permitted:)
        @permitted = permitted

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        not_supported_restrictions = resource_restrictions - @permitted
        return @success.new(true) unless not_supported_restrictions.any?

        exception = Errors::Authentication::Constraints::ConstraintNotSupported.new(
          not_supported_restrictions,
          @permitted
        )
        @failure.new(
          exception.message,
          exception: exception
        )
      end
    end
  end
end
