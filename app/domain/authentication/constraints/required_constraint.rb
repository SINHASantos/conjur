module Authentication
  module Constraints

    class RequiredConstraint

      def initialize(required:)
        @required = required

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        missing_required_constraints = @required - resource_restrictions
        return @success.new(true) unless missing_required_constraints.any?

        exception = Errors::Authentication::Constraints::RoleMissingConstraints.new(
          missing_required_constraints
        )
        @failure.new(
          exception.message,
          exception: exception
        )
      end
    end
  end
end
