module Authentication
  module Constraints

    # This constraint is initialized with an array of strings.
    # They represent the list of resource restrictions that any one of them must be present.
    # Calling `validate` enforces this constraint on the given list of resource restrictions.
    class AnyConstraint

      def initialize(any:)
        @any = any

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        restrictions_found = resource_restrictions & @any
        return @success.new(true) unless restrictions_found.empty?

        exception = Errors::Authentication::Constraints::RoleMissingRequiredConstraints.new(@any)
        @failure.new(
          exception.message,
          exception: exception
        )
      end
    end
  end
end
