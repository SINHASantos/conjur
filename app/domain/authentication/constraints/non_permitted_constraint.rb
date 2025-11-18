module Authentication
  module Constraints

    # This constraint is initialized with an array of strings.
    # They represent resource restrictions that are not allowed
    # Calling `validate` enforces this constraint on the given list of resource restrictions.
    # If there is annotation for one of these non permitted values proper error would be thrown
    class NonPermittedConstraint

      def initialize(non_permitted:)
        @non_permitted = non_permitted

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        any_non_permitted_restrictions = resource_restrictions & @non_permitted
        return @success.new(true) if any_non_permitted_restrictions.empty?

        exception = Errors::Authentication::Constraints::NonPermittedRestrictionGiven.new(
          any_non_permitted_restrictions
        )
        @failure.new(
          exception.message,
          exception: exception
        )
      end
    end
  end
end
