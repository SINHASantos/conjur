module Authentication
  module Constraints

    class ExclusiveConstraint

      def initialize(exclusive:)
        @exclusive = exclusive

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        exclusive_restrictions = resource_restrictions & @exclusive
        return @success.new(true) if exclusive_restrictions.length <= 1

        exception = Errors::Authentication::Constraints::IllegalConstraintCombinations.new(
          exclusive_restrictions
        )
        @failure.new(
          exception.message,
          exception: exception
        )
      end
    end
  end
end
