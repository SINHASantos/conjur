module Authentication
  module Constraints

    # This constraint is initialized with an array of strings.
    # They represent resource restrictions where exactly one is required.
    class RequiredExclusiveConstraint

      def initialize(required_exclusive:)
        @required_exclusive = required_exclusive

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        restrictions_found = resource_restrictions & @required_exclusive
        return @success.new(true) if restrictions_found.length == 1

        exception = Errors::Authentication::Constraints::IllegalRequiredExclusiveCombination.new(
          @required_exclusive,
          restrictions_found
        )
        @failure.new(
          exception.message,
          exception: exception
        )
      end

    end
  end
end
