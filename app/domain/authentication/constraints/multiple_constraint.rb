module Authentication
  module Constraints

    # This constraint aggregates multiple constraints and validates all of them.
    class MultipleConstraint

      def initialize(*args)
        @constraints = args

        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        @constraints.each do |constraint|
          response = constraint.validate(resource_restrictions: resource_restrictions)
          return response unless response.success?
        end
        @success.new(true)
      end
    end
  end
end
