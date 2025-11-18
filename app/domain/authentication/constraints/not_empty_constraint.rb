module Authentication
  module Constraints

    # This constraint returns true if the resource restriction contains at least one restriction. Otherwise it raises
    # EmptyAnnotationsListConfigured exception
    class NotEmptyConstraint

      def initialize
        @success = Responses::Success
        @failure = Responses::Failure
      end

      def validate(resource_restrictions:)
        return @success.new(true) unless resource_restrictions.empty?

        exception = Errors::Authentication::Constraints::RoleMissingAnyRestrictions.new
        @failure.new(
          exception.message,
          exception: exception
        )
      end
    end
  end
end
