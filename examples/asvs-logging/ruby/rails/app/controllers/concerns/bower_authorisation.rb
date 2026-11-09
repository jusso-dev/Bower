# frozen_string_literal: true

# include BowerAuthorisation in ApplicationController. Works with Pundit and CanCanCan; adapt
# the rescue_from classes to your authorisation library.
module BowerAuthorisation
  extend ActiveSupport::Concern

  included do
    before_action { request.env['bower.route'] = request.route_uri_pattern&.delete_suffix('(.:format)') }
    rescue_from 'Pundit::NotAuthorizedError', 'CanCan::AccessDenied', with: :bower_forbidden
  end

  private

  def bower_forbidden(error)
    record = error.respond_to?(:record) ? error.record : nil
    BowerSecurity.emit(request.env, 'eventCategory' => 'authorisation', 'eventType' => 'authorisation_failure',
                                    'eventAction' => record.is_a?(ActiveRecord::Base) ? 'authz.object' : 'authz.function',
                                    'eventResult' => 'denied', 'eventSeverity' => 'medium',
                                    'actor' => { 'userId' => current_user&.id&.to_s },
                                    'target' => { 'type' => record&.class&.name&.underscore || controller_name,
                                                  'id' => record.try(:id)&.to_s },
                                    'labels' => { 'requiredPermission' => "#{controller_name}.#{action_name}" })
    head :forbidden
  end
end
