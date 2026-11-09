# frozen_string_literal: true

# config/initializers/bower.rb
require Rails.root.join('app/middleware/bower_request_context')

# Run before ActionDispatch so the request ID and client IP exist for everything after it.
Rails.application.config.middleware.insert_before 0, BowerRequestContext

# Application logs: never write credentials (V16.2.5). Rails filters these from params and logs.
Rails.application.config.filter_parameters += %i[passw token secret otp code cookie authorization]

# Devise / Warden authentication events (V16.3.1). Skip this block without Devise.
if defined?(Warden)
  Warden::Manager.after_authentication do |user, auth, _opts|
    BowerSecurity.emit(auth.env, 'eventCategory' => 'authentication', 'eventType' => 'authentication_success',
                                 'eventAction' => 'authentication.login', 'eventResult' => 'success',
                                 'actor' => { 'userId' => user.id.to_s, 'username' => user.try(:email) },
                                 'labels' => { 'authMethod' => 'password' })
  end

  Warden::Manager.before_failure do |env, opts|
    params = Rack::Request.new(env).params
    username = params.dig('user', 'email') || params['email']
    BowerSecurity.emit(env, 'eventCategory' => 'authentication', 'eventType' => 'authentication_failure',
                            'eventAction' => 'authentication.attempt', 'eventResult' => 'failure', 'eventSeverity' => 'low',
                            'reason' => opts[:message].to_s.presence || 'InvalidCredentials', 'actor' => { 'username' => username })
  end

  Warden::Manager.before_logout do |user, auth, _opts|
    next unless user

    BowerSecurity.emit(auth.env, 'eventCategory' => 'authentication', 'eventType' => 'session_terminated',
                                 'eventAction' => 'session.logout', 'eventResult' => 'success', 'actor' => { 'userId' => user.id.to_s })
  end
end
