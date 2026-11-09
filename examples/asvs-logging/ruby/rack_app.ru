# frozen_string_literal: true

# A plain Rack app using the same middleware as the Rails example, so the event path can be run
# without Rails:  BOWER_COLLECTOR_URL=... BOWER_INGEST_TOKEN=... ruby rack_app.ru
require 'json'
require 'rack'
require_relative 'rails/app/middleware/bower_request_context'

app = lambda do |env|
  request = Rack::Request.new(env)
  case [request.request_method, request.path_info]
  when ['POST', '/login']
    begin
      body = JSON.parse(request.body.read)
    rescue JSON::ParserError
      BowerSecurity.emit(env, 'eventCategory' => 'application-security', 'eventType' => 'input_validation_failure',
                              'eventAction' => 'validation.reject', 'eventResult' => 'failure', 'eventSeverity' => 'low',
                              'reason' => 'MalformedJson', 'route' => '/login')
      next [400, { 'content-type' => 'application/json' }, ['{"error":"bad request"}']]
    end
    if Rack::Utils.secure_compare("#{body['username']}:#{body['password']}", 'demo:demo-password')
      BowerSecurity.emit(env, 'eventCategory' => 'authentication', 'eventType' => 'authentication_success',
                              'eventAction' => 'authentication.login', 'eventResult' => 'success', 'route' => '/login',
                              'actor' => { 'userId' => 'user-demo', 'username' => body['username'] }, 'labels' => { 'authMethod' => 'password' })
      [204, {}, []]
    else
      BowerSecurity.emit(env, 'eventCategory' => 'authentication', 'eventType' => 'authentication_failure',
                              'eventAction' => 'authentication.attempt', 'eventResult' => 'failure', 'eventSeverity' => 'low',
                              'reason' => 'InvalidCredentials', 'route' => '/login', 'actor' => { 'username' => body['username'].to_s })
      [401, { 'content-type' => 'application/json' }, ['{"error":"invalid credentials"}']]
    end
  when ['GET', '/admin/users']
    BowerSecurity.emit(env, 'eventCategory' => 'authorisation', 'eventType' => 'authorisation_failure', 'eventAction' => 'authz.function',
                            'eventResult' => 'denied', 'eventSeverity' => 'medium', 'route' => '/admin/users',
                            'actor' => { 'userId' => 'user-demo', 'role' => 'member' }, 'target' => { 'type' => 'function', 'id' => 'admin.users.list' })
    [403, { 'content-type' => 'application/json' }, ['{"error":"forbidden"}']]
  else
    [404, {}, []]
  end
end

if $PROGRAM_NAME == __FILE__
  require 'rackup'
  Rackup::Server.start(app: BowerRequestContext.new(app), Port: Integer(ENV.fetch('PORT', '4567')), Host: '127.0.0.1')
else
  use BowerRequestContext
  run app
end
