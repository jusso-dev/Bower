# frozen_string_literal: true

require_relative '../../../bower_events'

# Rack middleware: request ID (honours a W3C traceparent), trusted-proxy client IP, and a
# last-resort application_error event. Works in Rails and any Rack app.
class BowerRequestContext
  def initialize(app, trusted_proxies: ENV.fetch('TRUSTED_PROXIES', '').split(',').map(&:strip).reject(&:empty?))
    @app = app
    @trusted = trusted_proxies
  end

  def call(env)
    traceparent = env['HTTP_TRACEPARENT'].to_s
    env['bower.request_id'] = traceparent.length == 55 ? traceparent[3, 32] : SecureRandom.uuid
    # REMOTE_ADDR, not Rails' request.remote_ip, so only the configured proxies are trusted.
    env['bower.client_ip'] = BowerEvents.client_ip(env['REMOTE_ADDR'].to_s, env['HTTP_X_FORWARDED_FOR'], @trusted)
    status, headers, body = @app.call(env)
    headers['x-request-id'] = env['bower.request_id']
    [status, headers, body]
  rescue StandardError => e
    BowerSecurity.emit(env, 'eventCategory' => 'application-security', 'eventType' => 'application_error',
                            'eventAction' => 'error.unhandled', 'eventResult' => 'failure', 'eventSeverity' => 'medium',
                            'reason' => 'UnhandledException', 'labels' => { 'errorType' => e.class.name })
    [500, { 'content-type' => 'application/json', 'x-request-id' => env['bower.request_id'] },
     [JSON.generate(error: 'internal error', requestId: env['bower.request_id'])]]
  end
end

# Builds and sends events with the request context. Never raises.
module BowerSecurity
  APP = { 'name' => ENV.fetch('BOWER_APP_NAME', 'rails-example'), 'environment' => ENV.fetch('RAILS_ENV', 'development'),
          'version' => '1.0.0' }.freeze
  CLIENT = BowerEvents::Client.new

  module_function

  def emit(env, spec)
    path = env['PATH_INFO'].to_s
    spec = spec.merge('sourceIp' => env['bower.client_ip'], 'userAgent' => env['HTTP_USER_AGENT'],
                      'route' => env['bower.route'] || spec['route'] || path,
                      'request' => { 'correlationId' => env['bower.request_id'], 'method' => env['REQUEST_METHOD'], 'path' => path })
    CLIENT.send_async(BowerEvents.build_event(APP, spec))
  end
end
