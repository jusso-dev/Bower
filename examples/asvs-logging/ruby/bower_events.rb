# frozen_string_literal: true

# Bower security events for Ruby apps (Rails, Rack). Standard library only.
# Builds Bower envelope 1.0.0 events, sanitises them before they leave the process and posts
# them to a Bower collector. The collector redacts again; this is defence in depth.
require 'ipaddr'
require 'json'
require 'net/http'
require 'securerandom'
require 'time'
require 'uri'

module BowerEvents
  SCHEMA_VERSION = '1.0.0'
  CONTROL = /[\u0000-\u001f\u007f\u2028\u2029]+/
  SECRET_FRAGMENTS = %w[password passwd passphrase secret token apikey cookie authorization credential privatekey signature].freeze
  SECRET_NAMES = %w[body rawbody requestbody responsebody headers payload otp otpcode totp mfacode verificationcode
                    recoverycode backupcode stacktrace exceptionmessage statement querytext sqltext querystring rawquery].freeze
  LIMITS = { 'eventOutcomeReason' => 1024, 'path' => 2048 }.freeze

  module_function

  def secret?(name)
    normal = name.to_s.downcase.gsub(/[^a-z0-9]/, '')
    SECRET_NAMES.include?(normal) || SECRET_FRAGMENTS.any? { |fragment| normal.include?(fragment) }
  end

  def clean(value, key = '')
    case value
    when String then value.gsub(CONTROL, ' ')[0, LIMITS.fetch(key, 256)]
    when Hash
      value.each_with_object({}) do |(name, item), out|
        next if secret?(name) || item.nil?

        cleaned = clean(item, name.to_s)
        next if cleaned.is_a?(Hash) && cleaned.empty?

        out[name.to_s.gsub(CONTROL, ' ')[0, 128]] = cleaned
      end
    when Array then value.first(64).map { |item| clean(item) }
    else value
    end
  end

  # UTC, millisecond precision, Z suffix (ASVS 5.0 V16.2.2).
  def format_time(time) = time.utc.strftime('%Y-%m-%dT%H:%M:%S.%LZ')

  # spec keys (strings): eventType, eventCategory, eventAction, eventResult, eventSeverity,
  # reason, actor, target, sourceIp, userAgent, route, tenantId, request, labels, attributes, change.
  def build_event(app, spec, event_id: nil, now: Time.now)
    application = %w[name environment version instance].each_with_object({}) { |k, h| h[k] = app[k] if app[k] }
    application['tenantId'] = spec['tenantId'] if spec['tenantId']
    event = {
      'schemaVersion' => SCHEMA_VERSION, 'eventId' => event_id || SecureRandom.uuid, 'timeGenerated' => format_time(now),
      'eventCategory' => spec['eventCategory'], 'eventType' => spec['eventType'], 'eventAction' => spec['eventAction'],
      'eventResult' => spec['eventResult'], 'eventSeverity' => spec['eventSeverity'] || 'informational', 'application' => application
    }
    event['eventOutcomeReason'] = spec['reason'] if spec['reason']
    event['actor'] = spec['actor'].dup if spec['actor']
    event['target'] = spec['target'].dup if spec['target']
    event['source'] = { 'ipAddress' => spec['sourceIp'] } if spec['sourceIp']
    request = (spec['request'] || {}).dup
    request['path'] = request['path'].split(/[?#]/, 2).first if request['path']
    event['request'] = request unless request.empty?
    labels = (spec['labels'] || {}).dup
    labels['userAgent'] = spec['userAgent'] if spec['userAgent']
    labels['route'] = spec['route'] if spec['route']
    event['labels'] = labels.transform_values(&:to_s) unless labels.empty?
    event['attributes'] = spec['attributes'].dup if spec['attributes']
    change = (spec['change'] || {}).dup
    # Before and after values of settings and credentials never leave the process.
    change = change.key?('field') ? { 'field' => change['field'] } : {} if !change.empty? && spec['eventType'] != 'role_membership_changed'
    event['change'] = change unless change.empty?
    clean(event)
  end

  # Original client address (ASVS 5.0 V15.3.4, V4.1.3). X-Forwarded-For is read only when the
  # direct peer is a trusted proxy, right to left, skipping trusted hops.
  def client_ip(remote, forwarded_for, trusted_proxies)
    networks = trusted_proxies.map { |cidr| IPAddr.new(cidr) }
    trusted = lambda do |address|
      ip = IPAddr.new(address)
      networks.any? { |network| network.family == ip.family && network.include?(ip) }
    rescue IPAddr::Error
      false
    end
    return remote if forwarded_for.nil? || forwarded_for.empty? || !trusted.call(remote)

    hops = forwarded_for.split(',').map(&:strip).reject(&:empty?)
    hops.reverse_each do |hop|
      next if trusted.call(hop)

      begin
        return IPAddr.new(hop).to_s
      rescue IPAddr::Error
        return remote
      end
    end
    hops.first || remote
  end

  # Posts events to a Bower collector. Never raises into the request path.
  class Client
    def initialize(endpoint: ENV.fetch('BOWER_COLLECTOR_URL', 'http://127.0.0.1:4319'), token: ENV['BOWER_INGEST_TOKEN'], timeout: 2)
      @uri = URI.join(endpoint.end_with?('/') ? endpoint : "#{endpoint}/", 'v1/events')
      @token = token
      @timeout = timeout
    end

    def send_event(event)
      request = Net::HTTP::Post.new(@uri, 'Content-Type' => 'application/json')
      request['Authorization'] = "Bearer #{@token}" if @token && !@token.empty?
      request.body = JSON.generate(event)
      Net::HTTP.start(@uri.host, @uri.port, use_ssl: @uri.scheme == 'https', open_timeout: @timeout, read_timeout: @timeout) do |http|
        http.request(request).code.to_i
      end
    rescue StandardError
      nil
    end

    def send_async(event) = Thread.new { send_event(event) }
  end
end
