# Print the contract events and proxy results as JSON lines (see ../contract).
require 'json'
require_relative 'bower_events'

def sort_keys(value)
  case value
  when Hash then value.keys.sort.to_h { |k| [k, sort_keys(value[k])] }
  when Array then value.map { |v| sort_keys(v) }
  else value
  end
end

# Python's json.dumps(sort_keys=True) separators and ASCII escaping.
def py_json(value)
  JSON.generate(sort_keys(value)).gsub('":', '": ').gsub(',"', ', "')
end

cases = JSON.parse(File.read(ARGV[0]))
now = Time.iso8601(cases['now'])
cases['cases'].each { |c| puts py_json(BowerEvents.build_event(cases['app'], c['spec'], event_id: c['eventId'], now: now)) }
cases['proxyCases'].each { |c| puts py_json({ 'clientIp' => BowerEvents.client_ip(c['remote'], c['forwardedFor'], c['trusted']) }) }
