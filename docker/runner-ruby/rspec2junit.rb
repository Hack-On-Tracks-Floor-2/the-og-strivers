# Converts RSpec's JSON report into JUnit XML (one <testcase> per example).
require 'json'
data = JSON.parse(File.read(ARGV[0])) rescue { 'examples' => [] }
esc = ->(s) { s.to_s.gsub('&', '&amp;').gsub('<', '&lt;').gsub('>', '&gt;').gsub('"', '&quot;') }
puts '<testsuites><testsuite name="rspec">'
data.fetch('examples', []).each do |ex|
  body = case ex['status']
         when 'failed' then %(<failure message="#{esc.(ex.dig('exception', 'message'))}"/>)
         when 'pending' then '<skipped/>'
         else ''
         end
  puts %(<testcase classname="#{esc.(ex['file_path'])}" name="#{esc.(ex['full_description'])}">#{body}</testcase>)
end
puts '</testsuite></testsuites>'
