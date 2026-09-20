#!/usr/bin/env ruby
# 台帳の quote が lines の範囲から逐語で取れることを検証する。
# 「逐語」を約束ではなく検査済みの性質にするための唯一の仕掛け。
require 'yaml'
RFC_DIR = ARGV[1] or abort "usage: verify-quotes.rb <ledger.yaml> <rfc-dir>"
led = YAML.load_file(ARGV[0])
src = File.readlines(File.join(RFC_DIR, "clean-#{led['doc'].split.last}.txt"), chomp: true)
norm = ->(s) { s.gsub(/\s+/, ' ').strip }
fail_n = 0
led['entries'].each do |e|
  q = e['quote'] or next
  a, b = e['lines']
  body = norm.call(src[(a - 1)..(b - 1)].join(' '))
  if body.include?(norm.call(q))
    puts "  ok   #{e['id']}  L#{a}-#{b}"
  else
    fail_n += 1
    puts "  FAIL #{e['id']}  L#{a}-#{b}  quote が行範囲に逐語で存在しない"
    puts "       台帳: #{norm.call(q)[0, 100]}"
    puts "       原文: #{body[0, 100]}"
  end
end
puts "\n#{led['entries'].count { |e| e['quote'] }} 件の quote を検証 — 不一致 #{fail_n} 件"
exit(fail_n.zero? ? 0 : 1)
