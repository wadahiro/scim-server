#!/usr/bin/env ruby
# 台帳の quote が lines の範囲から逐語で取れることを検証する。
# 「逐語」を約束ではなく検査済みの性質にするための唯一の仕掛け。
#
# `lines` は生ファイル（spec/rfc/<doc>.txt、無改変で同梱されたもの）の行番号
# (tools/prototype/relocate_ledger.py が clean-*.txt からの行範囲をここへ
# 変換済み)。よってここではページ furniture（ヘッダ/フッタ行・フォームフィード
# を含む行）を範囲から除いたうえで比較する — clean-*.txt は参照しない。
require 'yaml'
RFC_DIR = ARGV[1] or abort "usage: verify-quotes.rb <ledger.yaml> <rfc-dir>"
led = YAML.load_file(ARGV[0])
FURNITURE = /^(RFC \d+\s|Hunt,|.*\[Page \d+\]\s*$)/
src = File.readlines(File.join(RFC_DIR, "#{led['doc'].downcase.gsub(' ', '')}.txt"), chomp: true)
norm = ->(s) { s.gsub(/\s+/, ' ').strip }
furniture = ->(l) { l =~ FURNITURE || l.include?("\f") }
fail_n = 0
led['entries'].each do |e|
  q = e['quote'] or next
  a, b = e['lines']
  span = src[(a - 1)..(b - 1)].reject { |l| furniture.call(l) }
  body = norm.call(span.join(' '))
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
