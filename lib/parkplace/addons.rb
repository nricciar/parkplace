begin
  require 'gem_plugin'
  gem 'mongrel_upload_progress'
  GemPlugin::Manager.instance.load "mongrel" => GemPlugin::INCLUDE
  require 'parkplace/upload_progress'
  Rack::Handler.register 'mongrel', 'Rack::Handler::MongrelUploadProgress'
  Rack::Handler.register 'mongrel_no_upload_progress', 'Rack::Handler::Mongrel'
rescue LoadError
  puts "-- Unable to load mongrel_upload_progress, no fancy upload progress."
end
begin
  require 'exifr'
  puts "-- EXIFR found, JPEG metadata enabled."
rescue LoadError
  puts "-- EXIFR not found, JPEG metadata disabled."
end
begin
  require "git"
  puts "-- Git support found, versioning support enabled."
rescue LoadError
  puts "-- Git support not found, versioning support disabled."
end
begin
  require 'parkplace/torrent'
  puts "-- RubyTorrent found, torrent support is turned on."
  puts "-- TORRENT SUPPORT IS EXTREMELY EXPERIMENTAL -- WHAT I MEAN IS: IT PROBABLY DOESN'T WORK."
rescue LoadError
  puts "-- No RubyTorrent found, torrent support disbled."
end
begin
  require 'memcache'
  memcache_options = {
    :c_threshold => 10_000,
    :compression => true,
    :debug => false,
    :namespace => 'parkplace',
    :readonly => false,
    :urlencode => false
  }
  CACHE = MemCache.new memcache_options
  puts "-- MemCache found, request cache enabled"
rescue LoadError
  puts "-- No MemCache found, no request cache"
end
