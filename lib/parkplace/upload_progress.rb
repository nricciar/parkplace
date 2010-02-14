require 'mongrel'
require 'stringio'
require 'rack/content_length'
require 'rack/chunked'

class Upload < GemPlugin::Plugin "/handlers"
 
  private
    def upload_notify(action, params, *args)
      return unless !(params['PATH_INFO'] =~ /@path_info/) &&
        params[Mongrel::Const::REQUEST_METHOD] == 'POST' &&
        upload_id = Mongrel::HttpRequest.query_parse(params['QUERY_STRING'])['upload_id']
      if action == :mark
        last_checked_time = Mongrel::Uploads.last_checked(upload_id)
        return unless last_checked_time && Time.now - last_checked_time > @frequency
      end
      Mongrel::Uploads.send(action, upload_id, *args)
      Mongrel::Uploads.update_checked_time(upload_id) unless action == :finish
    end
 
end

UploadProgress = GemPlugin::Manager.instance.create('/handlers/upload', { :path_info => '\/control\/buckets\/(.+)' })

module Rack
  module Handler
    class MongrelUploadProgress < ::Mongrel::HttpHandler
      def self.run(app, options={})
        $PARKPLACE_PROGRESS = true
        server = ::Mongrel::HttpServer.new(
          options[:Host] || '0.0.0.0',
          options[:Port] || 8080,
          options[:num_processors] || 950,
          options[:throttle] || 0,
          options[:timeout] || 60)
        # Acts like Rack::URLMap, utilizing Mongrel's own path finding methods.
        # Use is similar to #run, replacing the app argument with a hash of
        # { path=>app, ... } or an instance of Rack::URLMap.
        if options[:map]
          if app.is_a? Hash
            app.each do |path, appl|
              path = '/'+path unless path[0] == ?/
              server.register(path, Rack::Handler::Mongrel.new(appl))
            end
          elsif app.is_a? URLMap
            app.instance_variable_get(:@mapping).each do |(host, path, appl)|
             next if !host.nil? && !options[:Host].nil? && options[:Host] != host
             path = '/'+path unless path[0] == ?/
             server.register(path, Rack::Handler::Mongrel.new(appl))
            end
          else
            raise ArgumentError, "first argument should be a Hash or URLMap"
          end
        else
          server.register('/', Rack::Handler::Mongrel.new(app))
        end
        server.register('/', UploadProgress,true)
        yield server if block_given?
        server.run.join
      end
 
      def initialize(app)
        @app = Rack::Chunked.new(Rack::ContentLength.new(app))
      end
 
      def process(request, response)
        env = {}.replace(request.params)
        env.delete "HTTP_CONTENT_TYPE"
        env.delete "HTTP_CONTENT_LENGTH"
 
        env["SCRIPT_NAME"] = "" if env["SCRIPT_NAME"] == "/"
 
        rack_input = request.body || StringIO.new('')
        rack_input.set_encoding(Encoding::BINARY) if rack_input.respond_to?(:set_encoding)
 
        env.update({"rack.version" => [1,1],
                     "rack.input" => rack_input,
                     "rack.errors" => $stderr,
 
                     "rack.multithread" => true,
                     "rack.multiprocess" => false, # ???
                     "rack.run_once" => false,
 
                     "rack.url_scheme" => "http",
                   })
        env["QUERY_STRING"] ||= ""
 
        status, headers, body = @app.call(env)
 
        begin
          response.status = status.to_i
          response.send_status(nil)
 
          headers.each { |k, vs|
            vs.split("\n").each { |v|
              response.header[k] = v
            }
          }
          response.send_header
 
          body.each { |part|
            response.write part
            response.socket.flush
          }
        ensure
          body.close if body.respond_to? :close
        end
      end
    end
  end
end
