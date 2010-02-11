require 'mongrel'
require 'parkplace/thread_pool'

module ParkPlace

class BackupHandler < Mongrel::HttpHandler

  @@known_hosts = {}

  def self.known_hosts
    @@known_hosts
  end

  def process(request, response)
    if request.params["HTTP_AUTHORIZATION"].nil?
      response.start(401) do |head,out|
        out << "Access Denied"
      end
      return
    else
      username,key = request.params["HTTP_AUTHORIZATION"].split(":")
      user = Models::User.find_by_sql [%{ SELECT * FROM parkplace_users WHERE login = ?}, username ]
      if user.empty? || !user.first.superuser? || MD5.md5("#{user.first.secret}:#{request.params['REQUEST_URI']}:#{request.params['HTTP_IF_MODIFIED_SINCE']}").hexdigest != key
        response.start(401) do |head,out|
          out << "Access Denied"
        end
        return
      end
    end
    response.start(200) do |head,out|
      # serve up files to the backup server
      # needs to be fixed
      if request.params["REQUEST_URI"] =~ /^\/backup\/([0-9]+)$/
        @slot = Models::Bit.find_by_sql [%{ SELECT * FROM parkplace_bits WHERE id = ?}, $1.to_i ]
        unless @slot.empty?
          @slot = @slot.first
          if @slot.obj.is_a? ParkPlace::Models::FileInfo
            head['Content-Type'] = @slot.obj.mime_type
          end
          file_path = File.join(STORAGE_PATH, @slot.obj.path)
          out << File.open(file_path) { |f| f.read }
        end
      else

      slave_host = request.params['HTTP_X_FORWARDED_FOR'].nil? ? request.params['REMOTE_ADDR'] : request.params['HTTP_X_FORWARDED_FOR']
      @@known_hosts[slave_host.to_s] = {
        :last_check_in => Time.now,
        :last_known_version => request.params["HTTP_IF_MODIFIED_SINCE"].to_i
      }

      head['Content-Type'] = "text/plain"

      if request.params["HTTP_IF_MODIFIED_SINCE"]
            sc = 0
            @bits = []
            # we will hold the connection open for 60 seconds
            # polling for any updates if somthing comes up we
            # send it off immedietly and close the connection
            while sc <= 60 && Models::Bit.last_time_updated == request.params["HTTP_IF_MODIFIED_SINCE"].to_i
              @@known_hosts[slave_host.to_s][:status] = "ok"
              sleep 2
              sc += 1
            end
            if Models::Bit.last_time_updated > request.params["HTTP_IF_MODIFIED_SINCE"].to_i
              puts "[#{Time.now}] Pushing new updates to #{slave_host}"
              @@known_hosts[slave_host.to_s][:status] = "out of sync"
              conditions = [ 'updated_at > ?', Time.at(request.params["HTTP_IF_MODIFIED_SINCE"].to_i) ]
              @bits = Models::Bit.find(:all, :conditions => conditions, :order => "updated_at ASC", :limit => 25, :include => :bits_users)
              @bits += Models::User.find(:all, :conditions => conditions, :order => "updated_at ASC", :limit => 25)
            end
          else
            puts "Initial slave update for #{slave_host}"
            @bits = Models::Bit.find(:all, :order => "updated_at ASC", :limit => 25, :include => :bits_users)
            @bits += Models::User.find(:all, :order => "updated_at ASC", :limit => 25)
          end
          if @bits.empty?
            head['Last-Modified'] = Models::Bit.last_time_updated
            out << Marshal.dump([])
          else
            head['Last-Modified'] = @bits.last.updated_at.to_i
            @bits.sort! { |x,y| x.updated_at <=> y.updated_at }
            out << Marshal.dump(@bits)
          end
      end
    end
  end
end

end
