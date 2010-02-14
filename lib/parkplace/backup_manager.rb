require 'parkplace/thread_pool'

module ParkPlace

class BackupManager

  @@known_hosts = {}

  def self.known_hosts
    @@known_hosts
  end

  def call(env)
    head = { 'Content-Type' => 'text/html' }
    slave_host = env['HTTP_X_FORWARDED_FOR'].nil? ? env['REMOTE_ADDR'] : env['HTTP_X_FORWARDED_FOR']
    if env["HTTP_AUTHORIZATION"].nil?
      puts "[#{Time.now}] Unauthorized access to /backup from #{slave_host}" if ParkPlace.options.verbose
      return [401, head, "Access Denied"]
    else
      username,key = env["HTTP_AUTHORIZATION"].split(":")
      user = Models::User.find_by_sql [%{ SELECT * FROM parkplace_users WHERE login = ?}, username ]
      if user.empty? || !user.first.superuser? || MD5.md5("#{user.first.secret}:#{env['REQUEST_URI']}:#{env['HTTP_IF_MODIFIED_SINCE']}").hexdigest != key
        puts "[#{Time.now}] Failed authentication for user #{username} from #{slave_host}" if ParkPlace.options.verbose
        return [401, head, "Access Denied"]
      end
    end
    if env["REQUEST_URI"] =~ /^\/backup\/([0-9]+)$/
      @slot = Models::Bit.find_by_sql [%{ SELECT * FROM parkplace_bits WHERE id = ?}, $1.to_i ]
      unless @slot.empty?
        @slot = @slot.first
        file_path = File.join(STORAGE_PATH, @slot.obj.path)
        head['Content-Type'] = @slot.obj.mime_type if @slot.obj.is_a? ParkPlace::Models::FileInfo
        head['X-Sendfile'] = file_path
        return [200, head, []]
      end
    else
      @@known_hosts[slave_host.to_s] = {
        :last_check_in => Time.now,
        :last_known_version => env["HTTP_IF_MODIFIED_SINCE"].to_i
      }

      head['Content-Type'] = "text/plain"

      if env["HTTP_IF_MODIFIED_SINCE"]
        sc = 0
        @bits = []
        # we will hold the connection open for 60 seconds
        # polling for any updates if somthing comes up we
        # send it off immedietly and close the connection
        while sc <= 60 && Models::Bit.last_time_updated == env["HTTP_IF_MODIFIED_SINCE"].to_i
          @@known_hosts[slave_host.to_s][:status] = "ok"
          sleep 2
          sc += 1
        end
        if Models::Bit.last_time_updated > env["HTTP_IF_MODIFIED_SINCE"].to_i
          puts "[#{Time.now}] Pushing new updates to #{slave_host}" if ParkPlace.options.verbose
          @@known_hosts[slave_host.to_s][:status] = "out of sync"
          conditions = [ 'updated_at > ?', Time.at(env["HTTP_IF_MODIFIED_SINCE"].to_i) ]
          @bits = Models::Bit.find(:all, :conditions => conditions, :order => "updated_at ASC", :limit => 25, :include => :bits_users)
          @bits += Models::User.find(:all, :conditions => conditions, :order => "updated_at ASC", :limit => 25)
        end
      else
        puts "[#{Time.now}] Initial slave update for #{slave_host}" if ParkPlace.options.verbose
        @bits = Models::Bit.find(:all, :order => "updated_at ASC", :limit => 25, :include => :bits_users)
        @bits += Models::User.find(:all, :order => "updated_at ASC", :limit => 25)
      end
      if @bits.empty?
        head['Last-Modified'] = Models::Bit.last_time_updated.to_s
      else
        head['Last-Modified'] = @bits.last.updated_at.to_i.to_s
        @bits.sort! { |x,y| x.updated_at <=> y.updated_at }
      end
      puts "[#{Time.now}] #{slave_host} requested resource #{env["REQUEST_URI"]}" if ParkPlace.options.verbose
      [200, head, Marshal.dump(@bits)]
    end
  end
end

end
