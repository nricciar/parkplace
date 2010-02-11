require 'parkplace/mimetypes_hash'

class Class
    def login_required
        include Camping::Session, ParkPlace::UserSession, ParkPlace::Base, ParkPlace::S3
    end
end
class HashWithIndifferentAccess
 def self.self_and_descendants_from_active_record
   [self]
 end
 def self.human_attribute_name(attribute_key_name, options = {})
   defaults = self_and_descendants_from_active_record.map do |klass|
     "#{klass.name.underscore}.#{attribute_key_name}""#{klass.name.underscore}.#{attribute_key_name}"
   end
   defaults << options[:default] if options[:default]
   defaults.flatten!
   defaults << attribute_key_name.humanize
   options[:count] ||= 1
   I18n.translate(defaults.shift, options.merge(:default => defaults, :scope => [:activerecord, :attributes]))
 end
 def self.human_name(options = {})
   defaults = self_and_descendants_from_active_record.map do |klass|
     "#{klass.name.underscore}""#{klass.name.underscore}"
   end
   defaults << self.name.humanize
   I18n.translate(defaults.shift, {:scope => [:activerecord, :models], :count => 1, :default => defaults}.merge(options))
 end
end
module ParkPlace::UserSession
    def service(*a)
        if @state.user_id
            @user = ParkPlace::Models::User.find @state.user_id
        end
        @state.errors, @state.next_errors = @state.next_errors || [], nil
        if @user
            super(*a)
        else
            redirect Controllers::CLogin
        end
        self
    end
end

module ParkPlace::Controllers

    class CHome < R '/control'
        login_required
        def get
            redirect CBuckets
        end
    end

    class CLogin < R '/control/login'
        include Camping::Session, ParkPlace::Base
        def get
            render :control, "Login", :login
        end
        def post
            @login = true
            @user = User.find_by_login @input.login
            if @user
                if @user.password == hmac_sha1( @input.password, @user.secret )
                    @state.user_id = @user.id
                    return redirect(CBuckets)
                else
                    @user.errors.add(:password, 'is incorrect')
                end
            else
                @user = User.new
                @user.errors.add(:login, 'not found')
            end
            render :control, "Login", :login
        end
    end

    class CLogout < R '/control/logout'
        login_required
        def get
            @state.clear
            redirect CHome
        end
    end

    class CBuckets < R '/control/buckets'
        login_required
        def load_buckets
            @buckets = Bucket.find_by_sql [%{
               SELECT b.*, COUNT(c.id) AS total_children
               FROM parkplace_bits b LEFT JOIN parkplace_bits c 
                        ON c.parent_id = b.id AND c.deleted = 0
               WHERE b.deleted = 0 AND b.parent_id IS NULL AND b.owner_id = ?
               GROUP BY b.id ORDER BY b.name}, @user.id]
            @bucket = Bucket.new(:owner_id => @user.id, :access => CANNED_ACLS['private'])
        end
        def get
            load_buckets
            render :control, 'Your Buckets', :buckets
        end
        def post
            Bucket.find_root(@input.bucket.name)
            load_buckets
            @bucket.errors.add_to_base("A bucket named `#{@input.bucket.name}' already exists.")
            render :control, 'Your Buckets', :buckets
        rescue NoSuchBucket
            bucket = Bucket.create(@input.bucket)
            redirect CBuckets
        end
    end

    class CFiles < R '/control/buckets/([^\/]+)'
        login_required
        def get(bucket_name)
            @bucket = Bucket.find_root(bucket_name)
            only_can_read @bucket
            @files = Slot.find :all, :include => :torrent, 
              :conditions => ['deleted = 0 AND parent_id = ?', @bucket.id], :order => 'name'
            render :control, "/#{@bucket.name}", :files
        end
        def post(bucket_name)
            bucket = Bucket.find_root(bucket_name)
            only_can_write bucket

            tmpf = @input.upfile.tempfile
            readlen, md5 = 0, MD5.new
            while part = tmpf.read(BUFSIZE)
                readlen += part.size
                md5 << part
            end
            fileinfo = FileInfo.new
            fileinfo.mime_type = @input.upfile['type'] || "binary/octet-stream"
            fileinfo.size = readlen
            fileinfo.md5 = md5.hexdigest
            fileinfo.etag = '"' + md5.hexdigest + '"'

            mdata = {}
            if defined?(EXIFR) && fileinfo.mime_type =~ /jpg|jpeg/
              photo_data = EXIFR::JPEG.new(tmpf.path).to_hash
              photo_data.each_pair do |key,value|
                tmp = key.to_s.gsub(/[^a-z0-9]+/i, '-').downcase.gsub(/-$/,'')
                mdata[tmp] = value.to_s
              end
            end

            @input.fname = @input.upfile.filename if @input.fname.blank?
            begin
              slot = bucket.find_slot(@input.fname)
              fileinfo.path = slot.obj.path
              file_path = File.join(STORAGE_PATH,fileinfo.path)
              slot.update_attributes(:owner_id => @user.id, :meta => mdata, :obj => fileinfo)
              FileUtils.mv(tmpf.path, file_path,{ :force => true })
            rescue NoSuchKey
              fileinfo.path = File.join(bucket_name, rand(10000).to_s(36) + '_' + File.basename(tmpf.path))
              fileinfo.path.succ! while File.exists?(File.join(STORAGE_PATH, fileinfo.path))
              file_path = File.join(STORAGE_PATH,fileinfo.path)
              FileUtils.mkdir_p(File.dirname(file_path))
              FileUtils.mv(tmpf.path, file_path)
              slot = Slot.create(:name => @input.fname, :owner_id => @user.id, :meta => mdata, :obj => fileinfo)
              slot.grant(:access => @input.facl.to_i)
              bucket.add_child(slot)
            end

            if slot.versioning_enabled?
              slot.git_repository.add(File.basename(fileinfo.path))
              slot.git_repository.commit("Added #{slot.name} to the Git repository.")
            end

            redirect CFiles, bucket_name
        end
    end

    class CFile < R '/control/buckets/([^\/]+?)/(.+)'
        login_required
        include ParkPlace::SlotGet
    end

    class CDeleteBucket < R '/control/delete/([^\/]+)'
        login_required
        def post(bucket_name)
            bucket = Bucket.find_root(bucket_name)
            only_owner_of bucket

            if Slot.count(:conditions => ['deleted = 0 AND parent_id = ?', bucket.id]) > 0
                error "Bucket #{bucket.name} cannot be deleted, since it is not empty."
            else
                bucket.destroy
            end
            redirect CBuckets
        end
    end

    class CDeleteFile < R '/control/delete/(.+?)/(.+)'
        login_required
        def post(bucket_name, oid)
            bucket = Bucket.find_root bucket_name
            only_can_write bucket
            slot = bucket.find_slot(oid)

            if slot.versioning_enabled?
              slot.git_repository.remove(File.basename(slot.obj.path))
              slot.git_repository.commit("Removed #{slot.name} from the Git repository.")
            end

            slot.destroy
            redirect CFiles, bucket_name
        end
    end

    class CSlaves < R '/control/slaves'
      login_required

      def get
        only_superusers
        @known_hosts = BackupHandler.known_hosts
        @last_updated = Models::Bit.last_time_updated
        render :control, "Network Status", :known_hosts
      end
    end

    class CUsers < R '/control/users'
        login_required
        def get
            only_superusers
            @usero = User.new
            @users = User.find :all, :conditions => ['deleted != 1'], :order => 'login'
            render :control, "User List", :users
        end
        def post
            only_superusers
            @usero = User.new @input.user.merge(:activated_at => Time.now)
            if @usero.valid?
                @usero.save
                redirect CUsers
            else
                render :control, "New User", :user
            end
        end
    end

    class CDeleteUser < R '/control/users/delete/(.+)'
        login_required
        def post(login)
            only_superusers
            @usero = User.find_by_login login
            if @usero.id == @user.id
                error "Suicide is not an option."
            else
                @usero.destroy
            end
            redirect CUsers
        end
    end

    class CUser < R '/control/users/([^\/]+)'
        login_required
        def get(login)
            only_superusers
            @usero = User.find_by_login login
            render :control, "#{@usero.login}", :profile
        end
        def post(login)
            only_superusers
            @usero = User.find_by_login login
            @usero.update_attributes(@input.user)
            render :control, "#{@usero.login}", :profile
        end
    end

    class CProgressIndex < R '/control/progress'
        def get
            Mongrel::Uploads.instance.instance_variable_get("@counters").inspect
        end
    end

    class CProgress < R '/control/progress/(.+)'
        def get(upid)
            Mongrel::Uploads.instance.check(upid).inspect
        end
    end

    class CProfile < R '/control/profile'
        login_required
        def get
            @usero = @user
            render :control, "Your Profile", :profile
        end
        def post
            @user.update_attributes(@input.user)
            @usero = @user
            render :control, "Your Profile", :profile
        end
    end

    class CStatic < R '/control/s/(.+)'
        def get(path)
            @headers['Content-Type'] = MIME_TYPES[path[/\.\w+$/, 0]] || "text/plain"
            @headers['X-Sendfile'] = File.join(ParkPlace::STATIC_PATH, path)
        end
    end
end

module ParkPlace::Views
    def control_tab(klass)
        opts = {:href => R(klass)}
        opts[:class] = (@env.PATH_INFO =~ /^#{opts[:href]}/ ? "active" : "inactive")
        opts
    end
    def control(str, view)
        html do
            head do
                title { "Park Place Control Center &raquo; " + str }
                script :language => 'javascript', :src => '/control/s/js/jquery.js'
                # script :language => 'javascript', :src => R(CStatic, 'js/support.js')
                style "@import '/control/s/css/control.css';", :type => 'text/css'
            end
            body do
                div.page! do
                    if @user and not @login
                    div.menu do
                        ul do
                            li { a 'buckets', control_tab(CBuckets) }
                            li { a 'users',   control_tab(CUsers)   } if @user.superuser?
                            li { a 'slaves',   control_tab(CSlaves)   } if @user.superuser?
                            li { a 'profile', control_tab(CProfile) }
                            li { a 'logout',  control_tab(CLogout)  }
                        end
                    end
                    end
                    div.header! do
                        h1 "Park Place"
                        h2 str
                    end
                    div.content! do
                        __send__ "control_#{view}"
                    end
                end
            end
        end
    end

    def control_login
        control_loginform
    end

    def control_loginform
        form :method => 'post', :class => 'create' do
            errors_for @user if @user
            div.required do
                label 'User', :for => 'login'
                input.login! :type => 'text'
            end
            div.required do
                label 'Password', :for => 'password'
                input.password! :type => 'password'
            end
            input.loggo! :type => 'submit', :value => "Login"
        end
    end

    def control_buckets
        errors_for @state
        if @buckets.any?
            table do
                thead do
                    th "Name"
                    th "Contains"
                    th "Updated on"
                    th "Permission"
                    th "Actions"
                end
                tbody do
                    @buckets.each do |bucket|
                        tr do
                            th { 
                              div { a bucket.name, :href => R(CFiles, bucket.name) }
                              div { i { small { "Versioning Enabled" } } } if bucket.versioning_enabled?
                            }
                            td "#{bucket.total_children rescue 0} files"
                            td bucket.updated_at
                            td bucket.access_readable
                            td { a "Delete", :href => R(CDeleteBucket, bucket.name), :onClick => POST, :title => "Delete bucket #{bucket.name}" }
                        end
                    end
                end
            end
        else
            p "A sad day.  You have no buckets yet."
        end
        h3 "Create a Bucket"
        form :method => 'post', :class => 'create' do
            errors_for @bucket
            input :name => 'bucket[owner_id]', :type => 'hidden', :value => @bucket.owner_id
            div.required do
                label 'Bucket Name', :for => 'bucket[name]'
                input :name => 'bucket[name]', :type => 'text', :value => @bucket.name
            end
            div.required do
                label 'Permissions', :for => 'bucket[access]'
                select :name => 'bucket[access]' do
                    ParkPlace::CANNED_ACLS.sort.each do |acl, perm|
                        opts = {:value => perm}
                        opts[:selected] = true if perm == @bucket.access
                        option acl, opts
                    end
                end
            end
            input.newbucket! :type => 'submit', :value => "Create"
        end
    end

    def control_files
        p "Click on a file name to get file and torrent details."
        table do
            caption { a(:href => R(CBuckets)) { self << "&larr; Buckets" } }
            thead do
                th "File"
                th "Size"
                th "Permission"
            end
            tbody do
                @files.each do |file|
                    tr do
                        th do
                            a file.name, :href => "javascript://", :onclick => "$('#details-#{file.id}').toggle()"
                            div.details :id => "details-#{file.id}" do
                                p "Last modified on #{file.updated_at}"
                                p do
                                    info = [a("Get", :href => R(CFile, @bucket.name, file.name))]
                                    info += [a("Torrent", :href => R(RSlot, @bucket.name, file.name) + "?torrent")]
                                    if file.torrent
                                        info += ["#{file.torrent.seeders} seeders", 
                                            "#{file.torrent.leechers} leechers",
                                            "#{file.torrent.total} downloads"]
                                    end
                                    info += [a("Delete", :href => R(CDeleteFile, @bucket.name, file.name), 
                                               :onClick => POST, :title => "Delete file #{file.name}")]
                                    info.join " &bull; "
                                end
                            end
                        end
                        td number_to_human_size(file.obj.size)
                        td file.access_readable
                    end
                end
            end
        end
        h3 "Upload a File"
        form :action => "?upload_id=#{Time.now.to_f}", :method => 'post', :enctype => 'multipart/form-data', :class => 'create' do
            div.required do
                input :name => 'upfile', :type => 'file'
            end
            div.optional do
                label 'File Name', :for => 'fname'
                input :name => 'fname', :type => 'text'
            end
            div.required do
                label 'Permissions', :for => 'facl'
                select :name => 'facl' do
                    ParkPlace::CANNED_ACLS.sort.each do |acl, perm|
                        opts = {:value => perm}
                        opts[:selected] = true if perm == @bucket.access
                        option acl, opts
                    end
                end
            end
            input.newfile! :type => 'submit', :value => "Create"
        end
    end

    def control_known_hosts
        table do
            thead do
                th "Host"
                th "Last Sync"
                th "Last Version"
            end
            tbody do
              @known_hosts.each_pair do |key,value|
                tr do
                  th do
                    key
                  end
                  th do
                    div :style => (10.minutes.ago > value[:last_check_in] ? "color:#660000" : "color:#006600") do
                      value[:last_check_in]
                    end
                  end
                  th do
                    div :style => (@last_updated.to_i == value[:last_known_version].to_i ? "color:#006600" : "color:#660000") do
                      value[:last_known_version]
                    end
                  end
                end
              end
            end
        end
    end

    def control_user
        control_userform
    end

    def control_userform
        form :action => R(CUsers), :method => 'post', :class => 'create' do
            errors_for @usero
            div.required do
                label 'Login', :for => 'user[login]'
                input.large :name => 'user[login]', :type => 'text', :value => @usero.login
            end
            div.required.inline do
                label 'Is a super-admin? ', :for => 'user[superuser]'
                checkbox 'user[superuser]', @usero.superuser
            end
            div.required do
                label 'Password', :for => 'user[password]'
                input.fixed :name => 'user[password]', :type => 'password'
            end
            div.required do
                label 'Password again', :for => 'user[password_confirmation]'
                input.fixed :name => 'user[password_confirmation]', :type => 'password'
            end
            div.required do
                label 'Email', :for => 'user[email]'
                input :name => 'user[email]', :type => 'text', :value => @usero.email
            end
            div.required do
                label 'Key (must be unique)', :for => 'user[key]'
                input.fixed.long :name => 'user[key]', :type => 'text', :value => @usero.key || generate_key
            end
            div.required do
                label 'Secret', :for => 'user[secret]'
                input.fixed.long :name => 'user[secret]', :type => 'text', :value => @usero.secret || generate_secret
            end
            input.newuser! :type => 'submit', :value => "Create"
        end
    end

    def control_users
        errors_for @state
        table do
            thead do
                th "Login"
                th "Activated on"
                th "Actions"
            end
            tbody do
                @users.each do |user|
                    tr do
                        th { a user.login, :href => R(CUser, user.login) }
                        td user.activated_at
                        td { a "Delete", :href => R(CDeleteUser, user.login), :onClick => POST, :title => "Delete user #{user.login}" }
                    end
                end
            end
        end
        h3 "Create a User"
        control_userform
    end

    def control_profile
        form :method => 'post', :class => 'create' do
            errors_for @usero
            if @user.superuser?
                div.required.inline do
                    label 'Is a super-admin? ', :for => 'user[superuser]'
                    checkbox 'user[superuser]', @usero.superuser
                end
            end
            div.required do
                label 'Password', :for => 'user[password]'
                input.fixed :name => 'user[password]', :type => 'password'
            end
            div.required do
                label 'Password again', :for => 'user[password_confirmation]'
                input.fixed :name => 'user[password_confirmation]', :type => 'password'
            end
            div.required do
                label 'Email', :for => 'user[email]'
                input :name => 'user[email]', :type => 'text', :value => @usero.email
            end
            div.required do
                label 'Key', :for => 'key'
                h4 @usero.key
            end
            div.required do
                label 'Secret', :for => 'secret'
                h4 @usero.secret
            end
            input.newfile! :type => 'submit', :value => "Save"
            # input.regen! :type => 'submit', :value => "Generate New Keys"
        end
    end

    def number_to_human_size(size)
      case 
        when size < 1.kilobyte: '%d Bytes' % size
        when size < 1.megabyte: '%.1f KB'  % (size / 1.0.kilobyte)
        when size < 1.gigabyte: '%.1f MB'  % (size / 1.0.megabyte)
        when size < 1.terabyte: '%.1f GB'  % (size / 1.0.gigabyte)
        else                    '%.1f TB'  % (size / 1.0.terabyte)
      end.sub('.0', '')
    rescue
      nil
    end

    def checkbox(name, value)
        opts = {:name => name, :type => 'checkbox', :value => 1}
        opts[:checked] = "true" if value.to_i == 1
        input opts
    end

end
