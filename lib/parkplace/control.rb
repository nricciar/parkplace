require 'parkplace/mimetypes_hash'

class Class
  def login_required
    include ParkPlace::UserSession, ParkPlace::Control
  end
end

module ParkPlace::Controllers

  class CHome < R '/control'
    login_required
    def get
      ParkPlace::Base.redirect CBuckets
    end
  end

  class CLogin < R '/control/login'
    include ParkPlace::Control
    def get
      [200, {}, render(:control, "Login", :login)]
    end
    def post
      @login = true
      @user = Models::User.find_by_login @input['login']
      if @user
	if @user.password == hmac_sha1( @input['password'], @user.secret )
	  @state.user_id = @user.id
	  ParkPlace::Base.redirect(CBuckets) {
            cookie_data = Base64.encode64(Marshal.dump(@state))
            { 'Set-Cookie' => "parkplace=" + ParkPlace::Base.escape("#{OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA1.new,
              ParkPlace::Base.options.secret, cookie_data)}--#{cookie_data}") }
          }
	else
	  @user.errors.add(:password, 'is incorrect')
	end
      else
	@user = Models::User.new
	@user.errors.add(:login, 'not found')
      end
      [200, {}, render(:control, "Login", :login)]
    end
  end

  class CLogout < R '/control/logout'
    login_required
    def get
      @state.user_id = nil
      ParkPlace::Base.redirect(CHome) { {  'Set-Cookie' => "parkplace=;expires=#{1.hour.ago.httpdate}" } }
    end
  end

  class CBuckets < R '/control/buckets'
    login_required
    def load_buckets
      @buckets = Models::Bucket.find_by_sql [%{
	       SELECT b.*, COUNT(c.id) AS total_children
	       FROM parkplace_bits b LEFT JOIN parkplace_bits c 
			ON c.parent_id = b.id AND c.deleted = 0
	       WHERE b.deleted = 0 AND b.parent_id IS NULL AND b.owner_id = ?
	       GROUP BY b.id ORDER BY b.name}, @user.id]
	       @bucket = Models::Bucket.new(:owner_id => @user.id, :access => CANNED_ACLS['private'])
    end
    def get
      load_buckets
      [200, {}, render(:control, 'Your Buckets', :buckets)]
    end
    def post
      Models::Bucket.find_root(@input['bucket']['name'])
      load_buckets
      @bucket.errors.add_to_base("A bucket named `#{@input['bucket']['name']}' already exists.")
      [200, {}, render(:control, 'Your Buckets', :buckets)]
    rescue NoSuchBucket
      bucket = Models::Bucket.new(@input['bucket'])
      if bucket.save()
	ParkPlace::Base.redirect CBuckets
      else
	load_buckets
	@bucket.errors.add_to_base("Invalid bucket name.")
	[200, {}, render(:control, 'Your Buckets', :buckets)]
      end
    end
  end

  class CBucketVersioning < R '/control/buckets/([^\/]+)/versioning'
    login_required
    def post(bucket_name)
      @bucket = Models::Bucket.find_root(bucket_name)
      only_can_write bucket
      @bucket.git_init if defined?(Git)
      ParkPlace::Base.redirect CFiles, @bucket.name
    end
  end

  class CFiles < R '/control/buckets/([^\/]+)'
    login_required
    def get(bucket_name)
      @bucket = Models::Bucket.find_root(bucket_name)
      only_can_read @bucket
      @files = Models::Slot.find :all, :include => :torrent, 
	:conditions => ['deleted = 0 AND parent_id = ?', @bucket.id], :order => 'name'
      [200, {}, render(:control, "/#{@bucket.name}", :files)]
    end
    def post(bucket_name)
      @bucket = Models::Bucket.find_root(bucket_name)
      only_can_write bucket

      if @input['upfile'].instance_of?(String)
	error "No file specified."
	@files = Models::Slot.find :all, :include => :torrent,
	  :conditions => ['deleted = 0 AND parent_id = ?', @bucket.id], :order => 'name'
	return ParkPlace::Base.redirect(CFiles, bucket.name)
      end

      tmpf = @input['upfile'][:tempfile]
      readlen, md5 = 0, MD5.new
      while part = tmpf.read(BUFSIZE)
	readlen += part.size
	md5 << part
      end
      fileinfo = Models::FileInfo.new
      fileinfo.mime_type = @input['upfile'][:type] || "binary/octet-stream"
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

      @input['fname'] = @input['upfile'][:filename] if @input['fname'].blank?
      begin
	slot = @bucket.find_slot(@input['fname'])
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
	slot = Models::Slot.create(:name => @input['fname'], :owner_id => @user.id, :meta => mdata, :obj => fileinfo)
	slot.grant(:access => @input['facl'].to_i)
	@bucket.add_child(slot)
      end

      if slot.versioning_enabled?
	begin
	  slot.git_repository.add(File.basename(fileinfo.path))
	  slot.git_repository.commit("Added #{slot.name} to the Git repository.")
	  slot.git_update
	rescue => err
	  puts "[#{Time.now}] GIT: #{err}" if ParkPlace::Base.options.verbose
	end
      end

      return ParkPlace::Base.redirect(CFiles, bucket_name)
    end
  end

  class CFile < R '/control/buckets/([^\/]+?)/(.+)'
    login_required
    include ParkPlace::SlotGet
  end

  class CDeleteBucket < R '/control/delete/([^\/]+)'
    login_required
    def post(bucket_name)
      bucket = Models::Bucket.find_root(bucket_name)
      only_owner_of bucket

      if Models::Slot.count(:conditions => ['deleted = 0 AND parent_id = ?', bucket.id]) > 0
	error "Bucket #{bucket.name} cannot be deleted, since it is not empty."
      else
	bucket.destroy
      end
      ParkPlace::Base.redirect CBuckets
    end
  end

  class CFileChanges < R '/control/changes/(.+?)/(.+)'
    login_required
    def get(bucket_name, oid)
      @bucket = Models::Bucket.find_root bucket_name
      @file = @bucket.find_slot(oid)
      only_owner_of @bucket
      @versions = @bucket.git_repository.log.path(File.basename(@file.obj.path))
      [200, {}, render(:popup, "Changes For #{@file.name}", :changes)]
    end
  end

  class CDeleteFile < R '/control/delete/(.+?)/(.+)'
    login_required
    def post(bucket_name, oid)
      bucket = Models::Bucket.find_root bucket_name
      only_can_write bucket
      slot = bucket.find_slot(oid)

      if slot.versioning_enabled?
	slot.git_repository.remove(File.basename(slot.obj.path))
	slot.git_repository.commit("Removed #{slot.name} from the Git repository.")
	slot.git_update
      end

      slot.destroy
      ParkPlace::Base.redirect CFiles, bucket_name
    end
  end

  class CSlaves < R '/control/slaves'
    login_required

    def get
      only_superusers
      @known_hosts = BackupManager.known_hosts
      @last_updated = Models::Bit.last_time_updated
      [200, {}, render(:control, "Network Status", :known_hosts)]
    end
  end

  class CUsers < R '/control/users'
    login_required
    def get
      only_superusers
      @usero = Models::User.new
      @users = Models::User.find :all, :conditions => ['deleted != 1'], :order => 'login'
      [200, {}, render(:control, "User List", :users)]
    end
    def post
      only_superusers
      @usero = Models::User.new @input['user'].merge(:activated_at => Time.now)
      if @usero.valid?
	@usero.save
	ParkPlace::Base.redirect CUsers
      else
	[200, {}, render(:control, "New User", :user)]
      end
    end
  end

  class CDeleteUser < R '/control/users/delete/(.+)'
    login_required
    def post(login)
      only_superusers
      @usero = Models::User.find_by_login login
      if @usero.id == @user.id
	error "Suicide is not an option."
      else
	@usero.destroy
      end
      ParkPlace::Base.redirect CUsers
    end
  end

  class CUser < R '/control/users/([^\/]+)'
    login_required
    def get(login)
      only_superusers
      @usero = Models::User.find_by_login login
      [200, {}, render(:control, "#{@usero.login}", :profile)]
    end
    def post(login)
      only_superusers
      @usero = Models::User.find_by_login login
      @usero.update_attributes(@input['user'])
      [200, {}, render(:control, "#{@usero.login}", :profile)]
    end
  end

  class CProgressIndex < R '/control/progress'
    def get
      Mongrel::Uploads.instance.instance_variable_get("@counters").inspect
    end
  end

  class CProgress < R '/control/progress/(.+)'
    def get(upid)
      params = Mongrel::Uploads.check(upid)
      return [200, {'Content-Type' => 'text/javascript'}, ["UploadProgress.update(#{params[:size]},#{params[:received]});"]] unless params.nil?
      [200, {'Content-Type' => 'text/javascript'}, ["UploadProgress.finish()"]]
    end
  end

  class CProfile < R '/control/profile'
    login_required
    def get
      @usero = @user
      [200, {}, render(:control, "Your Profile", :profile)]
    end
    def post
      @user.update_attributes(@input['user'])
      @usero = @user
      [200, {}, render(:control, "Your Profile", :profile)]
    end
  end

  class CStatic < R '/control/s/(.+)'
    def get(path)
      [200, { 'Content-Type' => (MIME_TYPES[path[/\.\w+$/, 0]] || "text/plain"), 'X-Sendfile' =>
	File.join(ParkPlace::STATIC_PATH, path) }, []]
    end
  end
end

module ParkPlace::Views

  include ParkPlace::Controllers

      def R(c,*g)
	      p,h=/\(.+?\)/,g.grep(Hash)
	            (g-=h).inject(c.urls.find{|x|x.scan(p).size==g.size}.dup){|s,a|
		              s.sub p,ParkPlace::Base.escape((a[a.class.primary_key]rescue a))
			            }+(h.any?? "?"+h[0].map{|x|x.map{|z|ParkPlace::Base.escape z}*"="}*"&": "")
				        end

  def control_tab(klass)
    opts = {:href => R(klass)}
    opts[:class] = (@env['PATH_INFO'] =~ /^#{opts[:href]}/ ? "active" : "inactive")
    opts
  end
  def popup(str, view)
    html do
      head do
	title { "Park Place Control Center &raquo; " + str }
	style "@import '/control/s/css/control.css';", :type => 'text/css'
      end
      body do
	div.content! do
	  __send__ "control_#{view}"
	end
      end
    end
  end

  def control(str, view)
    html do
      head do
	title { "Park Place Control Center &raquo; " + str }
	script :language => 'javascript', :src => '/control/s/js/prototype.js'
	script :language => 'javascript', :src => '/control/s/js/upload_status.js' if $PARKPLACE_PROGRESS
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
	  th "Info"
	  th "Actions"
	end
	tbody do
	  @buckets.each do |bucket|
	    tr do
	      th { 
		div { a bucket.name, :href => R(CFiles, bucket.name) }
	      }
	      td "#{bucket.total_children rescue 0} files"
	      td bucket.updated_at
	      td bucket.access_readable + (bucket.versioning_enabled? ? ",versioned" : "")
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
    errors_for @state
    p "Click on a file name to get file and torrent details."
    table do
      caption {
	if defined?(Git)
	  span(:style => "float:right") {
	    if !@bucket.versioning_enabled? 
	      a(:href=>R(CBucketVersioning,@bucket.name), :onClick => POST) { "Enable Versioning For This Bucket" }
	    else
	      "Versioning Enabled"
	    end
	  }
	end
      a(:href => R(CBuckets)) { self << "&larr; Buckets" } 
      }
      thead do
	th "File"
	th "Size"
	th "Permission"
      end
      tbody do
	if @files.empty?
	  tr { td(:colspan => "3", :style => "padding:15px;text-align:center") { "No Files" } }
	end
	@files.each do |file|
	  tr do
	    th do
	      a file.name, :href => "javascript://", :onclick => "$('details-#{file.id}').toggle()"
	      div.details :id => "details-#{file.id}", :style => "display:none" do
		p "Revision: #{file.git_object.objectish}" if @bucket.versioning_enabled?
		p "Last modified on #{file.updated_at}"
		if file.obj.mime_type =~ /audio/
		  object(:classid => "clsid:D27CDB6E-AE6D-11cf-96B8-444553540000", :codebase => "http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=6,0,0,0", :width => "165", :height => "38", :id => "nifty-player-#{file.id}") do
		  '<params name="movie" value="/control/s/media/niftyplayer.swf?file=' + R(CFile, @bucket.name, file.name) + '"><params name="bgcolor" value="#ffffff" /><embed src="/control/s/media/niftyplayer.swf?file=' + R(CFile, @bucket.name, file.name) + '" quality=high bgcolor=#FFFFFF width="165" height="38" name="niftyPlayer1" align="" type="application/x-shockwave-flash" pluginspage="http://www.macromedia.com/go/getflashplayer"></embed>'
		  end
		end
		p do
		  info = [a("Get", :target => "_blank", :href => R(CFile, @bucket.name, file.name))]
		  info += [a("Changes", :onclick => "window.open(this.href,'changelog','height=600,width=500');return false;", :href => R(CFileChanges,@bucket.name,file.name))] if @bucket.versioning_enabled?
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
    div :id => "results"
    div(:id => "progress-bar", :style => "display:none")
    iframe(:id => "upload", :name => "upload", :style => "display:none")
    @upid = Time.now.to_f
    form({ :action => "?upload_id=#{@upid}", :id => "upload-form", :method => 'post', :enctype => 'multipart/form-data', :class => 'create' }.merge(
      $PARKPLACE_PROGRESS ? { :onsubmit => "UploadProgress.monitor('#{@upid}')", :target => "upload" } : {} )) do
	h3 "Upload a File"
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

  def control_changes
    table do
      thead do
	th "Commit Log For #{@file.name}"
      end
      tbody do
	@versions.each do |version|
	  tr {
	    td { 
	    div { a(:target => "_blank", :href => R(CFile, @bucket.name, @file.name).to_s + "?version-id=#{version.sha}") { version.sha } }
	    div "On: #{version.date}"
	    div "By: #{version.author.name} <#{version.author.email}>"
	  }
	  }
	end
      end
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
