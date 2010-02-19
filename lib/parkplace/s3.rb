module ParkPlace::Controllers

  class RService < S3 '/'
    def get
      only_authorized
      buckets = Models::Bucket.find :all, :conditions => ['parent_id IS NULL AND owner_id = ?', @user.id], :order => "name"

      xml do |x|
        x.ListAllMyBucketsResult :xmlns => "http://s3.amazonaws.com/doc/2006-03-01/" do
          x.Owner do
            x.ID @user.key
            x.DisplayName @user.login
          end
          x.Buckets do
            buckets.each do |b|
              x.Bucket do
                x.Name b.name
                x.CreationDate b.created_at.getgm.iso8601
              end
            end
          end
        end
      end
    end
  end

  class RBucket < S3 '/([^\/]+)/?'

    include ParkPlace::S3

    def put(bucket_name)
      only_authorized
      bucket = Models::Bucket.find_root(bucket_name)
      only_owner_of bucket
      bucket.grant(requested_acl(bucket))
      [200, { 'Location' => @env['PATH_INFO'], 'Content-Length' => 0.to_s}, []]
    rescue NoSuchBucket
      Models::Bucket.create(:name => bucket_name, :owner_id => @user.id).grant(requested_acl)
      [200, { 'Location' => @env['PATH_INFO'], 'Content-Length' => 0.to_s}, []]
    end
    def delete(bucket_name)
      bucket = Models::Bucket.find_root(bucket_name)
      only_owner_of bucket

      if Models::Slot.count(:conditions => ['deleted = 0 AND parent_id = ?', bucket.id]) > 0
        raise BucketNotEmpty
      end
      bucket.destroy
      [204, { }, [ ]]
    end
    def get(bucket_name)
      bucket = Models::Bucket.find_root(bucket_name)
      if @input.has_key? 'versioning'
        return versioning_response_for(bucket)
      elsif @input.has_key? 'acl'
        only_can_read_acp bucket
        return acl_response_for(bucket)
      else
        only_can_read bucket
      end

      if @input.has_key? 'torrent'
        return torrent(bucket)
      end

      # Patch from Alan Wootton -- used to be ticket 12 in Trac:
      #   Let's be more like amazon and always have these 3 things
      @input['max-keys'] = 1000 unless @input['max-keys']
      @input['marker'] = '' unless @input['marker']
      @input['prefix'] = '' unless @input['prefix']

      opts = {:conditions => ['deleted = 0 AND parent_id = ?', bucket.id], :order => "name", :include => :owner}

      if @input['prefix'] && @input['prefix'].length > 0
        opts[:conditions].first << ' AND name LIKE ?'
        opts[:conditions] << "#{@input['prefix']}%"
      end
      opts[:offset] = 0
      if @input['marker'] && @input['marker'].length > 0
        opts[:conditions].first << ' AND name > ?'
        opts[:conditions] << "#{@input['marker']}"
      end
      if @input['max-keys']
        opts[:limit] = @input['max-keys'].to_i
      end
      slot_count = Models::Slot.count :conditions => opts[:conditions]
      contents = Models::Slot.find :all, opts

      if @input['delimiter']
        @input['prefix'] = '' if @input['prefix'].nil?

        # Build a hash of { :prefix => content_key }. The prefix will not include the supplied @input.prefix.
        prefixes = contents.inject({}) do |hash, c|
          prefix = get_prefix(c).to_sym
          hash[prefix] = [] unless hash[prefix]
          hash[prefix] << c.name
          hash
        end

        # The common prefixes are those with more than one element
        common_prefixes = prefixes.inject([]) do |array, prefix|
          array << prefix[0].to_s if prefix[1].size > 1
          array
        end

        # The contents are everything that doesn't have a common prefix
        contents = contents.reject do |c|
          common_prefixes.include? get_prefix(c)
        end
      end

      xml do |x|
        x.ListBucketResult :xmlns => "http://s3.amazonaws.com/doc/2006-03-01/" do
          x.Name bucket.name
          x.Prefix @input['prefix'] if @input['prefix']
          x.Marker @input['marker'] if @input['marker']
          x.Delimiter @input['delimiter'] if @input['delimiter']
          x.MaxKeys @input['max-keys'] if @input['max-keys']
          x.IsTruncated slot_count > contents.length + opts[:offset].to_i
          contents.each do |c|
            x.Contents do
              x.Key c.name
              x.LastModified c.updated_at.getgm.iso8601
              x.ETag c.etag
              x.Size c.obj.size
              x.StorageClass "STANDARD"
              x.Owner do
                x.ID c.owner.key
                x.DisplayName c.owner.login
              end
            end
          end
          if common_prefixes
            common_prefixes.each do |p|
              x.CommonPrefixes do
                x.Prefix p
              end
            end
          end
        end
      end
    end

    private
    def get_prefix(c)
      c.name.sub(@input.prefix, '').split(@input.delimiter)[0] + @input.delimiter
    end
  end

  class GitRepo < S3 '/(.+?).git/(.+)'
    def get(bucket_name,oid)
      # if they have authenticated with the backup manager
      # allow access
      check_host = @env['HTTP_X_FORWARDED_FOR'].nil? ? @env['REMOTE_ADDR'] : @env['HTTP_X_FORWARDED_FOR']
      unless ParkPlace::BackupManager.known_hosts.nil? || ParkPlace::BackupManager.known_hosts[check_host].nil?
        @bucket = Models::Bucket.find_root bucket_name
        unless @bucket.git_repository_path.nil? || !File.exists?(File.join(@bucket.git_repository_path,'.git',oid))
          [200, { 'Content-Type' => 'binary/octet-stream' }, File.open(File.join(@bucket.fullpath,'.git',oid))]
        end
      else
        raise AccessDenied
      end
    end
  end

  class RSlot < S3 '/(.+?)/(.+)'

    include ParkPlace::S3, ParkPlace::SlotGet

    def put(bucket_name, oid)
      bucket = Models::Bucket.find_root bucket_name
      only_can_write bucket

      raise MissingContentLength unless @env['HTTP_CONTENT_LENGTH']

      if @env['HTTP_X_AMZ_COPY_SOURCE'].to_s =~ /\/(.+?)\/(.+)/
        source_bucket_name = $1
        source_oid = $2

        source_slot = Models::Bucket.find_root(source_bucket_name).find_slot(source_oid)
        @meta = source_slot.meta
        only_can_read source_slot

        temp_path = File.join(STORAGE_PATH, source_slot.obj.path)
        fileinfo = source_slot.obj
        fileinfo.path = File.join(bucket_name, rand(10000).to_s(36) + '_' + File.basename(temp_path))
        fileinfo.path.succ! while File.exists?(File.join(STORAGE_PATH, fileinfo.path))
        file_path = File.join(STORAGE_PATH,fileinfo.path)
      else
        temp_path = @env['rack.input'][:path] rescue nil
        readlen = 0
        md5 = MD5.new

        Tempfile.open(File.basename(oid)) do |tmpf|
          temp_path ||= tmpf.path
          tmpf.binmode
          while part = @env['rack.input'].read(BUFSIZE)
            readlen += part.size
            md5 << part
            tmpf << part unless @env['rack.input'].is_a?(Tempfile)
          end
        end

        fileinfo = Models::FileInfo.new
        fileinfo.mime_type = @env['HTTP_CONTENT_TYPE'] || "binary/octet-stream"
        fileinfo.disposition = @env['HTTP_CONTENT_DISPOSITION']
        fileinfo.size = readlen 
        fileinfo.md5 = Base64.encode64(md5.digest).strip
        fileinfo.etag = '"' + md5.hexdigest + '"'

        raise IncompleteBody if @env['HTTP_CONTENT_LENGTH'].to_i != readlen
        if @env['HTTP_CONTENT_MD5']
          b64cs = /[0-9a-zA-Z+\/]/
            re = /
            ^
          (?:#{b64cs}{4})*       # any four legal chars
            (?:#{b64cs}{2}        # right-padded by up to two =s
             (?:#{b64cs}|=){2})?
             $
          /ox

          raise InvalidDigest unless @env['HTTP_CONTENT_MD5'] =~ re
          raise BadDigest unless fileinfo.md5 == @env['HTTP_CONTENT_MD5']
        end

      end

      mdata = {}
      if defined?(EXIFR) && fileinfo.mime_type =~ /jpg|jpeg/
        photo_data = EXIFR::JPEG.new(temp_path).to_hash
        photo_data.each_pair do |key,value|
          tmp = key.to_s.gsub(/[^a-z0-9]+/i, '-').downcase.gsub(/-$/,'')
          mdata[tmp] = value.to_s
        end
        @meta.nil? || @meta.empty? ? mdata : @meta.merge(mdata)
      end

      slot = nil
      meta = @meta.nil? || @meta.empty? ? nil : {}.merge(@meta)
      owner_id = @user ? @user.id : bucket.owner_id

      begin
        slot = bucket.find_slot(oid)
        if source_slot.nil?
          fileinfo.path = slot.obj.path
          file_path = File.join(STORAGE_PATH,fileinfo.path)
          FileUtils.mv(temp_path, file_path,{ :force => true })
        else
          FileUtils.cp(temp_path, file_path)
        end
        slot.update_attributes(:owner_id => owner_id, :meta => meta, :obj => fileinfo)
      rescue NoSuchKey
        if source_slot.nil?
          fileinfo.path = File.join(bucket_name, rand(10000).to_s(36) + '_' + File.basename(temp_path))
          fileinfo.path.succ! while File.exists?(File.join(STORAGE_PATH, fileinfo.path))
          file_path = File.join(STORAGE_PATH,fileinfo.path)
          FileUtils.mkdir_p(File.dirname(file_path))
          FileUtils.mv(temp_path, file_path)
        else
          FileUtils.cp(temp_path, file_path)
        end
        slot = Models::Slot.create(:name => oid, :owner_id => owner_id, :meta => meta, :obj => fileinfo)
        bucket.add_child(slot)
      end
      slot.grant(requested_acl(slot))

      headers = {}
      if slot.versioning_enabled?
        begin
          slot.git_repository.add(File.basename(fileinfo.path))
          tmp = slot.git_repository.commit("Added #{slot.name} to the Git repository.")
          slot.git_update
          headers['x-amz-version-id'] = slot.git_object.objectish
        rescue Git::GitExecuteError => error_message
          puts "[#{Time.now}] GIT: #{error_message}" if ParkPlace::Base.options.verbose
        end
      end

      [200, headers.merge({ 'ETag' => slot.etag, 'Content-Length' => 0.to_s }), []]
    end
    def delete(bucket_name, oid)
      bucket = Models::Bucket.find_root bucket_name
      only_can_write bucket
      @slot = bucket.find_slot(oid)

      if @slot.versioning_enabled?
        begin
          @slot.git_repository.remove(File.basename(@slot.obj.path))
          @slot.git_repository.commit("Removed #{@slot.name} from the Git repository.")
          @slot.git_update
        rescue Git::GitExecuteError => error_message
          puts "[#{Time.now}] GIT: #{error_message}" if ParkPlace::Base.options.verbose
        end
      end

      @slot.destroy
      [204, { }, [ ]]
    rescue NoSuchKey
      [204, { }, [ ]]
    end
  end
end
