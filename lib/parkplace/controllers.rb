require 'fileutils'

module ParkPlace
    module SlotGet
        def head(bucket_name, oid)
            bucket = ParkPlace::Models::Bucket.find_root(bucket_name)
            if @input.has_key? 'version-id'
              @revision = Git::Object.new(bucket.git_repository,@input['version-id'],'commit')
              headers['x-amz-version-id'] = @revision.sha

              # this is still the most recent record which is wrong
              # this also means that metadata or acls are not saved
              # with their revisions at the moment
              @slot = bucket.find_slot(oid)
              @slot.updated_at = @revision.date()

              @revision_file = @revision.gtree().blobs[File.basename(@slot.obj.path)]
            else
              @slot = bucket.find_slot(oid)
              @slot.check_origin_for_updates! if $PARKPLACE_ACCESSORIES && @slot.meta['origin']

              # check to see if versioning is enabled then display 
              # version information if needed
              git_object = @slot.git_object
              headers['x-amz-version-id'] = git_object.objectish if git_object
            end

            if @input.has_key? 'acl'
              only_can_read_acp @slot
            else
              only_can_read @slot
            end

            etag = @slot.etag
            since = Time.httpdate(@env.HTTP_IF_MODIFIED_SINCE) rescue nil
            raise NotModified if since and @slot.updated_at <= since
            since = Time.httpdate(@env.HTTP_IF_UNMODIFIED_SINCE) rescue nil
            raise PreconditionFailed if since and @slot.updated_at > since
            raise PreconditionFailed if @env.HTTP_IF_MATCH and etag != @env.HTTP_IF_MATCH
            raise NotModified if @env.HTTP_IF_NONE_MATCH and etag == @env.HTTP_IF_NONE_MATCH

            headers = {}
            if @slot.meta
                @slot.meta.each { |k, v| headers["x-amz-meta-#{k}"] = v }
            end

            if @slot.obj.is_a? ParkPlace::Models::FileInfo
                headers['Content-Type'] = @slot.obj.mime_type
                headers['Content-Disposition'] = @slot.obj.disposition
            end
            headers['Content-Type'] ||= 'binary/octet-stream'
            r(200, '', headers.merge('ETag' => etag, 'Last-Modified' => @slot.updated_at.httpdate, 'Content-Length' => @slot.obj.size.to_s))
        end
        def get(bucket_name, oid)
            head(bucket_name, oid)
            if @input.has_key? 'acl'
                acl_response_for(@slot)
            elsif @input.has_key? 'version-id'
                @revision_file.contents
            elsif @input.has_key? 'torrent'
                torrent @slot
            elsif @slot.obj.kind_of?(ParkPlace::Models::FileInfo) && @env.HTTP_RANGE =~ /^bytes=(\d+)?-(\d+)?$/ # yay, parse basic ranges
                range_start = $1
                range_end = $2
                raise NotImplemented unless range_start || range_end # Need at least one or the other.
                file_path = File.join(STORAGE_PATH, @slot.obj.path)
                file_size = File.size(file_path)
                f = File.open(file_path)
                if range_start # "Bytes N through ?" mode
                  range_end = (file_size - 1) if range_end.nil?
                  content_length = (range_end.to_i - range_start.to_i + 1)
                  headers['Content-Range'] = "bytes #{range_start.to_i}-#{range_end.to_i}/#{file_size}"
                else # "Last N bytes of file" mode.
                  range_start = file_size - range_end.to_i
                  content_length = range_end.to_i
                  headers['Content-Range'] = "bytes #{range_start.to_i}-#{file_size - 1}/#{file_size}"
                end
                f.seek(range_start.to_i)
                @status = 206
                headers['Content-Length'] = ([content_length,0].max).to_s
                return f
            elsif @env.HTTP_RANGE  # ugh, parse ranges
                raise NotImplemented
            else
                case @slot.obj
                when ParkPlace::Models::FileInfo
                    file_path = File.join(STORAGE_PATH, @slot.obj.path)
                    headers['X-Sendfile'] = file_path
                else
                    @slot.obj
                end
            end
        end
    end

    module Controllers
        def self.S3 *routes
            R(*routes).send :include, ParkPlace::S3, Base
        end
    end
end
