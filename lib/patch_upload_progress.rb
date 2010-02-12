# support for a regular expression as the path for file uploads
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
