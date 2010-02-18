$PARKPLACE_ACCESSORIES = true
require 'parkplace'

ParkPlace::Base.config(ParkPlace::Base.options)
use Rack::Head
use Rack::ShowExceptions
use Rack::CommonLogger

map "/" do
  run ParkPlace::Base
end
map "/control/s" do
  run Rack::File.new(ParkPlace::STATIC_PATH)
end
map "/backup" do
  run ParkPlace::BackupManager.new
end
