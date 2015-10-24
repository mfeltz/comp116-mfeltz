require 'packetfu'

# checks if NULL scan by checking that all 
# flags are off
def is_null_scan? (flags)
	return flags.fin == 0 &&
	flags.syn == 0 &&
	flags.rst == 0 &&
	flags.psh == 0 &&
	flags.ack == 0 &&
	flags.urg == 0
end

# checks if FIN scan by checking that only 
# the fin flag is set to 1
def is_fin_scan? (flags)
	return flags.fin == 1 &&
	flags.syn == 0 &&
	flags.rst == 0 &&
	flags.psh == 0 &&
	flags.ack == 0 &&
	flags.urg == 0
end

# checks if XMAS scan by checking that the
# fin, psh, and urg flags are on
def is_xmas_scan? (flags)
	return flags.fin == 1 &&
	flags.psh == 1 &&
	flags.urg == 1
end

# checks if nmap scan by checking payload for
# binary pattern for nmap scan
def is_nmap_scan?(payload)
	nmap_binary = /\x4E\x6D\x61\x70/
	return nmap_binary.match(payload)
end

# checks if nikto scan by checking payload for
# binary pattern for nikto scan
def is_nikto_scan?
	nikto_binary = /\x4E\x69\x6B\x74\x6F/
	return nikto_binary.match(payload)
end

# checks if credit card leak by checking payload for
# clear text credit card numbers
def is_credit_card?(pkt)
	visa = /4\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
	mastercard = /5\d{3}(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
	discover = /6011(\s|-)?\d{4}(\s|-)?\d{4}(\s|-)?\d{4}/
	amex = /3\d{3}(\s|-)?\d{6}(\s|-)?\d{5}/
	return visa.match(payload) ||
	mastercard.match(payload) ||
	discover.match(payload) ||
	amex.match(payload)
end

# function to print live incident alerts
def print_live_alert(incident_count, message, pkt)
	 puts "#{incident_count}. ALERT: #{message} is detected from #{pkt.ip_saddr} (#{pkt.proto()[-1]}) (#{pkt.payload})!"
end

# function to analyze live stream
# captures and parses input to get packets and checks
# for each type of scan or leak
def analyze_live
	incident_count = 0
	cap = PacketFu::Capture.new(:start =>true, :iface => iface, :promisc => true)
	cap.stream.each do |p|
		pkt = PacketFu::Packet.parse(p)
		if pkt.is_ip?
			if pkt.is_tcp?
				flags = pkt.tcp_flags.to_i
				if is_null_scan?(flags)
					incident_count++
					print_live_alert(incident_count, "NULL scan", pkt)
				end
				if is_fin_scan?(flags)
					incident_count++
					print_live_alert(incident_count, "FIN scan", pkt)
				end
				if is_null_scan?(flags)
					incident_count++
					print_live_alert(incident_count, ". ALERT: XMAS scan is detected from ", pkt)
				end
			end
			if is_nmap_scan? pkt
				incident_count++
				print_live_alert(incident_count, ". ALERT: Nmap scan is detected from ", pkt)
			end
			if is_nikto_scan? pkt
				incident_count++
				print_live_alert(incident_count, ". ALERT: Nikto scan is detected from ", pkt)
			end
			if is_credit_card? pkt
				incident_count++
				print_live_alert(incident_count, ". ALERT: Credit card leaked in the clear from ", pkt)
			end
		end
	end
end

# function to print live incident alerts
def print_log_alert(incident_count, message, line)
	by_space = line.split(' ')
	by_quotes = line.split("\"")
	ip_address = by_space[0]
	payload = by_quotes[1]
	protocol = by_space[7].split("\"")[0]

	puts "#{incident_count}. ALERT: #{message} is detected from #{ip_address} (#{protocol}) (#{payload})!"
end

# function to analyze web server log
# checks each line for each type of scan or leak
def analyze_log(file)
	incident_count = 0
	file.each do |line|
		# nmap
		if /nmap/.match(line) != nil
			incident_count++
			print_log_alert(incident_count, "Nmap scan", line)
		end
		# nikto
		if /nikto/.match(line) != nil
			incident_count++
			print_log_alert(incident_count, "Nikto scan", line)
		end
		# masscan
		if /masscan/.match(line) != nil
			incident_count++
			print_log_alert(incident_count, "Someone running Masscan", line)
		end
		# Shellshock () { :;}; or () { :; };
		if /\(\)\s\{\s\:\;\s*\}\;/.match(line) != nil
			incident_count++
			print_log_alert(incident_count, "Someone scanning for Shellshock vulnerability", line)
		end
		# phpMyAdmin
		if /phpMyAdmin/.match(line) != nil
			incident_count++
			print_log_alert(incident_count, "Someone looking for phpMyAdmin stuff", line)
		end
	end
end

# runs analyze_log if the 2 arguments are '-r' and a file
# runs analyze_live if no arguments are given
if ARGV[0] == "-r" && ARGV[1] != nil
	file = File.new(ARGV[1])
	analyze_log file 
elseif ARGV[0] == nil && ARGV[1] == nil
	analyze_live
end
