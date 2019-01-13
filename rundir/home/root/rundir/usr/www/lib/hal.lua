#!/usr/bin/lua

function get_pppoe_info()
	local t = {}
	t["username"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.pppoe.username | awk -F= '{print $2}'"),1,-2)
	t["password"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.pppoe.password | awk -F= '{print $2}'"),1,-2)
	return t
end

function get_dhcp_mode()
	local t = {}
	file = io.open("/data/ap.conf","r")
	assert(file)
	local data=file:read("*a")
	file:close()
	if  string.find(data, "network.wan.proto=static") then
		t["mode"] = "static"
	else if string.find(data, "network.wan.proto=pppoe") then
		t["mode"] = "pppoe"
	else
		t["mode"] = "dhcp"
	end
	end
	return t;
end

function get_dhcpv6_mode()
	local t = {}
	file = io.open("/data/ap.conf","r")
	assert(file)
	local data=file:read("*a")
	file:close()
	if  string.find(data, "network.wan.proto6=static") then
		t["mode"] = "static"
	else
		t["mode"] = "dhcp"
	end
	return t;
end

function get_vender_info()
	local t = {}
	-- Get AP version and vender
	local version = exec_get_local(env_get_version)
	if version then
		t["version"] = string.sub(version,1,-2)
	end

	local vender = exec_get_local(env_get_vender)
	if vender then
		t["vender"] = string.sub(vender,1,-2)
	end

	return t
end

function get_wan_info()
	local t = {}
    local t_mode = {}
    local tmp_string
    t["ip"] = ""
    t["mask"] = ""
    t["mac"] = ""
    t["pri_dns"] = ""
    t["alt_dns"] = ""
    t["gateway"] = ""
    t["cfg1xclient_enable"] = ""
    t["cfg1xclient_username"] = ""
    t["cfg1xclient_password"] = ""
    t["vlan"] = ""
    t["username"] = ""
    t["password"] = ""
    -- parase tmp_string get ip,mask,mac
    t_mode = get_dhcp_mode()
    if t_mode["mode"] and t_mode["mode"]=="pppoe" then
        tmp_string = exec_get_local(env_ifconfig_pppoe)
    else
        tmp_string = exec_get_local(env_ifconfig_wan)
    end
    if tmp_string then
        local ip = string.sub(string.match(tmp_string, "addr:%d+%.%d+%.%d+%.%d+") or "", 6)
	local mask = string.sub(string.match(tmp_string, "Mask:%d+%.%d+%.%d+%.%d+") or "", 6)
	t["ip"] = ip or ""
	t["mask"] = mask or ""
	end

	-- Get DNS
		t["pri_dns"] = get_dns(1) or ""
		t["alt_dns"] = get_dns(2) or ""

	-- Get gateway
	
	if t_mode["mode"] == "pppoe" then
		local string = exec_get_local("route -n | awk '/UH/{print}' | awk '{print $1}'")
		gate = string.match(string, "%d+%.%d+%.%d+%.%d+")
	else
		local string = exec_get_local("route -n | awk '/UG/{print}' | awk '{print $2}'")
		gate = string.match(string, "%d+%.%d+%.%d+%.%d+")
	end
	t["gateway"] = gate or ""
	-- Get 1xclient
	
	-- Get Vlan
	t["vlan"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.vlanid | awk -F = '{print $2}'"), 1, -2)
	
	-- Get pppoe info
	-- get 1xclient info
	  t["cfg1xclient_enable"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.enable | awk -F = '{print $2}'"), 1, -2)
    if t["cfg1xclient_enable"] == "1" then
    	t["cfg1xclient_username"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.username | awk -F = '{print $2}'"), 1, -2)
    	t["cfg1xclient_password"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.password | awk -F = '{print $2}'"), 1, -2)
		else
			t["cfg1xclient_enable"] = "0"
		end
	return t
end

function get_wanv6_info(mode)
	local t = {}
    local t_mode = {}
    local tmp_string
    t["ip"] = ""
    t["prefix"] = ""
    t["mac"] = ""
    t["pri_dns"] = ""
    t["alt_dns"] = ""
    t["gateway"] = ""
    t["cfg1xclient_enable"] = ""
    t["cfg1xclient_username"] = ""
    t["cfg1xclient_password"] = ""
    t["vlan"] = ""
    t["username"] = ""
    t["password"] = ""
    -- parase tmp_string get ip,mask,mac

    if mode then
    		local tmp = string.sub(exec_get_local("ifconfig br-wan | grep 'inet6 addr'| grep 'Scope:Global'| sed -n '1p' | awk -F' ' '{print $3}'"), 1, -2)
        local ip = string.sub(exec_get_local("echo "..tmp.." | awk -F'/' '{print $1}'"), 1, -2)
				local prefix = string.sub(exec_get_local("echo "..tmp.." | awk -F'/' '{print $2}'"), 1, -2)
				t["ip"] = ip or ""
				t["prefix"] = prefix or ""
		end

	-- Get DNS
		t["pri_dns"] = get_dnsv6(1) or ""
		t["alt_dns"] = get_dnsv6(2) or ""

	-- Get 1xclient
	
	-- Get Vlan
	t["vlan"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.vlanid | awk -F = '{print $2}'"), 1, -2)
	
	-- Get pppoe info
	-- get 1xclient info
	  t["cfg1xclient_enable"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.enable | awk -F = '{print $2}'"), 1, -2)
    if t["cfg1xclient_enable"] == "1" then
    	t["cfg1xclient_username"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.username | awk -F = '{print $2}'"), 1, -2)
    	t["cfg1xclient_password"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.password | awk -F = '{print $2}'"), 1, -2)
		else
			t["cfg1xclient_enable"] = "0"
		end
    	t["is_enable"] = string.sub(exec_get_local("cat /data/ap.conf | grep network.ipv6.enable | awk -F = '{print $2}'"), 1, -2)
	if t["is_enable"] ~= "1" then
		t["gateway"] = ""
		return t
	end
	-- Get gateway
		gate = string.sub(exec_get_local("route -A inet6 | grep UG | grep br-wan | awk 'NR==1{print $2}'"), 1, -2)
		t["gateway"] = gate or ""
	return t
end


function get_csip()
	local t = {}
	local csip = exec_get_local("cat /data/ap.conf | grep cloud | awk -F = '{print $2}'")
	-- local checkStr = string.find(csip, "%d+%.%d+%.%d+%.%d+")
	if csip == nil then
		t["csip"] = "0.0.0.0"
	else
		t["csip"]  = string.sub(csip,1,-2)
	end
	return t
end

function get_lan()
	local t = {}
	t["lan_ip"] = string.sub(exec_get_local("cat /data/ap.conf | grep lan_ip | awk -F = '{print $2}'"),1,-2)
	t["lan_mask"] = string.sub(exec_get_local("cat /data/ap.conf | grep lan_mask | awk -F = '{print $2}'"),1,-2)
	t["dhcp_low"] = string.sub(exec_get_local("cat /data/ap.conf | grep start_ip | awk -F = '{print $2}'"),1,-2)
	t["dhcp_hi"] = string.sub(exec_get_local("cat /data/ap.conf | grep end_ip | awk -F = '{print $2}'"),1,-2)
	t["interval"] = string.sub(exec_get_local("cat /data/ap.conf | grep leases | awk -F = '{print $2}'"),1,-2)
	return t
end

function set_lan(ip,mask,lowip,hiip,interval)
	local result = exec_get_local("/tmp/rundir/sbin/wtpconf set lan "..ip.." "..mask.." "..lowip.." "..hiip.." "..interval)

	if string.find(result, "conflict") then
        return 1
  end
	if string.find(result, "ERROR:lanip") then
        return 2
  end
  	if string.find(result, "ERROR:start") then
        return 3
  end
	if string.find(result, "ERROR:end") then
        return 4
  end
	if string.find(result, "ERROR:first") then
        return 5
  end
  return 0
end

function file_exist(path)
	local file = io.open(path,"rb")
	if file then file:close() end
		
	return file ~= nil
end

function get_md5(file)
	local cmd = "md5sum "..file.." | awk '{print $1}'"
	return string.sub(exec_get_local(cmd),1,-2)	
end

function get_country_code(radio)
 local cmd = "iwpriv "..radio.." getCountry | awk -F: '{print $2}'"
	return string.sub(exec_get_local(cmd),1,-2)	
end

function format_country_code_info(s, t)
    assert(type(t) == "table")
		    local iter = string.gfind(s, "([^\;]+)")	
		    t["pre_info"] = iter()
		    t["mid_info"] = iter()
		    t["tail_info"] = iter()
end

function get_country_code_info()
	local t = {}
	local tmp ={}
	local i = 1
	local string
	local NR = exec_get_local("awk 'END{print NR}' ./countries.txt")
	--local NR = "10"
	for i=1,tonumber(NR) do
		local arr = {}
		string = exec_get_local("awk 'NR==" ..i.."' ./countries.txt")		
			format_country_code_info(string,arr)
			t[i] = arr
	end
	return t
end

function get_tz_info()
		return string.sub(exec_get_local("cat /data/ap.conf | grep system.tz | awk -F= '{print $2}'"),1,-2)
end

function get_1x_info()
		return string.sub(exec_get_local("cat /data/ap.conf | grep network.wan.1xclient.enable | awk -F = '{print $2}'"), 1, -2)
end

function get_ping()
		t = {}
		local tmp = {}
		nr = 1
		fp = io.open("/tmp/ping.log","r")
		for i in fp:lines() do 
			tmp["value"] = i
			t[nr] = tmp
			nr = nr + 1
		end
		return t
end
