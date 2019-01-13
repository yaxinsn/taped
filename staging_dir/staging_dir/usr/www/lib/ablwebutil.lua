#!/usr/bin/lua
local cjson = require("cjson")
-- globle flags


--split string with delimiter into a table
function split(s, delim)
    local t = {}
    if s then
        assert(type(delim) == "string" and string.len(delim) > 0, "bad delimiter")

        local start = 1
        local pos
        
        repeat
            pos = string.find(s, delim, start, true)

            if pos then
                table.insert(t, string.sub(s, start, pos - 1))
                start = pos + string.len(delim)
            end
        until not pos

        table.insert(t, string.sub(s, start))
    end

    return t
end

function urldecode(s)
    return (string.gsub(string.gsub(s, "+", " "), "%%(%x%s)", function(str)
        return string.char(tonumber(str, 16))
    end ))
end

function urlencode(s)
    return (string.gsub(s, "%W",
    function(str)
        return string.format("%%%02X", string.byte(str))
    end ))
end

--trim leading and trailing spaces from string
function trim(s)
    return (string.gsub(s, "^%s*(.-)%s*$", "%1"))
end

--process a single key=value pair from g GET line 
function assemble_value(s, t)
    assert(type(t) == "table")
    local _, _, key, value = string.find(s, "(.-)=(.+)")
	local f = io.open("/tmp/rundir/usr/www/web.log", "a")
	
    if key then
        t[trim(key)] = trim(value)
		f:write(key..":"..value)
    end 
	f:close()
end

-- get user data
function get_user_input()
    local _, v
    --local f = io.open("/tmp/rundir/usr/www/web.log", "w")
	
    local get_data = {}
    for _, v in ipairs(split(os.getenv("QUERY_STRING"), "&")) do
        assemble_value(v, get_data)
		--f:write(v)
    end


    local cookie_data = {}
    for _, v in ipairs(split(os.getenv("HTTP_COOKIE"), ";")) do
        assemble_value(v, cookie_data)
		--f:write(v)
    end

    local post_data = {}
    local post_length = tonumber(os.getenv("CONTENT_LENGTH")) or 0
	
    if os.getenv("REQUEST_METHOD") == "POST" and post_length > 0 then
        for _, v in ipairs(split(io.read(post_length), "&")) do
        --for _, v in ipairs(split(os.getenv("*a"), "&")) do
            assemble_value(v, post_data)
			--f:write(v)
        end
    end
	--f:close()
    return get_data, cookie_data, post_data, os.getenv("REQUEST_METHOD")
end

-- http header
function show_http_header(cookies)
    assert(not done_http_header, "Too many HTTP headers")

    print("Content-Type: text/html\n\n; charset=utf-8")
    print("X-Powered-By: ablwebutil.lua written by Roc Yang")

    if cookies then
        assert (type(cookies) == "table")
        for k, v in pairs(cookies) do
            print("Set-Cookie: "..k.."="..v)
        end
    end

    print("")
    done_http_header = true
end

-- exec and get info
function exec_get_local(cammand)
    local fname = os.tmpname()
    os.execute(cammand.." 2> /dev/null  1> "..fname )
    local f = io.open(fname, "r")
    local s = f:read("*a")
    f:close()
    os.remove(fname)
    return s
end

-- check ip addr
function check_ip(ip)
	if not ip then
		return false
	end
	local cnt = 0
	local t = split(ip, '.')
	local new_ip = {}
	
	if not type(t) == "table" then
		return false
	end
	
	for _,dt in pairs(t) do 
		local tmp = tonumber(dt)
		if tmp and tmp >= 0 and tmp <= 255 then
			new_ip[cnt] = tmp
			cnt = cnt + 1
		else
			return false
		end
	end
	
	if cnt == 4 then
		return string.format("%d.%d.%d.%d", new_ip[0], new_ip[1], new_ip[2], new_ip[3])
	end
	
	return false
end

-- check ip addr
function check_domain(domain)
    if not domain then
        return false
    end
    local cnt = 0
    local t = split(domain, '.')
    local new_domain = {}
    
    if not type(t) == "table" then
        return false
    end
    
    for _,dt in pairs(t) do 
        local tmp = tonumber(dt)
        if tmp then
            return true
        end
    end
    
    return true
end

--print table
local function print_func(str)
        print("" .. tostring(str))
end

function get_user_input_update()
    local _, v
    --local f = io.open("/tmp/rundir/usr/www/web.log", "w")
	
    local get_data = {}
    for _, v in ipairs(split(os.getenv("QUERY_STRING"), "&")) do
        assemble_value(v, get_data)
		--f:write(v)
    end


    local cookie_data = {}
    for _, v in ipairs(split(os.getenv("HTTP_COOKIE"), ";")) do
        assemble_value(v, cookie_data)
		--f:write(v)
    end

    local post_data = {}
    local post_length = tonumber(os.getenv("CONTENT_LENGTH")) or 0
    
    if os.getenv("REQUEST_METHOD") == "POST" and post_length > 0 then
    			local fix_len = post_length - 400
					local mode_len = fix_len%100
					local cnt = math.ceil(fix_len/100) - 1
					local start = 0
					local en = 0
					local num = 0
					local f = io.open("upgrade.bin","wb")
					local str = io.read(300)
					while true do
						start,en = string.find(str,"\r\n",start+1)
						if start == nil then break end
						num = num + 1
						if num == 4 then break end
					end
					f:write(string.sub(str,en+1,300))
					
    			for i=1,cnt do
						f:write(io.read(100))
					end
					f:write(io.read(mode_len))
					str = io.read(100)
					start,en = string.find(str,"\r\n")
					if start == nil then
						f:write(string.sub(str,1,100))
					else
						f:write(string.sub(str,1,start-1))
					end
					f:close()
    end
	--f:close()
    return get_data, cookie_data, post_data, os.getenv("REQUEST_METHOD")
end

function json_http_resp(j_obj)
	print('Content-Type: application/json\r\n\r\n') 
	local jsonStr = cjson.encode(j_obj)
	print(jsonStr)
	os.exit()
end
function form_data_http_resp(j_obj)
	print("Content-Type: multipart/form-data\n\n")
	local jsonStr = cjson.encode(j_obj)
	print(jsonStr)
	os.exit()
end