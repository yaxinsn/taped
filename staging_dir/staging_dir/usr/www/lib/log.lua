

--read all post value
-- write all the post value to a /tmp/my.cgi.log

function log(file, ...)

    local _,v;

    local f = io.open(file, "a+")
    
    local get_data = {}
    for _, v in ipairs((arg)) do
                f:write(v)
                f:write('\t')
    end
    f:write("\n")
    f:close();
end

function my_log(...)
	log("/tmp/cgi.log",...);
end


function bak_log(name)
	cmd="mv " .. "/tmp/cgi.log " .. "/tmp/" .. name;
	os.execute(cmd);
end
--[[
function assemble_value(s, t)      
    assert(type(t) == "table")                                    
    local _, _, key, value = string.find(s, "(.-)=(.+)")
                                             
    if key then                                                
        t[trim(key)] = trim(value)                          
                my_log(key..":"..value .. "\n")
    end                                                        
end   

--  os.execute("export >/tmp/cgi.param");

    my_log("---------" .. os.date() .. "\n");
    post_data = {};
    my_log("QUERY_STRING: " ..  os.getenv("QUERY_STRING") .. "\n");   
    post_length = tonumber(os.getenv("CONTENT_LENGTH")) or 0;

    if os.getenv("REQUEST_METHOD") == "POST" and post_length > 0 then
        my_log("POST method\n");
	post_raw = io.read(post_length);
	my_log("posw_raw:\n" .. post_raw .. "\n");

--	for _, v in ipairs(split(io.read(post_raw), "&")) do
--            assemble_value(v, post_data)
--        end                                                                
    end 
print("time: " .. os.date());
-- print("a is " .. os.getenv("a"));
--]]

--[[

io.write("Content-Type: text/plain\n\n")
local json_data ={}
local csip  = {}
local cjson = require("cjson")
print("time:" .. os.time());
print("------");

--]]
