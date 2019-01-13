#!/usr/bin/lua
TOP="/home/root/rundir/usr/www"
dofile(TOP .. "/lib/log.lua");                                            
dofile(TOP .. "/lib/webutil.lua");                                        
dofile(TOP .. "/lib/config.lua");                                         
package.path = package.path..";?.lua"
dofile(TOP .. "/lib/password.lua");

--[[ This is main entry for this webapp
    We handle requests like streams.
    get_params()
    auth_check()
    dispatch()
    render()
]]--

-- 1.get request infomations
get_data, cookie_data, post_data, method, sessionid = get_user_input()

local script_name=os.getenv("SCRIPT_NAME") or ""

my_log("script name " .. script_name);
-- 2.check auth
if not string.find(script_name,"login")  then
      flag =is_authed(sessionid)
      if not flag then
      obj = 
	{
		STATUS = "TIMEOUT",
		MSG = "Session is timerout ",
	}
	json_http_resp(obj)
	my_log("app.lua: 2 check auth, session timeout");
        os.exit();
      else
	
	my_log("app.lua: 2 check auth, session is ok");
	end
end

my_log("app.lua : is end script name " .. script_name);
-- 3.route
