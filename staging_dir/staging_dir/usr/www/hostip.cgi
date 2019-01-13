dofile("./lib/app.lua");

my_log("----name " .. os.getenv("SCRIPT_NAME"));
function post_output()

	json_data = {};
	http_data = {};
	json_data["STATUS"] = "OK"
	json_data["INFO"] = "success"
	json_http_resp(json_data);
	my_log("-POST-is end");
end
--
if method == "POST" then

	config_["HOSTIP"]=post_data;
	if config_["HOSTIP"]["SESSIONID"] ~= nil then
		config_["HOSTIP"]["SESSIONID"]=nil;
	end
        set_config(config_);
	post_output();
	bak_log("post.hostip.cgi.log");
else

	json_data = {};
	http_data = {};
	json_data["STATUS"] = "OK"
	json_data["HOSTIP"] = config_["HOSTIP"];
	if json_data["HOSTIP"] == nil then
		json_data["HOSTIP"]={};
	end

	if json_data["HOSTIP"]["SESSIONID"] ~= nil then
		json_data["HOSTIP"]["SESSIONID"]=nil;
	end
	json_data["HOSTIP"]["MAC"] = "00:22:33:44:55:66"
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("get.hostip.cgi.log");
end

--main end

