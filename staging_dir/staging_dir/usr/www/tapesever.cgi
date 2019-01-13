dofile("./lib/app.lua");


--get_data, cookie_data, post_data, method = get_user_input()

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

	config_["TAPESERVER"]=post_data;
	if config_["TAPESERVER"]["SESSIONID"] ~=nil then
                config_["TAPESERVER"]["SESSIONID"]=nil
        end
	set_config(config_);
	post_output();
	bak_log("tapeserver.log");
else

	local	json_data = {};
	local http_data = {};
	json_data["STATUS"] = "OK"
--json_data["msg"] = "get csip success"
--[[
	http_data["MAINIP"] = "2.2.2.4"
	http_data["MAINPORT"] = "8090"
	http_data["SPAREIP"] = "2.2.2.5"
	http_data["SPAREPORT"] = "8091"
	json_data["TAPESERVER"] = http_data;
--]]
	if config_["TAPESERVER"]["SESSIONID"] ~=nil then
                config_["TAPESERVER"]["SESSIONID"]=nil
        end
	json_data["TAPESERVER"] = config_["TAPESERVER"];
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("tapeserver.log");
end

--main end

