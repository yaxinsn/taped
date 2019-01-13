
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
	
	config_["CALLCENTER"]=post_data;
	if config_["CALLCENTER"]["SESSIONID"] ~=nil then
                config_["CALLCENTER"]["SESSIONID"]=nil
        end
	set_config(config_);
	post_output();
	bak_log("callcenter.log");
else --GET
--GET
	local json_data = {};
	local http_data = {};
	json_data["STATUS"] = "OK"
	if config_["CALLCENTER"]["SESSIONID"] ~=nil then
                config_["CALLCENTER"]["SESSIONID"]=nil
        end
	json_data["CALLCENTER"] = config_["CALLCENTER"];
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("callcenter.log");
end

--main end

