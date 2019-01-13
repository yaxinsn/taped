
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

	config_["NTPSERVER"]=post_data;
	if config_["NTPSERVER"]["SESSIONID"] ~=nil then
                config_["NTPSERVER"]["SESSIONID"]=nil
        end
        set_config(config_);
	post_output();
	bak_log("heart.log");
else

	json_data = {};
	http_data = {};
	json_data["STATUS"] = "OK"
        if config_["NTPSERVER"]["SESSIONID"] ~=nil then
                config_["NTPSERVER"]["SESSIONID"]=nil
        end
	json_data["NTPSERVER"] = config_["NTPSERVER"]
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("NTPSERVER.log");
end

--main end

