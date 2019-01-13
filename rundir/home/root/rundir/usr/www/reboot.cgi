
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

	post_output();
	os.execute("echo I reboot >>/etc/reboot.xxxx");	
	bak_log("reboot.log");

	os.execute("sleep 5 && /sbin/reboot ");	
else

	json_data = {};
	http_data = {};
	json_data["STATUS"] = "OK"
        if config_["HEART"]["SESSIONID"] ~=nil then
                config_["HEART"]["SESSIONID"]=nil
        end
	json_data["HEART"] = config_["HEART"]
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("heart.log");
end

--main end

