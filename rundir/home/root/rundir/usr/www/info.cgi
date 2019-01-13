
dofile("./lib/app.lua");


--get_data, cookie_data, post_data, method = get_user_input()

function post_output()

	local json_data = {};
	local http_data = {};
	json_data["STATUS"] = "error"
	json_data["INFO"] = "Can't POST"
	json_http_resp(json_data);
	my_log("-POST-is end, but info not support port");
end
--
if method == "POST" then

	post_output();
	bak_log("info.cgi.log");
else

	local json_data = {};
	local http_data = {};
	json_data["STATUS"] = "OK"
	http_data["MAC"] = "00:11:22:33:44:55"
	http_data["WEB_VER"] = "web_v1"
	http_data["SYS_VER"] = "sys_v1"
	http_data["TAPE"] = "v44"
	json_data["INFO"] = http_data;
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("info.cgi.log");
end

--main end

