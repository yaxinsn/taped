dofile("./lib/app.lua");

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

	config_["PASSWORD"]=post_data;
        set_config(config_);
	post_output();
	bak_log("post.password.cgi");
else

	json_data = {};
	json_data["STATUS"] = "OK"
	json_http_resp(json_data);
	my_log("-get-is end");
	bak_log("password.cgi");
end

--main end

