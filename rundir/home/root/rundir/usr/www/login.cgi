
dofile("./lib/app.lua");

my_log("app.lua is out");
my_log("method is " .. method .. "and esssion is nil");
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
	local _data={};
        if post_data["PASSWORD"] then
            local success,user, sessionid = do_login(post_data["USER"],post_data["PASSWORD"]);
            if success then
                 _data["SESSIONID"]=sessionid;
                 _data["STATUS"]="OK"
            else
                 _data["STATUS"]="PASSWORD ERROR";
            end
            json_http_resp(_data);
        end
	bak_log("post.login.cgi");
else
        my_log("get is end");
	bak_log("get.login.cgi");
end

--main end

