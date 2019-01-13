#!/usr/bin/lua
dofile "/tmp/rundir/usr/lib/ablwebutil.lua"
package.path = package.path..";?.lua"
local env = require("env")

get_data, cookie_data, post_data, method = get_user_input_update()

