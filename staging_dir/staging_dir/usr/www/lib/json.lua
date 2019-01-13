#!/usr/bin/lua
-- type to json


local function print_func(str)
        print("" .. tostring(str))
    end

c = 0
tmp = "{"
format1=""
format2=""
format3=""
function print_lua_table (lua_table, indent)
    if lua_table == nil or type(lua_table) ~= "table" then
        return
    end
    
    indent = indent or 0
    for k, v in pairs(lua_table) do
        if type(k) == "string" then
            if(k == "disabled" or k == "guide") then
                c = 1
            end
            k = string.format("%q", k)
        end
        local szSuffix = ""
        local szPrefix = string.rep("    ", indent)
        if type(v) == "table" then
            szSuffix = "\n"..szPrefix.."{"
        end
        formatting = szPrefix..""..k..""..":"..szSuffix
        if type(v) == "table" then
            tmp = string.format("%s%s",tmp,formatting)
            print_lua_table(v, indent + 1)
            --print_func(szPrefix.."}")
            format = szPrefix.."}"
            tmp = string.format("%s%s",tmp,format)
            --tmp = tmp..format
        else
            local szValue = ""

            if type(v) == "string" then
                szValue = string.format("%q", v)
            else
                szValue = tostring(v)
            end
            if b == 1 then

            else
            	if c == 1 then
            	    -- print(szPrefix..k..":["..v.."],")
                    format2 = szPrefix..k..":["..v.."],\n"
            	    tmp = string.format("%s%s",tmp,format2)
            	else
              	    format3 = formatting..szValue..",\n"
            	    tmp = string.format("%s%s",tmp,format3)
              	end	
            end
        end
    end
    return string.format("%s}",tmp)
end

function replace_comma(str)
    i,j = string.find(str,",")
    
    while(i ~= nil) do
    	j = i
        h,t = string.find(str,",",i + 1)
        i = h
    end
    
    str1 = string.sub(str,1,j - 1)
    str2 = string.sub(str,j + 1,-1)
    
    return str1,str2
end


function print_json_string(lua_table, indent)
    --print_lua_table(lua_table,indent)
    
    str = print_lua_table(lua_table,indent)

    str_tmp,str2 = replace_comma(str)
    print(str_tmp..str2)
end
