/*****************************************************************

2017/9/24 10:04:09 liudan 
读取整个文件，转成字符串，并完成config的定义。

文件分类：
json.c
config.c
main.c


*****************************************************************/

#include <stdio.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>

const char *json_common_get_string(json_object *js_obj, const char *key )
{
	json_object *js_tmp = NULL;
	const char *str = NULL;

	json_object_object_get_ex(js_obj, key,&js_tmp);

	if (js_tmp == NULL) return NULL;

	str = (char *) json_object_get_string(js_tmp);
	return str;
}


json_object * convert_json_data(char* s)
{
	json_object *js_obj;
	js_obj = json_tokener_parse(s);
	return js_obj;
}

static void external_add_json_obj(json_object *json_obj_out, char *object, char *string)
{
	json_object *json_obj_tmp = json_object_new_string(string);
	json_object_object_add(json_obj_out, object, json_obj_tmp);
}

json_object* add_obj_to_json(json_object *json_obj_out,char *k,char* v)
{
		
	if(json_obj_out == NULL)
		json_obj_out = json_object_new_object();
	external_add_json_obj(json_obj_out, k, v);
	return json_obj_out;
}

const char* convert_json_to_str(json_object *js_obj)
{
	const char *str = NULL;
	str = json_object_get_string(js_obj);
	return str;
}

#if 0
const char* g_str3="/* more difficult test case */ { \"glossary\": { \"title\": \"example glossary\", \"GlossDiv\": { \"title\": \"S\", \"GlossList\": [ { \"ID\": \"SGML\", \"SortAs\": \"SGML\", \"GlossTerm\": \"Standard Generalized Markup Language\", \"Acronym\": \"SGML\", \"Abbrev\": \"ISO 8879:1986\", \"GlossDef\": \"A meta-markup language, used to create markup languages such as DocBook.\", \"GlossSeeAlso\": [\"GML\", \"XML\", \"markup\"] } ] } } }";
const char* g_str="{\"name\":\"main\",\"age\":\"13\"}";
const char* g_str2="{\"street\":\"one street\",\"gateNo\":\"13\"}";

int _test(int argc,char* argv[])
{
	json_object * a;

	
	char buf1[1000];
	char buf2[1000];
	char buf3[1000];
	strcpy(buf1,g_str);
	strcpy(buf2,g_str2);
	strcpy(buf3,g_str3);
	json_object * b = convert_json_data(buf1);
	json_object * obj3 = convert_json_data(g_str3);

	memset(buf1,0,200);
	a = convert_json_data(g_str);
	if(a)
	printf("%s\n", convert_json_to_str(a));
	printf("add port \n");
	add_obj_to_json(a,"port","beijing");
	printf("%s\n", convert_json_to_str(a));
	printf("modfiy port \n");
	add_obj_to_json(a,"port","tianjin");
	printf("%s\n", convert_json_to_str(a));


	printf("add new json\n");
	json_object_object_add(a,"address",b);

//	json_object_put(b); //can't put b in here

	printf("%s\n", convert_json_to_str(a));
	printf("del address \n");
	json_object_object_del(a,"address");

	json_object_put(b);// del this obj, so , should put it here. 
	printf("%s\n", convert_json_to_str(a));
	json_object_put(a);


	printf("I can use json_ojbect_get_strings as const input, and use this input convert to new json \n");
	{
		json_object* obj3_glossary2 = convert_json_data(json_common_get_string(obj3,"glossary"));
		json_object* obj3_glossary = json_object_object_get(obj3, "glossary");
		printf("obj3_glossary2:%p\n",obj3_glossary2);
		printf("%s\n", convert_json_to_str(obj3_glossary2));
		printf("obj3_glossary:%p\n",obj3_glossary);
		printf("%s\n", convert_json_to_str(obj3_glossary));
		json_object_put(obj3_glossary2);
//		json_object_put(obj3_glossary); // not use it , obj3_glossary is sub obj of obj3. ,I will put obj3 at end.
#if 0		
		json_object_put(obj3_glossary); 
		printf("I object_put obj3_glossary ,and output obj3.\n");
		printf("%s\n", convert_json_to_str(obj3));// panic is in here.
#endif		
	}
json_object_put(obj3);

	return 0;
		
}

#endif
