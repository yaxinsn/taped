

#ifndef _JSON_H_
#define _JSON_H_
#include <stdio.h>
#include <json-c/json.h>
#include <stdlib.h>
#include <string.h>
#include "types_.h"

json_object* add_obj_to_json(json_object *json_obj_out,char *k,char* v);
json_object * convert_json_data(char* s);
const char *json_common_get_string(json_object *js_obj, const char *key );
const char* convert_json_to_str(json_object *js_obj);

#endif //_JSON_H_