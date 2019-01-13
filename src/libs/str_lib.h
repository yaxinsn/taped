#ifndef STR_LIB_H__
#define STR_LIB_H__


char* find_key_from_line(const char* line,const char* key,int* v_len,const char* delim);

char* setup_value_by_key_from_line(const char* line,const char* key,char** dest);



#endif


