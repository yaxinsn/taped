 /*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ /| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             /___|/___/|_| /_/_____|
 *
 * $Id: multi-post.c,v 1.1 2002/05/06 13:38:28 bagder Exp $
 *
 * This is an example application source code using the multi interface
 * to do a multipart formpost without "blocking".
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/inet.h>
#include <curl/curl.h>

#include "log.h"

#include "curl_upload.h"

//typedef unsigned char BYTE;
#if 1
#define TOHEX(x) ((x)>9 ? (x)+55 : (x)+48)

void set_up_formpost(struct curl_httppost** formpost,struct curl_httppost** lastptr,
    struct upload_file_info* info)
{
	
    char* path_and_filename[256]={0};
  /* Fill in the submit field too, even if this is rarely needed */
  curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_LOCAL_NUMBER",
               CURLFORM_COPYCONTENTS, info->call_local_number,
               CURLFORM_END);

  curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_CALLER_NUMBER",
               CURLFORM_COPYCONTENTS, info->call_caller_number,
               CURLFORM_END);
  

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_CALLEE_NUMBER",
               CURLFORM_COPYCONTENTS, info->call_callee_number,
               CURLFORM_END);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALLEE_GROUP_NUMBER",
               CURLFORM_COPYCONTENTS, info->called_group_number,
               CURLFORM_END);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_DIRECTION",
               CURLFORM_COPYCONTENTS, info->call_direction,
               CURLFORM_END);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "BOX_MAC",
               CURLFORM_COPYCONTENTS, info->box_id,
               CURLFORM_END);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_BEGINTIME",
               CURLFORM_COPYCONTENTS, info->call_begin_time,
               CURLFORM_END);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_ENDTIME",
               CURLFORM_COPYCONTENTS,  info->call_end_time,
               CURLFORM_END);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "SECRET",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);
               
      curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "SERIAL_NO",
               CURLFORM_COPYCONTENTS, info->frag_serial_no,
               CURLFORM_END);

      curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "FRAG_FLAG",
               CURLFORM_COPYCONTENTS, info->frag_flag,
               CURLFORM_END);
             
    sprintf(path_and_filename,"%s",info->file_name);

    curl_formadd((struct curl_httppost**)formpost,
               (struct curl_httppost**)lastptr,
               CURLFORM_COPYNAME, info->file_name,
               CURLFORM_FILE, path_and_filename,
               CURLFORM_FILENAME, info->file_name,
               CURLFORM_END);
}

#endif

static size_t server_return_funtion
( void *ptr, size_t size, size_t nmemb, void *stream)
{
	memcpy((char*)stream,(char*)ptr,size*nmemb);
	return size*nmemb;
}
#if 0
int upload_mix_file(char* server_url,struct upload_file_info* file_info)
{
  CURL *curl;
//  CURLcode res;

  CURLM *multi_handle;
  int still_running;

  struct HttpPost *formpost=NULL;
  struct HttpPost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  char buf[] = "Expect:";
  int ret;
  char server_ret_msg[2048]={0};

  set_up_formpost((struct curl_httppost**)&formpost,(struct curl_httppost**)&lastptr,file_info);

  curl = curl_easy_init();
  multi_handle = curl_multi_init();

  /* initalize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = curl_slist_append(headerlist, buf);
  if(curl && multi_handle) {
    //int perform=0;

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL,
                                        server_url);
                  //   "http://39.105.109.64:8099/record/box/reportOneRecord");

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,server_return_funtion);
    
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,server_ret_msg);

    curl_multi_add_handle(multi_handle, curl);

    while(CURLM_CALL_MULTI_PERFORM ==
          curl_multi_perform(multi_handle, &still_running));

    while(still_running) 
    {
      struct timeval timeout;
      int rc; /* select() return code */

      fd_set fdread;
      fd_set fdwrite;
      fd_set fdexcep;
      int maxfd;

      FD_ZERO(&fdread);
      FD_ZERO(&fdwrite);
      FD_ZERO(&fdexcep);

      /* set a suitable timeout to play around with */
      timeout.tv_sec = 1;
      timeout.tv_usec = 0;

      /* get file descriptors from the transfers */
      curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

      rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &timeout);

      switch(rc) {
          case -1:
            /* select error */
            break;
          case 0:
            printf("timeout!\n");
          default:
            /* timeout or readable/writable sockets */
            printf("perform!\n");
            while(CURLM_CALL_MULTI_PERFORM ==
                  curl_multi_perform(multi_handle, &still_running));
            printf("running: %d!\n\n", still_running);
            break;
        }
    }

    curl_multi_cleanup(multi_handle);

    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree((struct curl_httppost*)formpost);

    log("server reg msg: %s \n",server_ret_msg);
    if(strlen(server_ret_msg) != 0)
        ret  = 0;
    else
        ret  = -1;
    /* free slist */
    curl_slist_free_all (headerlist);
  }
  return ret;
}
#endif
int upload_mix_file(char* server_url,struct upload_file_info* file_info)
{
  CURL *curl;
//  CURLcode res;

 // CURLM *multi_handle;
  int still_running;

  struct HttpPost *formpost=NULL;
  struct HttpPost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  char buf[] = "Expect:";
  int ret;
  CURLcode res = CURLE_OK; 
  char server_ret_msg[2048]={0};

  set_up_formpost((struct curl_httppost**)&formpost,(struct curl_httppost**)&lastptr,file_info);

  curl = curl_easy_init();
//  multi_handle = curl_multi_init();

  /* initalize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = curl_slist_append(headerlist, buf);
  if(curl) {
    //int perform=0;

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL,
                                        server_url);
                  //   "http://39.105.109.64:8099/record/box/reportOneRecord");

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,server_return_funtion);
    
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,server_ret_msg);
    res = curl_easy_perform(curl);  


    if (res != CURLE_OK)
    {
        log("curl  res: %d \n",res);
        ret = -2;
    }
    /* always cleanup */
    curl_easy_cleanup(curl);

    /* then cleanup the formpost chain */
    curl_formfree((struct curl_httppost*)formpost);

    log("server reg msg: %s \n",server_ret_msg);
    if(strlen(server_ret_msg) != 0)
        ret  = 0;
    else
        ret  = -1;
    /* free slist */
    curl_slist_free_all (headerlist);
  }
  return ret;
}



