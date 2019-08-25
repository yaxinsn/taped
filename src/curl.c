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
//#include <winsock2.h>
#include <curl/curl.h>
#include <ctype.h>

typedef unsigned char BYTE;

#define TOHEX(x) ((x)>9 ? (x)+55 : (x)+48)
void URLEncode(char* szIn, char** pOut);
void set_up_formpost(curl_httppost** formpost,curl_httppost** lastptr)
{
	

  /* Fill in the submit field too, even if this is rarely needed */
  curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_LOCAL_NUMBER",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);

  curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_CALLER_NUMBER",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);
  

curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_CALLEE_NUMBER",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);

curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_DIRECTION",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);

curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "BOX_ID",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);

curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_BEGINTIME",
               CURLFORM_COPYCONTENTS, "2018-06-02 05:33;41",
               CURLFORM_END);

curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "CALL_CALLEE_ENDTIME",
               CURLFORM_COPYCONTENTS, "2018-06-02 05:33;41",
               CURLFORM_END);

curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "SECRET",
               CURLFORM_COPYCONTENTS, "1",
               CURLFORM_END);

  curl_formadd((curl_httppost**)formpost,
               (curl_httppost**)lastptr,
               CURLFORM_COPYNAME, "t.g",
               CURLFORM_FILE, "./t.g",
               CURLFORM_FILENAME, "t.g",
               CURLFORM_END);
}
int main(int argc, char *argv[])
{
  CURL *curl;
//  CURLcode res;

  CURLM *multi_handle;
  int still_running;

  struct HttpPost *formpost=NULL;
  struct HttpPost *lastptr=NULL;
  struct curl_slist *headerlist=NULL;
  char buf[] = "Expect:";

  char name[] = "t.g";
  char* pUrlName = NULL;
  URLEncode(name, &pUrlName);


#if 1

set_up_formpost((curl_httppost**)&formpost,(curl_httppost**)&lastptr);
#else
  /* Fill in the file upload field */
  curl_formadd((curl_httppost**)&formpost,
               (curl_httppost**)&lastptr,
               CURLFORM_COPYNAME, "File1",
               CURLFORM_FILE, "./t.g",
               CURLFORM_FILENAME, name,
               CURLFORM_END);
/*  curl_formadd((curl_httppost**)&formpost,
               (curl_httppost**)&lastptr,
               CURLFORM_COPYNAME, "filename",
               CURLFORM_FILENAME, "tt.bmp",
               CURLFORM_END);
*/
  /* Fill in the filename field */
  curl_formadd((curl_httppost**)&formpost,
               (curl_httppost**)&lastptr,
               CURLFORM_COPYNAME, "filename",
               CURLFORM_COPYCONTENTS, "tt.bmp",
               CURLFORM_END);


  /* Fill in the submit field too, even if this is rarely needed */
  curl_formadd((curl_httppost**)&formpost,
               (curl_httppost**)&lastptr,
               CURLFORM_COPYNAME, "CmdUpload",
               CURLFORM_COPYCONTENTS, "UpLoad",
               CURLFORM_END);
#endif
  curl = curl_easy_init();
  multi_handle = curl_multi_init();

  /* initalize custom header list (stating that Expect: 100-continue is not
     wanted */
  headerlist = curl_slist_append(headerlist, buf);
  if(curl && multi_handle) {
    int perform=0;

    /* what URL that receives this POST */
    curl_easy_setopt(curl, CURLOPT_URL,
                     "http://39.105.109.64:8099/record/box/reportOneRecord");

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist);
    curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);

    curl_multi_add_handle(multi_handle, curl);

    while(CURLM_CALL_MULTI_PERFORM ==
          curl_multi_perform(multi_handle, &still_running));

    while(still_running) {
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
    curl_formfree((curl_httppost*)formpost);

    /* free slist */
    curl_slist_free_all (headerlist);
  }
  delete[] pUrlName;
  return 0;
}

void URLEncode(char* szIn, char** pOut)
{
    int i;
 int nInLenth = strlen(szIn);
 int nFlag = 0;
 BYTE byte;
 *pOut = new char[nInLenth*3];
 char* szOut = *pOut;
 for (int i=0; i<nInLenth; i++)
 {
  byte = szIn[i];
  if (isalnum(byte))
  {
   szOut[nFlag++] = byte;
  }
  else
  {
   if (isspace(byte))
   {
    szOut[nFlag++] = '+';
   }
   else
   {
    szOut[nFlag++] = '%';
    szOut[nFlag++] = TOHEX(byte>>4);
    szOut[nFlag++] = TOHEX(byte%16);
   }
  }
 }
 szOut[nFlag] = '/0';
}
