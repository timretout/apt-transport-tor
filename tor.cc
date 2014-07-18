//-*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
// $Id: http.cc,v 1.59 2004/05/08 19:42:35 mdz Exp $
/* ######################################################################

   Tor Acquire Method - This is the Tor acquire method for APT.
   
   It uses libcurl

   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include "config.h"

#include <apt-pkg/fileutl.h>
#include <apt-pkg/acquire-method.h>
#include <apt-pkg/error.h>
#include <apt-pkg/hashes.h>
#include <apt-pkg/netrc.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/strutl.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <ctype.h>
#include <stdlib.h>

#include "tor.h"

#include <apti18n.h>
									/*}}}*/
using namespace std;

size_t
TorMethod::parse_header(void *buffer, size_t size, size_t nmemb, void *userp)
{
   size_t len = size * nmemb;
   TorMethod *me = (TorMethod *)userp;
   std::string line((char*) buffer, len);
   for (--len; len > 0; --len)
      if (isspace(line[len]) == 0)
      {
	 ++len;
	 break;
      }
   line.erase(len);

   if (line.empty() == true)
   {
      if (me->Server->Result != 416 && me->Server->StartPos != 0)
	 ;
      else if (me->Server->Result == 416 && me->Server->Size == me->File->FileSize())
      {
         me->Server->Result = 200;
	 me->Server->StartPos = me->Server->Size;
      }
      else
	 me->Server->StartPos = 0;

      me->File->Truncate(me->Server->StartPos);
      me->File->Seek(me->Server->StartPos);
   }
   else if (me->Server->HeaderLine(line) == false)
      return 0;

   return size*nmemb;
}

size_t 
TorMethod::write_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
   TorMethod *me = (TorMethod *)userp;

   if (me->Res.Size == 0)
      me->URIStart(me->Res);
   if(me->File->Write(buffer, size*nmemb) != true)
      return false;

   return size*nmemb;
}

int
TorMethod::progress_callback(void *clientp, double dltotal, double /*dlnow*/,
			      double /*ultotal*/, double /*ulnow*/)
{
   TorMethod *me = (TorMethod *)clientp;
   if(dltotal > 0 && me->Res.Size == 0) {
      me->Res.Size = (unsigned long long)dltotal;
   }
   return 0;
}

// TorServerState::TorServerState - Constructor			/*{{{*/
TorServerState::TorServerState(URI Srv,TorMethod * /*Owner*/) : ServerState(Srv, NULL)
{
   TimeOut = _config->FindI("Acquire::tor::Timeout",TimeOut);
   Reset();
}
									/*}}}*/

void TorMethod::SetupProxy()  					/*{{{*/
{
   URI ServerName = Queue->Uri;

   // Curl should never read proxy settings from the environment, as
   // we determine which proxy to use.  Do this for consistency among
   // methods and prevent an environment variable overriding a
   // no-proxy ("DIRECT") setting in apt.conf.
   curl_easy_setopt(curl, CURLOPT_PROXY, "");

   // Determine the proxy setting
   string UseProxy = _config->Find("Acquire::tor::Proxy", _config->Find("Acquire::tor::Proxy").c_str());

   if (UseProxy.empty() == true)
   {
      // Default proxy
      // - socks5h (actually ignored below) - use proxy for DNS resolution
      // - apt:apt@ - dummy socks authentication (for IsolateSOCKSAuth in Tor)
      // - localhost:9050 - default Tor SOCKS port
      UseProxy = "socks5h://apt:apt@localhost:9050";
   }

   // Determine what host and port to use based on the proxy settings
   Proxy = UseProxy;
   if (Proxy.Port != 1)
      curl_easy_setopt(curl, CURLOPT_PROXYPORT, Proxy.Port);
   curl_easy_setopt(curl, CURLOPT_PROXY, Proxy.Host.c_str());
   if (Proxy.User.empty() == false || Proxy.Password.empty() == false)
   {
      curl_easy_setopt(curl, CURLOPT_PROXYUSERNAME, Proxy.User.c_str());
      curl_easy_setopt(curl, CURLOPT_PROXYPASSWORD, Proxy.Password.c_str());
   }

   // Set proxy type to SOCKS5, and let proxy do DNS resolution
   curl_easy_setopt(curl, CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5_HOSTNAME);
}									/*}}}*/
// TorMethod::Fetch - Fetch an item					/*{{{*/
// ---------------------------------------------------------------------
/* This adds an item to the pipeline. We keep the pipeline at a fixed
   depth. */
bool TorMethod::Fetch(FetchItem *Itm)
{
   struct stat SBuf;
   struct curl_slist *headers=NULL;  
   char curl_errorstr[CURL_ERROR_SIZE];
   URI Uri = Itm->Uri;
   string remotehost = Uri.Host;

   // Undo any "tor" or "tor+" at the start
   string prefix="tor+";
   if ("tor" == Uri.Access)
   {
        Uri.Access = "http";
   }
   else if (!Uri.Access.compare(0, prefix.size(), prefix))
   {
        Uri.Access = Uri.Access.substr(prefix.size());
   }

   // TODO:
   //       - http::Pipeline-Depth
   //       - error checking/reporting
   //       - more debug options? (CURLOPT_DEBUGFUNCTION?)

   curl_easy_reset(curl);
   SetupProxy();

   maybe_add_auth (Uri, _config->FindFile("Dir::Etc::netrc"));

   // callbacks
   curl_easy_setopt(curl, CURLOPT_URL, static_cast<string>(Uri).c_str());
   curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, parse_header);
   curl_easy_setopt(curl, CURLOPT_WRITEHEADER, this);
   curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
   curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);
   curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, progress_callback);
   curl_easy_setopt(curl, CURLOPT_PROGRESSDATA, this);
   // options
   curl_easy_setopt(curl, CURLOPT_NOPROGRESS, false);
   curl_easy_setopt(curl, CURLOPT_FILETIME, true);
   // only allow curl to handle http, not the other stuff it supports
   curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
   curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP);

   // cache-control
   if(_config->FindB("Acquire::tor::No-Cache",
	_config->FindB("Acquire::http::No-Cache",false)) == false)
   {
      // cache enabled
      if (_config->FindB("Acquire::tor::No-Store",
		_config->FindB("Acquire::http::No-Store",false)) == true)
	 headers = curl_slist_append(headers,"Cache-Control: no-store");
      stringstream ss;
      ioprintf(ss, "Cache-Control: max-age=%u", _config->FindI("Acquire::tor::Max-Age",
		_config->FindI("Acquire::http::Max-Age",0)));
      headers = curl_slist_append(headers, ss.str().c_str());
   } else {
      // cache disabled by user
      headers = curl_slist_append(headers, "Cache-Control: no-cache");
      headers = curl_slist_append(headers, "Pragma: no-cache");
   }
   curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

   // speed limit
   int const dlLimit = _config->FindI("Acquire::tor::Dl-Limit",
		_config->FindI("Acquire::http::Dl-Limit",0))*1024;
   if (dlLimit > 0)
      curl_easy_setopt(curl, CURLOPT_MAX_RECV_SPEED_LARGE, dlLimit);

   // set header
   // Hardcoded so that all apt-transport-tor users look the same.
   curl_easy_setopt(curl, CURLOPT_USERAGENT,
			"Debian APT-CURL/1.0 (0.1)");

   // set timeout
   int const timeout = _config->FindI("Acquire::tor::Timeout",
		_config->FindI("Acquire::http::Timeout",120));
   curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
   //set really low lowspeed timeout (see #497983)
   curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, DL_MIN_SPEED);
   curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, timeout);

   // set redirect options and default to 10 redirects
   bool const AllowRedirect = _config->FindB("Acquire::tor::AllowRedirect",
	_config->FindB("Acquire::http::AllowRedirect",true));
   curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, AllowRedirect);
   curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10);

   // debug
   if(_config->FindB("Debug::Acquire::tor", false))
      curl_easy_setopt(curl, CURLOPT_VERBOSE, true);

   // error handling
   curl_errorstr[0] = '\0';
   curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errorstr);

   // If we ask for uncompressed files servers might respond with content-
   // negotiation which lets us end up with compressed files we do not support,
   // see 657029, 657560 and co, so if we have no extension on the request
   // ask for text only. As a sidenote: If there is nothing to negotate servers
   // seem to be nice and ignore it.
   if (_config->FindB("Acquire::tor::SendAccept", _config->FindB("Acquire::http::SendAccept", true)) == true)
   {
      size_t const filepos = Itm->Uri.find_last_of('/');
      string const file = Itm->Uri.substr(filepos + 1);
      if (flExtension(file) == file)
	 headers = curl_slist_append(headers, "Accept: text/*");
   }

   // if we have the file send an if-range query with a range header
   if (stat(Itm->DestFile.c_str(),&SBuf) >= 0 && SBuf.st_size > 0)
   {
      char Buf[1000];
      sprintf(Buf, "Range: bytes=%li-", (long) SBuf.st_size);
      headers = curl_slist_append(headers, Buf);
      sprintf(Buf, "If-Range: %s", TimeRFC1123(SBuf.st_mtime).c_str());
      headers = curl_slist_append(headers, Buf);
   }
   else if(Itm->LastModified > 0)
   {
      curl_easy_setopt(curl, CURLOPT_TIMECONDITION, CURL_TIMECOND_IFMODSINCE);
      curl_easy_setopt(curl, CURLOPT_TIMEVALUE, Itm->LastModified);
   }

   // go for it - if the file exists, append on it
   File = new FileFd(Itm->DestFile, FileFd::WriteAny);
   Server = new TorServerState(Itm->Uri, this);

   // keep apt updated
   Res.Filename = Itm->DestFile;

   // get it!
   CURLcode success = curl_easy_perform(curl);

   // If the server returns 200 OK but the If-Modified-Since condition is not
   // met, CURLINFO_CONDITION_UNMET will be set to 1
   long curl_condition_unmet = 0;
   curl_easy_getinfo(curl, CURLINFO_CONDITION_UNMET, &curl_condition_unmet);

   File->Close();
   curl_slist_free_all(headers);

   // cleanup
   if (success != 0)
   {
      _error->Error("%s", curl_errorstr);
      unlink(File->Name().c_str());
      return false;
   }

   // server says file not modified
   if (Server->Result == 304 || curl_condition_unmet == 1)
   {
      unlink(File->Name().c_str());
      Res.IMSHit = true;
      Res.LastModified = Itm->LastModified;
      Res.Size = 0;
      URIDone(Res);
      return true;
   }
   Res.IMSHit = false;

   if (Server->Result != 200 && // OK
	 Server->Result != 206 && // Partial
	 Server->Result != 416) // invalid Range
   {
      char err[255];
      snprintf(err, sizeof(err) - 1, "HttpError%i", Server->Result);
      SetFailReason(err);
      _error->Error("%s", err);
      // unlink, no need keep 401/404 page content in partial/
      unlink(File->Name().c_str());
      return false;
   }

   struct stat resultStat;
   if (unlikely(stat(File->Name().c_str(), &resultStat) != 0))
   {
      _error->Errno("stat", "Unable to access file %s", File->Name().c_str());
      return false;
   }
   Res.Size = resultStat.st_size;

   // invalid range-request
   if (Server->Result == 416)
   {
      unlink(File->Name().c_str());
      Res.Size = 0;
      delete File;
      Redirect(Itm->Uri);
      return true;
   }

   // Timestamp
   curl_easy_getinfo(curl, CURLINFO_FILETIME, &Res.LastModified);
   if (Res.LastModified != -1)
   {
      struct timeval times[2];
      times[0].tv_sec = Res.LastModified;
      times[1].tv_sec = Res.LastModified;
      times[0].tv_usec = times[1].tv_usec = 0;
      utimes(File->Name().c_str(), times);
   }
   else
      Res.LastModified = resultStat.st_mtime;

   // take hashes
   Hashes Hash;
   FileFd Fd(Res.Filename, FileFd::ReadOnly);
   Hash.AddFD(Fd);
   Res.TakeHashes(Hash);

   // keep apt updated
   URIDone(Res);

   // cleanup
   Res.Size = 0;
   delete File;

   return true;
}

int main()
{
   setlocale(LC_ALL, "");

   TorMethod Mth;
   curl_global_init(CURL_GLOBAL_NOTHING) ;

   return Mth.Run();
}

