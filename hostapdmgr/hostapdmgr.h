/*
 * Copyright 2019 Broadcom Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _HOSTAPDMGR_H_
#define _HOSTAPDMGR_H_

#include <swss/dbconnector.h>
#include <swss/schema.h>
#include <swss/table.h>
#include <swss/macaddress.h>
#include <swss/notificationproducer.h>
#include <swss/subscriberstatetable.h>
#include <swss/producerstatetable.h>
#include <swss/table.h>
#include <swss/select.h>
#include <swss/timestamp.h>
#include <swss/debugsh.h>
#include <map>
#include <string>
#include "netmsg.h"
#include "redisapi.h"

using namespace swss;
using namespace std;

#define REAUTH_PERIOD             3600
#define PAC_SERVER_TIMEOUT_DEF    30
#define PAC_QUIET_PERIOD_DEF      30

void hostapdHandleDumpError(void *cbData);

typedef struct hostapd_glbl_info_s {
  unsigned int enable_auth;
}hostapd_glbl_info_t;
  
typedef struct hostapd_intf_info_s {
  std::string capabilities;
  std::string control_mode;
  unsigned int admin_status;
  unsigned int link_status;
  unsigned int quiet_period   = PAC_QUIET_PERIOD_DEF;
  unsigned int server_timeout = PAC_SERVER_TIMEOUT_DEF;
  bool server_timeout_modified = false;
  bool quiet_period_modified   = false;
  bool config_created;
}hostapd_intf_info_t;

typedef struct radius_server_info_s {
  std::string server_port;
  std::string server_key;
  std::string server_priority;
  std::string server_ip;
  std::string server_vrf;
  std::string server_source_intf;
  bool config_ok;
}radius_server_info_t;

typedef std::map<std::string, radius_server_info_t> radius_server_info_map_t;

typedef struct radius_info_s {
  string m_radiusGlobalKey;
  std::string nas_ip;
  std::string mgmt_ip;
  std::string mgmt_ipv6;
  radius_server_info_map_t radius_auth_server_list;  
  radius_server_info_map_t radius_acct_server_list;  
}radius_info_t;

typedef std::map<std::string, hostapd_intf_info_t> hostapd_intf_info_map_t;

class HostapdMgr : public NetMsg
{ 
public:
  HostapdMgr(DBConnector *configDb, DBConnector *appDb);
  std::vector<Selectable*> getSelectables();
  bool processDbEvent(Selectable *source);
  virtual void onMsg(int nlmsg_type, struct nl_object *obj);
  void killHostapd(void);
  void showDebugInfo(DebugShCmd *cmd, string intf);
  string getStdIfFormat(string intf);

private:
  //tables this component listens to
  SubscriberStateTable m_confHostapdPortTbl;
  SubscriberStateTable m_confHostapdGlobalTbl;
  SubscriberStateTable m_confRadiusServerTable;
  SubscriberStateTable m_confRadiusGlobalTable;
  SubscriberStateTable m_mgmtIntfTbl;
  SubscriberStateTable m_IntfTbl;
  SubscriberStateTable m_VlanIntfTbl;
  SubscriberStateTable m_LoIntfTbl;
  SubscriberStateTable m_PoIntfTbl;

  hostapd_glbl_info_t m_glbl_info;
  hostapd_intf_info_map_t m_intf_info;
  radius_info_t m_radius_info;
  string m_radiusServerInUse;
  radius_server_info_t m_radiusServerInUseInfo;
  unsigned int active_intf_cnt;

  bool start_hostapd;
  bool stop_hostapd;

  void setPort(const string & alias, const hostapd_intf_info_t &intf_info);
  void delPort(const string & alias);
    
  // DB Event handler functions
  bool processHostapdConfigPortTblEvent(Selectable *tbl);
  bool processHostapdConfigGlobalTblEvent(Selectable *tbl);
  bool processRadiusServerTblEvent(Selectable *tbl);
  bool processRadiusGlobalTblEvent(Selectable *tbl);
  bool processMgmtIntfTblEvent(Selectable *tbl);
  bool processIntfTblEvent(Selectable *tbl);

  void writeToFile(const string& filename, const string& value);
  void informHostapd(const string& type, const vector<string> & interfaces);
  void createConfFile(const string& intf);
  void deleteConfFile(const string& intf);
  pid_t getHostapdPid(void);
  int waitForHostapdInit(pid_t hostapd_pid);
  void sendSignal(void);
  void updateRadiusServer();
  void hostapdDot1xWpaEventSend(const string& interface, const string& event, string& val);
  int  hostapdWpaSyncSend(const char *ctrl_ifname, const char * cmd, char *buf, size_t *len);
  void setPortDot1xTimeoutParams();
  bool IsSourceIntf(const string interface);
};

#endif // _HOSTAPDMGR_H_
