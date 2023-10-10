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

#ifndef _MABMGR_H_
#define _MABMGR_H_

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

#include "redisapi.h"
#include "auth_mgr_exports.h"
#include "mab_exports.h"

typedef struct radius_server_info_s {
  std::string server_port;
  std::string server_key;
  std::string server_ip;
  std::string server_priority;
  std::string server_vrf;
  std::string server_source_intf;
  bool        server_update;
  bool        dns_ok;
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

#define MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF L7_MAB_REQUEST_ATTRIBUTE1_GROUP_SIZE_2
#define MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF L7_MAB_REQUEST_ATTRIBUTE1_SEPARATOR_LEGACY
#define MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF L7_MAB_REQUEST_ATTRIBUTE1_CASE_UPPER
#define MABMGR_MAB_PORT_ENABLE_DEF L7_DISABLE
#define MABMGR_MAB_PORT_AUTH_TYPE_DEF L7_AUTHMGR_PORT_MAB_AUTH_TYPE_EAP_MD5
#define MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF  FD_MAB_PORT_SERVER_TIMEOUT

/* MAB GLOBAL config table param cache Info */
typedef struct {
    L7_MAB_REQUEST_ATTRIBUTE1_GROUP_SIZE_t group_size;
    L7_MAB_REQUEST_ATTRIBUTE1_SEPARATOR_t  separator;
    L7_MAB_REQUEST_ATTRIBUTE1_CASE_t attrCase;
} mabGlobalConfigCacheParams_t;

/* MAB port config table param cache Info */
typedef struct mabPortConfigCacheParams_t {
    bool mab_enable;
    L7_AUTHMGR_PORT_MAB_AUTH_TYPE_t  mab_auth_type;
    L7_uint32  mab_server_timeout;
} mabPortConfigCacheParams_t;

/* MAP to store MAB port config table params,
 * Key is "interface-id" (Eg. Ethernet0)
 * Value is "mabPortConfigCacheParams_t"
 */
typedef std::map<std::string, mabPortConfigCacheParams_t> mabPortConfigTableMap;

using namespace swss;
using namespace std;

class MabMgr
{ 
public:
    MabMgr(DBConnector *configDb, DBConnector *stateDb, DBConnector *appDb);
    std::vector<Selectable*> getSelectables();
    bool processDbEvent(Selectable *source);

    /* Placeholder for MAB Global table config params */
    static mabGlobalConfigCacheParams_t mabGlobalConfigTable;

    /* Debug routine. */
    void showDebugInfo(DebugShCmd *cmd);

private:
    //tables this component listens to
    SubscriberStateTable m_confMabPortTbl;
    SubscriberStateTable m_confMabGlobalTbl;
    SubscriberStateTable m_confRadiusServerTable;
    SubscriberStateTable m_confRadiusGlobalTable;
    SubscriberStateTable m_mgmtIntfTbl;
    SubscriberStateTable m_IntfTbl;
    SubscriberStateTable m_VlanIntfTbl;
    SubscriberStateTable m_LoIntfTbl;
    SubscriberStateTable m_PoIntfTbl;

    radius_info_t m_radius_info;
    mabPortConfigTableMap     m_mabPortConfigMap;

    // DB Event handler functions
    bool processMabConfigPortTblEvent(Selectable *tbl);
    bool processMabConfigGlobalTblEvent(Selectable *tbl);
    bool processRadiusServerTblEvent(Selectable *tbl);
    bool processRadiusGlobalTblEvent(Selectable *tbl);
    bool processMgmtIntfTblEvent(Selectable *tbl);
    bool processIntfTblEvent(Selectable *tbl);
    bool doMabGlobalTableSetTask(const KeyOpFieldsValuesTuple & t);
    bool doMabGlobalTableDeleteTask();
    bool doMabPortTableSetTask(const KeyOpFieldsValuesTuple & t, L7_uint32 & intIfNum);
    bool doMabPortTableDeleteTask(const KeyOpFieldsValuesTuple & t, L7_uint32 & intIfNum);

    void updateRadiusServer();
    void updateRadiusServerGlobalKey(string newKey, string oldKey);
    void updateRadiusGlobalInfo();
    bool IsSourceIntf(const string interface);
    void reloadRadiusServers() ;
};

#endif // _MABMGR_H_
