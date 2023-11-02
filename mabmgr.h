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
  bool        server_update;
  bool        dns_ok;
}radius_server_info_t;

typedef std::map<std::string, radius_server_info_t> radius_server_info_map_t;

typedef struct radius_info_s {
  string m_radiusGlobalKey;
  radius_server_info_map_t radius_auth_server_list;
}radius_info_t;

#define MABMGR_MAB_PORT_ENABLE_DEF     DISABLE
#define MABMGR_MAB_PORT_AUTH_TYPE_DEF  AUTHMGR_PORT_MAB_AUTH_TYPE_EAP_MD5
#define MABMGR_MAB_USER_CFG_ACCESS_TYPE_DEF     "allow" /*CG_PAC*/
#define MABMGR_MAB_USER_VLAN_ID_DEF           0 /*CG_PAC*/
#define MABMGR_MAB_USER_SESSION_TIMEOUT_DEF   60 /*CG_PAC*/
#define MABMGR_MAB_LAUTH_SUCCESS 1  /*CG_PAC*/
#define MABMGR_MAB_LAUTH_FAILED  0  /*CG_PAC*/

/* MAB port config table param cache Info */
typedef struct mabPortConfigCacheParams_t {
    bool mab_enable;
    AUTHMGR_PORT_MAB_AUTH_TYPE_t  mab_auth_type;
} mabPortConfigCacheParams_t;

/* MAB User config table param cache Info */
typedef struct mabUserConfigCacheParams_t { /*CG_PAC*/
    std::string access_type; /*allow list of the source mac. Default: “allow”*/
    int vlan_id;             /*VLAN to be associated with the authorized client*/
    int session_timeout;     /*Client session time*/
} mabUserConfigCacheParams_t;

/* MAP to store MAB port config table params,
 * Key is "interface-id" (Eg. Ethernet0)
 * Value is "mabPortConfigCacheParams_t"
 */
typedef std::map<std::string, mabPortConfigCacheParams_t> mabPortConfigTableMap;

/*CG_PAC*/
/*MAP to store MAB user configuration table parameters
 * Key: MAC Address of Supplicant
 * Value: mabUserConfigCacheParams_t
 * */
typedef std::map<std::string, mabUserConfigCacheParams_t> mabUserConfigTableMap;

/*CG_PAC: attrInfo_t of ~/radius/radius_attr_parse.h */
typedef struct lauth_attrInfo_s
{ 
  unsigned char   userName[65];
  unsigned int   userNameLen;

  //unsigned char   serverState[SERVER_STATE_LEN];
  //unsigned int   serverStateLen;

  //unsigned char   serverClass[SERVER_CLASS_LEN];
  //unsigned int   serverClassLen;

  unsigned int   sessionTimeout;
  //unsigned int   terminationAction;

  //unsigned int   accessLevel;    
  //unsigned char   idFromServer;   /* Most recent ID in EAP pkt received from Auth Server (0-255) */
  //unsigned char   vlanString[RADIUS_VLAN_ASSIGNED_LEN+1];
  unsigned int   vlanId; /* parsed VLAN id from vlan string */
  //unsigned int   attrFlags;
  //unsigned int   vlanAttrFlags;
  //bool     rcvdEapAttr;
}lauth_attrInfo_t;

using namespace swss;
using namespace std;

class MabMgr
{ 
public:
    MabMgr(DBConnector *configDb, DBConnector *stateDb, DBConnector *appDb);
    std::vector<Selectable*> getSelectables();
    bool processDbEvent(Selectable *source);
    int lauthClientChallengeProcess(string client_mac_key); /*CG_PAC*/
private:
    //tables this component listens to
    SubscriberStateTable m_confMabPortTbl;
    SubscriberStateTable m_confRadiusServerTable;
    SubscriberStateTable m_confRadiusGlobalTable;
    SubscriberStateTable m_confMabUserCfgTbl; //CG_PAC

    radius_info_t m_radius_info;
    mabPortConfigTableMap     m_mabPortConfigMap;
    mabUserConfigTableMap     m_mabUserConfigMap; //CG_PAC

    // DB Event handler functions
    bool processMabConfigPortTblEvent(Selectable *tbl);
    bool processRadiusServerTblEvent(Selectable *tbl);
    bool processRadiusGlobalTblEvent(Selectable *tbl);
    bool doMabPortTableSetTask(const KeyOpFieldsValuesTuple & t, uint32 & intIfNum);
    bool doMabPortTableDeleteTask(const KeyOpFieldsValuesTuple & t, uint32 & intIfNum);
    bool processMabUserCfgTblEvent(Selectable *tbl); //CG_PAC
    bool doMabUserCfgTableSetTask(const KeyOpFieldsValuesTuple & t);
    bool doMabUserCfgTableDeleteTask(const KeyOpFieldsValuesTuple & t);
    void updateRadiusServer();
    void updateRadiusServerGlobalKey(string newKey, string oldKey);
    void reloadRadiusServers() ;
};

#endif // _MABMGR_H_
