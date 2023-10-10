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

#include <cstring>
#include <string>
#include <hostcomm.h>
#include "mabmgr.h"
#include "mab_api.h"
#include "mab_exports.h"
#include "mab_include.h"
#include "datatypes.h"
#include "nimapi.h"
#include <arpa/inet.h>
#include <netdb.h>
#include "tokenize.h"
#include "fpSonicUtils.h"

#define MABD_CMD_BUFFSZ  2048
MabMgr *mab;

const string INTFS_PREFIX = "E";

DEBUGSH_CLI(MabMgrRadiusStats,
            "show system internal mabmgr radius-stats",
            SHOW_COMMAND,
            SYSTEM_DEBUG_COMMAND,
            INTERNAL_COMMAND,
            "MabMgr related commands",
            "Radius stats")
{
    mab->showDebugInfo(this);
}


mabGlobalConfigCacheParams_t MabMgr::mabGlobalConfigTable = { MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF,
                                                              MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF,
                                                              MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF };

MabMgr::MabMgr(DBConnector *configDb, DBConnector *stateDb, DBConnector *appDb) :
                           m_confMabPortTbl(configDb, "MAB_PORT_CONFIG_TABLE"),
                           m_confMabGlobalTbl(configDb, "MAB_GLOBAL_CONFIG_TABLE"),
                           m_confRadiusServerTable(configDb, "RADIUS_SERVER"),
                           m_confRadiusGlobalTable(configDb, "RADIUS"),
                           m_mgmtIntfTbl(appDb, "MGMT_INTF_TABLE"),
                           m_IntfTbl(configDb, CFG_INTF_TABLE_NAME),
                           m_VlanIntfTbl(configDb, CFG_VLAN_INTF_TABLE_NAME),
                           m_LoIntfTbl(configDb, CFG_LOOPBACK_INTERFACE_TABLE_NAME),
                           m_PoIntfTbl(configDb, CFG_LAG_INTF_TABLE_NAME) {

    Logger::linkToDbNative("mabmgr");
    SWSS_LOG_DEBUG("Installing MabMgr commands");
    mab = this;
    DebugShCmd::install(new MabMgrRadiusStats());

}

void MabMgr::showDebugInfo(DebugShCmd *cmd)
{
    char buffer[MABD_CMD_BUFFSZ];

    memset(buffer, 0, sizeof(buffer));

    if (L7_SUCCESS == mabRadiusClientGetStats(buffer, sizeof(buffer))) 
    {
        DEBUGSH_OUT(cmd, "Dumping MabMgr radius stats\n\n");
        DEBUGSH_OUT(cmd, "==============================================\n");

        DEBUGSH_OUT(cmd, "%s", buffer);
        DEBUGSH_OUT(cmd, "\n==============================================\n\n");
    }
}

std::vector<Selectable*> MabMgr::getSelectables() {
    vector<Selectable *> selectables{ &m_confMabPortTbl, &m_confMabGlobalTbl, &m_confRadiusServerTable, &m_confRadiusGlobalTable, 
                                      &m_mgmtIntfTbl, &m_IntfTbl, &m_VlanIntfTbl, &m_PoIntfTbl, &m_LoIntfTbl };
    return selectables;
}


bool MabMgr::processDbEvent(Selectable *tbl) {

    SWSS_LOG_DEBUG("Received a MAB Database event");

    //check the source table and accordingly invoke the appropriate handlers

    if (tbl == ((Selectable *) & m_confMabPortTbl)) {
        return processMabConfigPortTblEvent(tbl);
    }

    if (tbl == ((Selectable *) & m_confMabGlobalTbl)) {
        return processMabConfigGlobalTblEvent(tbl);
    }

    if (tbl == ((Selectable *) & m_confRadiusServerTable)) {
        return processRadiusServerTblEvent(tbl);
    }

    if (tbl == ((Selectable *) & m_confRadiusGlobalTable)) {
        return processRadiusGlobalTblEvent(tbl);
    }

    if (tbl == ((Selectable *) & m_mgmtIntfTbl)) {
         return processMgmtIntfTblEvent(tbl);
    }

    if ((tbl == ((Selectable *) & m_IntfTbl)) ||
        (tbl == ((Selectable *) & m_VlanIntfTbl)) ||        
        (tbl == ((Selectable *) & m_LoIntfTbl)) ||        
        (tbl == ((Selectable *) & m_PoIntfTbl))) {
         return processIntfTblEvent(tbl);
    }

    SWSS_LOG_DEBUG("Received event UNKNOWN to MAB, ignoring ");
    return false;
}

//Process the config db table events

bool MabMgr::processMabConfigPortTblEvent(Selectable *tbl) 
{
  SWSS_LOG_ENTER();
  SWSS_LOG_DEBUG("Received a table config event on MAB_PORT_CONFIG_TABLE table");

  std::deque<KeyOpFieldsValuesTuple> entries;
  m_confMabPortTbl.pops(entries);

  SWSS_LOG_DEBUG("Received %d entries", (int) entries.size());

  /* Nothing popped */
  if (entries.empty())
  {
      return false;
  }

  // Check through all the data
  for (auto entry : entries) 
  {
    std::string key = kfvKey(entry);
    std::string  op = kfvOp(entry);
    bool task_result = false;
    L7_uint32 intIfNum;

    SWSS_LOG_DEBUG("Received %s as key and %s as OP", key.c_str(), op.c_str());

    if(key.find(INTFS_PREFIX) == string::npos)
    {
        SWSS_LOG_NOTICE("Invalid key format. No 'E' prefix: %s", key.c_str());
        continue;
    }

    if(fpGetIntIfNumFromHostIfName(key.c_str(), &intIfNum) != L7_SUCCESS)
    {
        SWSS_LOG_NOTICE("Unable to get the internal interface number for %s.", key.c_str());
        continue;
    }

    if (op == SET_COMMAND)
        {
            task_result = doMabPortTableSetTask(entry, intIfNum);
        }
        else if (op == DEL_COMMAND)
        {
            task_result = doMabPortTableDeleteTask(entry, intIfNum);
        }
        if (!task_result)
            return false;
     }
     return true;
}

bool MabMgr::doMabPortTableSetTask(const KeyOpFieldsValuesTuple & t, L7_uint32 & intIfNum)
{
    SWSS_LOG_ENTER();
    const std::string & key = kfvKey(t);

    // Update mabPortConfigCache cache with incoming table data
    mabPortConfigCacheParams_t mabPortConfigCache;
    mabPortConfigCache.mab_enable = MABMGR_MAB_PORT_ENABLE_DEF;
    mabPortConfigCache.mab_auth_type = MABMGR_MAB_PORT_AUTH_TYPE_DEF;
    mabPortConfigCache.mab_server_timeout = MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF;

    for (auto item = kfvFieldsValues(t).begin(); item != kfvFieldsValues(t).end(); item++)
    {
        const std::string & field = fvField(*item);
        const std::string & value = fvValue(*item);

        if (field == "mab_enable")
        {
            if (value == "true")
               mabPortConfigCache.mab_enable = L7_ENABLE;
            else if (value == "false")
               mabPortConfigCache.mab_enable = L7_DISABLE;
            else {
               SWSS_LOG_WARN("Invalid configuration option received for mab enable: %s", value.c_str());
               continue;
            }
        }
        if (field == "mab_auth_type")
        {
            if (value == "pap")
                mabPortConfigCache.mab_auth_type= L7_AUTHMGR_PORT_MAB_AUTH_TYPE_PAP;
            else if (value == "chap")
                mabPortConfigCache.mab_auth_type = L7_AUTHMGR_PORT_MAB_AUTH_TYPE_CHAP;
            else if (value == "eap-md5")
                mabPortConfigCache.mab_auth_type = L7_AUTHMGR_PORT_MAB_AUTH_TYPE_EAP_MD5;
            else {
               SWSS_LOG_WARN("Invalid configuration option received for mab auth type: %s", value.c_str());
               continue;
            }
        }
        if (field == "server_timeout")
        {
            mabPortConfigCache.mab_server_timeout =  (unsigned int)stoi(value);
        }
    }

    mabPortConfigTableMap::iterator iter = m_mabPortConfigMap.find(key);
    if(iter == m_mabPortConfigMap.end())
    {
        m_mabPortConfigMap.insert(pair<std::string, mabPortConfigCacheParams_t>(key, mabPortConfigCache));
        mabPortConfigTableMap::iterator iter = m_mabPortConfigMap.find(key);

        if(mabPortConfigCache.mab_enable != MABMGR_MAB_PORT_ENABLE_DEF)
        {
            if (L7_SUCCESS != mabPortMABEnableSet(intIfNum, mabPortConfigCache.mab_enable))
            {
              iter->second.mab_enable = MABMGR_MAB_PORT_ENABLE_DEF;
              SWSS_LOG_ERROR("Unable to enable MAB operationally.");
            }
        }
        if(mabPortConfigCache.mab_auth_type != MABMGR_MAB_PORT_AUTH_TYPE_DEF)
        {
            if (L7_SUCCESS != mabPortMABAuthTypeSet(intIfNum, mabPortConfigCache.mab_auth_type))
            {
              iter->second.mab_auth_type = MABMGR_MAB_PORT_AUTH_TYPE_DEF;
              SWSS_LOG_ERROR("Unable to set MAB authentication type operationally.");
            }
        }
        if(MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF != mabPortConfigCache.mab_server_timeout)
        {
            if (L7_SUCCESS != mabPortMABServerTimeoutSet(intIfNum, mabPortConfigCache.mab_server_timeout))
            {
              iter->second.mab_server_timeout = MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF;
              SWSS_LOG_ERROR("Unable to set MAB port server timeout.");
            }
        }
     }
     else //Interface entry already exists in local cache, check for any parameter change for Add/Update/Delete
     {
        // mab_enable
        if (((iter->second.mab_enable == MABMGR_MAB_PORT_ENABLE_DEF) &&
            (mabPortConfigCache.mab_enable != MABMGR_MAB_PORT_ENABLE_DEF)) ||
            ((iter->second.mab_enable != MABMGR_MAB_PORT_ENABLE_DEF) &&
            (mabPortConfigCache.mab_enable != iter->second.mab_enable)))
        {
            if (L7_SUCCESS == mabPortMABEnableSet(intIfNum, mabPortConfigCache.mab_enable))
            {
              iter->second.mab_enable = mabPortConfigCache.mab_enable;
            }
            else
	    {
              SWSS_LOG_ERROR("Unable to enable/disable MAB operationally.");
              return false;
            }
        }
        // mab_auth_type
        if (((iter->second.mab_auth_type == MABMGR_MAB_PORT_AUTH_TYPE_DEF) &&
            (mabPortConfigCache.mab_auth_type != MABMGR_MAB_PORT_AUTH_TYPE_DEF)) ||
            ((iter->second.mab_auth_type != MABMGR_MAB_PORT_AUTH_TYPE_DEF) &&
            (mabPortConfigCache.mab_auth_type != iter->second.mab_auth_type)))
        {
            if (L7_SUCCESS == mabPortMABAuthTypeSet(intIfNum, mabPortConfigCache.mab_auth_type))
            {
              iter->second.mab_auth_type = mabPortConfigCache.mab_auth_type;
            }
            else
	    {
              SWSS_LOG_ERROR("Unable to set MAB authentication type operationally.");
              return false;
            }
        }
        if (iter->second.mab_server_timeout != mabPortConfigCache.mab_server_timeout)
        {
            if (L7_SUCCESS == 
                   mabPortMABServerTimeoutSet(intIfNum, mabPortConfigCache.mab_server_timeout))
            {
              iter->second.mab_server_timeout = mabPortConfigCache.mab_server_timeout;
            }
            else
            {
              SWSS_LOG_ERROR("Unable to set MAB port server timeout.");
              return false;
            }
        }
      }
      return true;
}

bool MabMgr::doMabPortTableDeleteTask(const KeyOpFieldsValuesTuple & t, L7_uint32 & intIfNum)
{
    SWSS_LOG_ENTER();
    const std::string & key = kfvKey(t);
    mabPortConfigTableMap::iterator iter = m_mabPortConfigMap.find(key);
    if(iter != m_mabPortConfigMap.end())
    {
      if (iter->second.mab_enable != MABMGR_MAB_PORT_ENABLE_DEF)
      {
            if (L7_SUCCESS == mabPortMABEnableSet(intIfNum, MABMGR_MAB_PORT_ENABLE_DEF))
            {
                iter->second.mab_enable = MABMGR_MAB_PORT_ENABLE_DEF;
            }
            else
            {
              SWSS_LOG_ERROR("Unable to set MAB enable with default.");
              return false;
            }
      }
      if (iter->second.mab_auth_type != MABMGR_MAB_PORT_AUTH_TYPE_DEF)
      {
            if (L7_SUCCESS == mabPortMABAuthTypeSet(intIfNum, MABMGR_MAB_PORT_AUTH_TYPE_DEF))
            {
              iter->second.mab_auth_type = MABMGR_MAB_PORT_AUTH_TYPE_DEF;
            }
            else
            {
              SWSS_LOG_ERROR("Unable to set MAB authentication type with default.");
              return false;
            }
      }
      if (MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF != iter->second.mab_server_timeout)
      {
          if (L7_SUCCESS == 
                   mabPortMABServerTimeoutSet(intIfNum, MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF))
          {
             iter->second.mab_server_timeout = MABMGR_MAB_PORT_SERVER_TIMEOUT_DEF; 
          }
          else
          {
             SWSS_LOG_ERROR("Unable to set MAB port server timeout.");
             return false;
          }
      }
    }
    return true;
}

bool MabMgr::processMabConfigGlobalTblEvent(Selectable *tbl) 
{
  SWSS_LOG_DEBUG("Received a table config event on MAB_GLOBAL_CONFIG_TABLE table");

  std::deque<KeyOpFieldsValuesTuple> entries;
  m_confMabGlobalTbl.pops(entries);

  SWSS_LOG_DEBUG("Received %d entries", (int) entries.size());

  /* Nothing popped */
  if (entries.empty())
  {
    return false;
  }

  // Check through all the data
  for (auto entry : entries) 
  {
    std::string key = kfvKey(entry);
    std::string  op = kfvOp(entry);
    bool task_result = false;

    SWSS_LOG_DEBUG("Received %s as key and %s as OP", key.c_str(), op.c_str());

    if (op == SET_COMMAND)
    {
            task_result = doMabGlobalTableSetTask(entry);
        }
        else if (op == DEL_COMMAND)
        {
            task_result = doMabGlobalTableDeleteTask();
        }
        if (!task_result)
            return false;
    }
    return true;
}

bool MabMgr::doMabGlobalTableSetTask(const KeyOpFieldsValuesTuple & t)
{
    SWSS_LOG_ENTER();

    // Update mabGlobalConfigCache with incoming table data
    mabGlobalConfigCacheParams_t mabGlobalConfigCache;
    mabGlobalConfigCache.group_size = MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF;
    mabGlobalConfigCache.separator = MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF;
    mabGlobalConfigCache.attrCase = MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF;

    for (auto item = kfvFieldsValues(t).begin(); item != kfvFieldsValues(t).end(); item++)
    {
        const std::string & field = fvField(*item);
        const std::string & value = fvValue(*item);

        if (field == "group_size")
        {
            if(value == "1")
               mabGlobalConfigCache.group_size = L7_MAB_REQUEST_ATTRIBUTE1_GROUP_SIZE_1;
            else if(value == "2")
               mabGlobalConfigCache.group_size = L7_MAB_REQUEST_ATTRIBUTE1_GROUP_SIZE_2;
            else if(value == "4")
               mabGlobalConfigCache.group_size = L7_MAB_REQUEST_ATTRIBUTE1_GROUP_SIZE_4;
            else if(value == "12")
               mabGlobalConfigCache.group_size = L7_MAB_REQUEST_ATTRIBUTE1_GROUP_SIZE_12;
            else {
               SWSS_LOG_WARN("Invalid option recieved for groupsize MAB request format attribute1: %s", value.c_str());
               continue;
            }
        }
        if (field == "separator")
        {
            if(value == "-")
               mabGlobalConfigCache.separator = L7_MAB_REQUEST_ATTRIBUTE1_SEPARATOR_IETF;
            else if(value == ":")
               mabGlobalConfigCache.separator = L7_MAB_REQUEST_ATTRIBUTE1_SEPARATOR_LEGACY;
            else if(value == ".")
               mabGlobalConfigCache.separator = L7_MAB_REQUEST_ATTRIBUTE1_SEPARATOR_DOT;
            else {
               SWSS_LOG_WARN("Invalid option recieved for separator MAB request format attribute1: %s", value.c_str());
               continue;
            }
        }
        if (field == "case")
        {
            if(value == "lowercase")
               mabGlobalConfigCache.attrCase = L7_MAB_REQUEST_ATTRIBUTE1_CASE_LOWER;
            else if(value == "uppercase")
               mabGlobalConfigCache.attrCase = L7_MAB_REQUEST_ATTRIBUTE1_CASE_UPPER;
            else {
               SWSS_LOG_WARN("Invalid option recieved for case MAB request format attribute1: %s", value.c_str());
               continue;
            }
        }
    }

    // Update MAB global config placeholder with table updates
    // group_size
    if (((mabGlobalConfigTable.group_size == MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF) &&
       (mabGlobalConfigCache.group_size != MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF)) ||
       ((mabGlobalConfigTable.group_size != MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF) &&
       (mabGlobalConfigCache.group_size != mabGlobalConfigTable.group_size)))
    {
       if (L7_SUCCESS == mabRequestFormatAttribut1GroupSizeSet(mabGlobalConfigCache.group_size))
       {
         mabGlobalConfigTable.group_size = mabGlobalConfigCache.group_size;
       }
       else
       {
         SWSS_LOG_ERROR("Unable to set the groupsize for formatting the MAB attribute1.");
         return false;
       }
    }
    // separator
    if (((mabGlobalConfigTable.separator == MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF) &&
       (mabGlobalConfigCache.separator != MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF)) ||
       ((mabGlobalConfigTable.separator != MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF) &&
       (mabGlobalConfigCache.separator != mabGlobalConfigTable.separator)))
    {
       if (L7_SUCCESS == mabRequestFormatAttribute1SeparatorSet(mabGlobalConfigCache.separator))
       {
         mabGlobalConfigTable.separator = mabGlobalConfigCache.separator;
       }
       else
       {
         SWSS_LOG_ERROR("Unable to set the separator for formatting the MAB attribute1.");
       return false;
       }
    }
    // case
    if (((mabGlobalConfigTable.attrCase == MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF) &&
       (mabGlobalConfigCache.attrCase != MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF)) ||
       ((mabGlobalConfigTable.attrCase != MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF) &&
       (mabGlobalConfigCache.attrCase != mabGlobalConfigTable.attrCase)))
    {
       if (L7_SUCCESS == mabRequestFormatAttribute1CaseSet(mabGlobalConfigCache.attrCase))
       {
         mabGlobalConfigTable.attrCase = mabGlobalConfigCache.attrCase;
       }
       else
       {
         SWSS_LOG_ERROR("Unable to set the case for formatting the MAB attribute1.");
         return false;
       }
    }
    return true;
}

bool MabMgr::doMabGlobalTableDeleteTask()
{
    SWSS_LOG_ENTER();

    if (mabGlobalConfigTable.group_size != MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF)
    {
         if (L7_SUCCESS == mabRequestFormatAttribut1GroupSizeSet(MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF))
         {
           mabGlobalConfigTable.group_size = MABMGR_REQUEST_ATTRIBUTE1_GROUP_SIZE_DEF;
         }
         else
         {
           SWSS_LOG_ERROR("Unable to set groupsize with default for formatting the MAB attribute1.");
           return false;
         }
    }
    if (mabGlobalConfigTable.separator != MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF)
    {
         if (L7_SUCCESS == mabRequestFormatAttribute1SeparatorSet(MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF))
         {
           mabGlobalConfigTable.separator = MABMGR_REQUEST_ATTRIBUTE1_SEPARATOR_DEF;
         }
         else
         {
           SWSS_LOG_ERROR("Unable to set separator with default for formatting the MAB attribute1.");
           return false;
         }
    }
    if (mabGlobalConfigTable.attrCase != MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF)
    {
         if (L7_SUCCESS == mabRequestFormatAttribute1CaseSet(MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF))
         {
           mabGlobalConfigTable.attrCase = MABMGR_REQUEST_ATTRIBUTE1_CASE_DEF;
         }
         else
         {
           SWSS_LOG_ERROR("Unable to set case for formatting the MAB attribute1.");
           return false;
         }
    }
    return true;
}

string execute(string command) {
   char buffer[128];
   string result = "";

   cout << "command is " << command << endl;
   // Open pipe to file
   FILE* pipe = popen(command.c_str(), "r");
   if (!pipe) {
      return "popen failed!";
   }

   // read till end of process:
   while (!feof(pipe)) {

      // use buffer to read and add to result
      if (fgets(buffer, 128, pipe) != NULL)
         result += buffer;
   }

   pclose(pipe);
   return result;
}

void MabMgr::updateRadiusServerGlobalKey(string newKey, string oldKey) {

   SWSS_LOG_ENTER();
   bool update = false;
   L7_RC_t rc = L7_FAILURE;

   if (0 == newKey.compare(oldKey))
   {
      return;
   }

   for (auto& item: m_radius_info.radius_auth_server_list)
   {
      /* server specific is configured */
      if (0 != item.second.server_key.size())
      {
         continue;
      }

      /* Check and update Radius server if using Global key */
      if (0 != newKey.size())
      {
         item.second.server_update = true;
         update = true;
      }
      else
      {
         rc = mabRadiusServerUpdate(RADIUS_MAB_SERVER_DELETE, "auth",
                                    item.second.server_ip.c_str(),
                                    item.second.server_priority.c_str(),
                                    oldKey.c_str(),
                                    item.second.server_port.c_str(),
                                    item.second.server_vrf.c_str(),
                                    item.second.server_source_intf.c_str());
         if (L7_SUCCESS != rc)
         {
             SWSS_LOG_ERROR("Unable to update radius server details for MAB ip = %s,  port = %s, priority = %s",
                            item.second.server_ip.c_str(),
                            item.second.server_port.c_str(),
                            item.second.server_priority.c_str());
         }
      }
   }

   /* Due to global key change update server needed */
   if (true == update)
   {
      updateRadiusServer();
   }
}

void MabMgr::updateRadiusServer() {

   SWSS_LOG_ENTER();
   L7_RC_t rc = L7_FAILURE;
   struct addrinfo* result;
   char ip[INET6_ADDRSTRLEN+1];
   void * src = NULL;

   SWSS_LOG_NOTICE("Deriving new RADIUS Servers for MAB");

   for (auto& item: m_radius_info.radius_auth_server_list)
   {
       if (false == item.second.server_update)
       {
           SWSS_LOG_INFO("skipped %s as update not needed.", item.first.c_str());
           continue;  
       }

       if (getaddrinfo(item.first.c_str(), NULL, NULL, &result) || result == NULL)
       {
           SWSS_LOG_WARN("skipped %s as it could not resolve.", item.first.c_str());
           item.second.dns_ok = false;
           continue;
       }

       if(result->ai_family == AF_INET)
           src = &((struct sockaddr_in*)result->ai_addr)->sin_addr;
       else
           src = &((struct sockaddr_in6*)result->ai_addr)->sin6_addr;

       inet_ntop(result->ai_family, src, ip, INET6_ADDRSTRLEN+1);
       freeaddrinfo(result);

       //Check if radius server has key configured. If not,
       // pick global key. If key does not exist, skip to next server. 
       if ((item.second.server_key  == "") && (m_radius_info.m_radiusGlobalKey == ""))
       {
           SWSS_LOG_WARN("skipped %s as no key is configured.", item.first.c_str());
           continue;  
       }

       string newKey = m_radius_info.m_radiusGlobalKey; 
       if (item.second.server_key != "")
       {
           newKey = item.second.server_key;
       }

       string radiusIp(ip);
       item.second.server_ip = radiusIp;
       
       rc = mabRadiusServerUpdate(RADIUS_MAB_SERVER_ADD, "auth", item.second.server_ip.c_str(),
                              item.second.server_priority.c_str(),
                              newKey.c_str(),
                              item.second.server_port.c_str(),
                              item.second.server_vrf.c_str(),
                              item.second.server_source_intf.c_str());
       if (L7_SUCCESS != rc)
       {
           SWSS_LOG_ERROR("Radius server update - Unable to update radius server details for MAB.");
           return;
       }
       SWSS_LOG_NOTICE("Updating radius details for MAB  ip = %s,  port = %s, priority = %s", 
                       item.second.server_ip.c_str(),
                       item.second.server_port.c_str(),
                       item.second.server_priority.c_str());
       item.second.server_update = false;
       item.second.dns_ok = true;
   }
   return;
}

void MabMgr::updateRadiusGlobalInfo() {
  L7_RC_t rc = L7_FAILURE;
  string nas_ip("");
  string nas_id("");

  if (m_radius_info.nas_ip.size())
  {
    nas_ip = m_radius_info.nas_ip;
    nas_id = m_radius_info.nas_ip;
  }
  else if (m_radius_info.mgmt_ip.size())
  {
    nas_ip = m_radius_info.mgmt_ip;
    nas_id = m_radius_info.mgmt_ip;
  }
  else if (m_radius_info.mgmt_ipv6.size())
  {
    nas_ip = m_radius_info.mgmt_ipv6;
    nas_id = m_radius_info.mgmt_ipv6;
  }

  if (nas_ip.size() && nas_id.size())
  {
    rc = mabRadiusGlobalCfgUpdate(nas_ip.c_str(), nas_id.c_str());
    if (L7_SUCCESS != rc)
    {
       SWSS_LOG_ERROR("Unable to update radius global configuration nas ip = %s,  nas_id = %s",
                      nas_ip.c_str(), nas_id.c_str());
    }
  }
  return;
}

void MabMgr::reloadRadiusServers() 
{
   SWSS_LOG_ENTER();
   L7_RC_t rc = L7_FAILURE;
   bool server_update = false;

   SWSS_LOG_NOTICE("Reloading RADIUS Servers for MAB");

   /*Check for servers that failed DNS resolution  */
   for (auto& item: m_radius_info.radius_auth_server_list)
   {
       if (false == item.second.dns_ok)
       {
           item.second.server_update = true;
           server_update = true;
       }
   }

   if (true == server_update)
   {
       SWSS_LOG_NOTICE("Reloading DNS failed RADIUS Servers for MAB");
       updateRadiusServer();
   }

   rc = mabRadiusServerUpdate(RADIUS_MAB_SERVERS_RELOAD, "auth", 
                              NULL, NULL, NULL, NULL, NULL, NULL);

   if (L7_SUCCESS != rc)
   {
       SWSS_LOG_ERROR("RADIUS Servers reload - Unable to reload.");
   }

   return;
}

bool MabMgr::processRadiusServerTblEvent(Selectable *tbl) 
{
  SWSS_LOG_ENTER();
  SWSS_LOG_NOTICE("Received a RADIUS_SERVER event");

  deque<KeyOpFieldsValuesTuple> entries;
  m_confRadiusServerTable.pops(entries);

  SWSS_LOG_NOTICE("Received %d entries", (int) entries.size());

  /* Nothing popped */
  if (entries.empty())
  {
    return false;
  }

  // Check through all the data
  for (auto entry : entries)
  {
    string key = kfvKey(entry);
    string val = kfvOp(entry);
    string cmd("");

    SWSS_LOG_NOTICE("Received %s as key and %s as OP", key.c_str(), val.c_str());

    if (val == SET_COMMAND)
    {
      SWSS_LOG_NOTICE("SET operation on RADIUS_SERVER table");

      m_radius_info.radius_auth_server_list[key].server_port = "";
      m_radius_info.radius_auth_server_list[key].server_key = "";
      m_radius_info.radius_auth_server_list[key].server_priority = "";
      m_radius_info.radius_auth_server_list[key].server_vrf = "";
      m_radius_info.radius_auth_server_list[key].server_source_intf = "";
      m_radius_info.radius_auth_server_list[key].server_update = true;
      m_radius_info.radius_auth_server_list[key].dns_ok = true;

      // Look at the data that is sent for this key

      for (auto i : kfvFieldsValues(entry))
      {
        string a = fvField(i);
        string b = fvValue(i);

        SWSS_LOG_DEBUG("Received %s as field and %s as value", a.c_str(), b.c_str());

        if (a == "passkey")
        {
          DBus::Struct<int, std::__cxx11::basic_string<char> > ret;
          ret = HostQuery_keyctl("pwDecrypt", b.c_str());
          if (0 != ret._1)
          {
            SWSS_LOG_ERROR("RADIUS server key is not decrypted properly and hence the MAB service is not steady.");
            return false;
          }
          m_radius_info.radius_auth_server_list[key].server_key = ret._2;
        }
        else if (a == "auth_port")
        {
          m_radius_info.radius_auth_server_list[key].server_port = b; 
        }
        else if (a == "priority")
        {
          m_radius_info.radius_auth_server_list[key].server_priority = b; 
        }
        else if (a == "vrf")
        {
          m_radius_info.radius_auth_server_list[key].server_vrf = b; 
        }
        else if (a == "src_intf")
        {
          m_radius_info.radius_auth_server_list[key].server_source_intf = b; 
        }
      }
      updateRadiusServer();
    }
    else if (val == DEL_COMMAND)
    {
      L7_RC_t rc = L7_FAILURE;
      SWSS_LOG_INFO("Delete Radius server for MAB %s ", 
                       m_radius_info.radius_auth_server_list[key].server_ip.c_str()); 
      // server deleted
      rc = mabRadiusServerUpdate(RADIUS_MAB_SERVER_DELETE, "auth",
                                 m_radius_info.radius_auth_server_list[key].server_ip.c_str(),
                                 m_radius_info.radius_auth_server_list[key].server_priority.c_str(),
                                 m_radius_info.radius_auth_server_list[key].server_key.c_str(),
                                 m_radius_info.radius_auth_server_list[key].server_port.c_str(),
                                 m_radius_info.radius_auth_server_list[key].server_vrf.c_str(),
                                 m_radius_info.radius_auth_server_list[key].server_source_intf.c_str());
      if (rc != L7_SUCCESS)
      {
         SWSS_LOG_ERROR("Radius server delete - Unable to delete radius server details for MAB.");
      }
      m_radius_info.radius_auth_server_list.erase(key);
    }
  }

  return true;
}

bool MabMgr::processRadiusGlobalTblEvent(Selectable *tbl) 
{
  SWSS_LOG_ENTER();
  SWSS_LOG_NOTICE("Received a RADIUS event");
  string tmp_radiusGlobalKey(m_radius_info.m_radiusGlobalKey);
  string tmp_nas_ip(m_radius_info.nas_ip);

  deque<KeyOpFieldsValuesTuple> entries;
  m_confRadiusGlobalTable.pops(entries);

  SWSS_LOG_NOTICE("Received %d entries", (int) entries.size());

  /* Nothing popped */
  if (entries.empty())
  {
    return false;
  }

  // Check through all the data
  for (auto entry : entries)
  {
    string key = kfvKey(entry);
    string val = kfvOp(entry);
    string cmd("");

    SWSS_LOG_NOTICE("Received %s as key and %s as OP", key.c_str(), val.c_str());

    // Removal of radius key and nas_ip as these are also sent as a SET
    m_radius_info.m_radiusGlobalKey = "";
    m_radius_info.nas_ip = "";

    if (val == SET_COMMAND)
    {
      SWSS_LOG_NOTICE("SET operation on RADIUS table");

      // Look at the data that is sent for this key
      for (auto i : kfvFieldsValues(entry))
      {

        string a = fvField(i);
        string b = fvValue(i);

        SWSS_LOG_DEBUG("Received %s as field and %s as value", a.c_str(), b.c_str());

        if (a == "passkey")
        {
          DBus::Struct<int, std::__cxx11::basic_string<char> > ret;
          ret = HostQuery_keyctl("pwDecrypt", b.c_str());
          if (0 != ret._1)
          {
            SWSS_LOG_ERROR("RADIUS server key is not decrypted properly and hence the MAB service is not steady.");
            return false;
          }
          m_radius_info.m_radiusGlobalKey = ret._2;
        }
        else if (a == "nas_ip")
        {
          m_radius_info.nas_ip = b;
        }
      }
    }
    else if (val == DEL_COMMAND)
    {
      m_radius_info.m_radiusGlobalKey = ""; 
      m_radius_info.nas_ip = "";
    }
  }

  updateRadiusServerGlobalKey(m_radius_info.m_radiusGlobalKey, tmp_radiusGlobalKey);

  if (m_radius_info.nas_ip != tmp_nas_ip)
  {
    updateRadiusGlobalInfo();
  }

  return true;
}

bool MabMgr::processMgmtIntfTblEvent(Selectable *tbl)
{
  std::deque<KeyOpFieldsValuesTuple> entries;
  m_mgmtIntfTbl.pops(entries);
  SWSS_LOG_NOTICE("Received %d entries from config event on MGMT_INTERFACE Table", (int) entries.size());

  // Removal of MGMT IP also is sent as a SET
  m_radius_info.mgmt_ip = "";
  m_radius_info.mgmt_ipv6 = "";

  for (auto entry : entries) 
  {
    std::string key = kfvKey(entry);
    SWSS_LOG_NOTICE("key %s", key.c_str());

    auto tokens = tokenize(key, ':');
    SWSS_LOG_NOTICE("size %d", tokens.size());

    // pick only IPv4 address of the management interface
    if (2 == tokens.size())
    {
      // eth0:a.b.c.d/mask
      auto tokens1 = tokenize(tokens[1], '/');
      SWSS_LOG_NOTICE("Management IPv4 %s", tokens1[0].c_str());
      m_radius_info.mgmt_ip = tokens1[0];
    }
    else if (tokens.size() > 2)
    {
      // eth0:2001::64/mask. Remove "eth0:"
      string ipv6Str = key.substr(5);

      auto tokens1 = tokenize(ipv6Str, '/');
      SWSS_LOG_NOTICE("Management IPv6 %s", tokens1[0].c_str());
      m_radius_info.mgmt_ipv6 = tokens1[0];
    }
  }

  string mgmt_intf("eth0");

  if (0 == m_radius_info.nas_ip.size())
  {
    SWSS_LOG_NOTICE("Interface %s address update for nas ip.", mgmt_intf.c_str());
    updateRadiusGlobalInfo();
  }

  reloadRadiusServers();

  return true;
}

bool MabMgr::IsSourceIntf(const string interface)
{
  for (auto& item: m_radius_info.radius_auth_server_list)
  {
    if (item.second.server_source_intf == interface)
    {
      return true;
    }
  }
  return false;
}

bool MabMgr::processIntfTblEvent(Selectable *tbl)
{
  std::deque<KeyOpFieldsValuesTuple> entries;

  if (tbl == ((Selectable *) & m_IntfTbl))
  {
    m_IntfTbl.pops(entries);
    SWSS_LOG_NOTICE("Received %d entries from config event on INTERFACE Table", (int) entries.size());
  }
  else if (tbl == ((Selectable *) & m_VlanIntfTbl))
  {
    m_VlanIntfTbl.pops(entries);
    SWSS_LOG_NOTICE("Received %d entries from config event on VLAN_INTERFACE Table", (int) entries.size());
  }
  else if (tbl == ((Selectable *) & m_LoIntfTbl))
  {
    m_LoIntfTbl.pops(entries);
    SWSS_LOG_NOTICE("Received %d entries from config event on LOOPBACK_INTERFACE Table", (int) entries.size());
  }
  else if (tbl == ((Selectable *) & m_PoIntfTbl))
  {
    m_PoIntfTbl.pops(entries);
    SWSS_LOG_NOTICE("Received %d entries from config event on PORTCHANNEL_INTERFACE Table", (int) entries.size());
  }

  for (auto entry : entries) 
  {
    std::string key = kfvKey(entry);
    SWSS_LOG_NOTICE("key %s", key.c_str());

    auto key_tokens = tokenize(key, '|');
    SWSS_LOG_NOTICE("size %d", key_tokens.size());

    if (2 == key_tokens.size())
    {
      // Ethernet0|IPAddress
      if (IsSourceIntf(key_tokens[0]))
      {
        auto ip_tokens = tokenize(key_tokens[1], '/');
        SWSS_LOG_NOTICE("Interface %s used as Source Interface. Address %s/%s", 
                        key_tokens[0].c_str(), ip_tokens[0].c_str(), ip_tokens[1].c_str());
        reloadRadiusServers();
        break;
      }
    }
  }

  return true;
}

