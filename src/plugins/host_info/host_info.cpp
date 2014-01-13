/*   
 *   This file is part of Cave Canem, an extensible DDS-based monitoring and 
 *   intrusion detection system.
 *
 *   Copyright (C) 2011 Fernando García Aranda
 *                                                                         
 *   This program is free software: you can redistribute it and/or modify  
 *   it under the terms of the GNU Lesser General Public License as published by  
 *   the Free Software Foundation, either version 3 of the License, or     
 *   (at your option) any later version.                                   
 *                                                                         
 *   This program is distributed in the hope that it will be useful,       
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         
 *   GNU Lesser General Public License for more details.                          
 *                                                                         
 *   You should have received a copy of the GNU Lesser General Public License     
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. 
 */

#include "host_info.hpp"


using namespace std;

/** 
 * @brief Constructor of the host_info class.
 * 
 * Constructor of the host_info class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
host_info::host_info(string plugin_id,
		     map<string,string> properties)
{
    // Customize if needed
    if(!initialize_plugin(properties))
	throw runtime_error("cpu plugin could not be initialized");
    
}

/** 
 * @brief Destructor of the host_info class.
 * 
 * Destructor of the host_info class.
 */
host_info::~host_info(void)
{
    // Customize if needed
    sigar_close(sig_);

}

/** 
 * @brief Initializes the requirements of the plugin.
 * 
 * Initializes all the stuff required by the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
bool host_info::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    sigar_open(&sig_);

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    
    strcpy(hostname_,net_info.host_name);
    
    return true;
}

/** 
 * @brief Gets some information related to the host status and publishes it.
 * 
 * Gets some information related to the host status and publishes it using the 
 * method <code>publish_information</code> -- defined 
 * in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data  DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool host_info::generate_and_publish_information(DDSDynamicDataWriter *writer,
					   DDS_DynamicData *data)
{
    
    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);
    
    //SYS_INFO---------------------------------------------
    sigar_sys_info_get(sig_,&sysinfo_);
    
    data->set_string("sys_name",
    		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		     sysinfo_.name);

    data->set_string("sys_version",
    		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		     sysinfo_.version);

    data->set_string("sys_arch",
    		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		     sysinfo_.arch);

    data->set_string("sys_description",
    		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		     sysinfo_.description);
	     
    //UPTIME-----------------------------------------------
    sigar_uptime_get(sig_,&uptime_);

    data->set_double("uptime",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     uptime_.uptime);
		     
    //Timestamp (time_t)
    timestamp_ = time(NULL);
    data->set_long("ts",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   timestamp_);
    
    // Then let the base class do the job of publising-----------------------------
    if(!publish_information(writer, data))
    	return false;

    return true;

}
