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

#include "proc_stat.hpp"


using namespace std;

/** 
 * @brief Constructor of the proc_stat class.
 * 
 * Constructor of the proc_stat class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
proc_stat::proc_stat(string plugin_id,
		     map<string,string> properties)
{
    // Customize if needed
    if(!initialize_plugin(properties))
	throw runtime_error("cpu plugin could not be initialized");
    
}

/** 
 * @brief Destructor of the proc_stat class.
 * 
 * Destructor of the proc_stat class.
 */
proc_stat::~proc_stat(void)
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
bool proc_stat::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    sigar_open(&sig_);

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    
    strcpy(hostname_,net_info.host_name);
    
    return true;
}

/** 
 * @brief Gets some information related to the processes running and publishes it.
 * 
 * Gets some information related to the processes running on the host and publishes 
 * it using the method <code>publish_information</code> -- defined 
 * in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data  DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool proc_stat::generate_and_publish_information(DDSDynamicDataWriter *writer,
					   DDS_DynamicData *data)
{
    
    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);
    
    //PROC STAT-------------------------------------------
    sigar_proc_stat_get(sig_,&procstat_);
    
    data->set_long("total",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.total);
    
    data->set_long("sleeping",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.sleeping);

    data->set_long("running",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.running);

    data->set_long("zombie",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.zombie);

    data->set_long("stopped",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.stopped);

    data->set_long("idle",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.idle);

    data->set_long("threads",
    		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
    		   procstat_.threads);


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
