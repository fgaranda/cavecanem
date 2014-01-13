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

#include "disk.hpp"

using namespace std;

/** 
 * @brief Constructor of the disk class.
 * 
 * Constructor of the disk class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
disk::disk(string plugin_id,map<string,string> properties ) 
{
    // Customize if needed
    if(!initialize_plugin(properties))
	throw runtime_error("Disk plugin could not be initialized");
}

/** 
 * @brief Destructor of the disk class.
 * 
 * Destructor of the disk class.
 */
disk::~disk(void)
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
bool disk::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    sigar_open(&sig_);

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    
    strcpy(hostname_,net_info.host_name);
    
    return true;
}

/** 
 * @brief Gets the list of the filesystems of a machine and publishes their status.
 * 
 * Gests the list of filesystems of a machine using Hyperic Sigar and publishes their
 * status using the method <code>publish_information</code>--defined and 
 * implemented in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool disk::generate_and_publish_information(DDSDynamicDataWriter *writer,
					    DDS_DynamicData *data)
{

    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);
    
    sigar_file_system_list_get(sig_,&fslist_);
    
    for(unsigned int i = 0; i < fslist_.number; i++) {
	if(fslist_.data[i].type == SIGAR_FSTYPE_LOCAL_DISK ||
	   fslist_.data[i].type == SIGAR_FSTYPE_NETWORK) {
	    sigar_file_system_usage_t fsusage;
	    sigar_file_system_usage_get(sig_,fslist_.data[i].dir_name,&fsusage);

	    data->set_string("name",
	    		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
	    		     fslist_.data[i].dev_name);
	    
	    data->set_string("mountdir",
			     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			     fslist_.data[i].dir_name);
	    
	    // type = 2  FSTYPE_LOCAL_DISK
	    // type = 3  FSTYPE_NETWORK
	    data->set_long("type",
			   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			   fslist_.data[i].type);

	    data->set_long("total", 
			   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			   fsusage.total);

	    data->set_long("used", 
			   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			   fsusage.used);

	    data->set_long("free", 
			   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			   fsusage.free);

	    data->set_double("used_per",
			     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			     fsusage.use_percent*100);

	    data->set_double("free_per",
			     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			     100.0-fsusage.use_percent*100);

	    timestamp_ = time(NULL);
	    data->set_long("ts",
			   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			   timestamp_);

	    
	    if(!publish_information(writer, data))
		return false;

	}
	
    }
    
    
    sigar_file_system_list_destroy(sig_,&fslist_);
    return true;
}
