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

#include "memory.hpp"


using namespace std;

/** 
 * @brief Constructor of the memory class.
 * 
 * Constructor of the memory class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
memory::memory(string plugin_id,
	       map<string,string> properties)
{
    // Customize if needed
    if(!initialize_plugin(properties))
	throw runtime_error("memory plugin could not be initialized");
    
}

/** 
 * @brief Destructor of the memory class.
 * 
 * Destructor of the memory class.
 */
memory::~memory(void)
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
bool memory::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    sigar_open(&sig_);

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    
    strcpy(hostname_,net_info.host_name);
    
    return true;
}

/** 
 * @brief Gets some information related to physical and swap memory and publishes it.
 * 
 * Gets some information related to physical and swap memory 
 * and publishes it using the method <code>publish_information</code> -- defined 
 * in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data  DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool memory::generate_and_publish_information(DDSDynamicDataWriter *writer,
					      DDS_DynamicData *data)
{

    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);

    //MEM
    sigar_mem_get(sig_,&mem_info_);
    
    data->set_long("mem_total",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   mem_info_.total/1024);

    data->set_long("mem_used",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   mem_info_.used/1024);

    data->set_long("mem_free",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   mem_info_.free/1024);

    data->set_long("mem_actual_used",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   mem_info_.actual_used/1024);
    
    data->set_long("mem_actual_free",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   mem_info_.actual_free/1024);
    
    data->set_double("mem_used_percent",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     mem_info_.used_percent);
    
    data->set_double("mem_free_percent",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     mem_info_.free_percent);
    

    //SWAP
    sigar_swap_get(sig_,&swap_info_);

    data->set_long("swap_total",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   swap_info_.total/1024);

    data->set_long("swap_used",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   swap_info_.used/1024);

    data->set_long("swap_free",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   swap_info_.free/1024);

    data->set_long("swap_page_in",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   swap_info_.page_in);

    data->set_long("swap_page_out",
		   DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		   swap_info_.page_out);

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
