/*   
 *   This file is part of Cave Canem, an extensible DDS-based monitoring and 
 *   intrusion detection system.
 *
 *   Copyright (C) 2013 Fernando García Aranda
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

#include "cpu.hpp"


using namespace std;

/** 
 * @brief Constructor of the cpu class.
 * 
 * Constructor of the cpu class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
cpu::cpu(string plugin_id,
	 map<string,string> properties)
{
    // Customize if needed
    if (initialize_plugin(properties) == false) {
        throw runtime_error("cpu plugin could not be initialized");
    }
}

/** 
 * @brief Destructor of the cpu class.
 * 
 * Destructor of the cpu class.
 */
cpu::~cpu(void)
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
bool cpu::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    if (sigar_open(&sig_) != 0) {
      return false;
    }

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    strcpy(hostname_,net_info.host_name);

    return true;
}

/** 
 * @brief Gets some information related to the cpu status and publishes it.
 * 
 * Gets some information related to the cpu--CPU usage, load average, etc.--
 * and publishes it using the method <code>publish_information</code> -- defined 
 * in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data  DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool cpu::generate_and_publish_information(DDSDynamicDataWriter *writer,
					   DDS_DynamicData *data)
{
    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);

    //CPU use
    sigar_cpu_get(sig_,&cpu_info_);
    
    data->set_double("cpu_user",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.user*100.0/cpu_info_.total);

    data->set_double("cpu_sys",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.sys*100.0/cpu_info_.total);
    
    data->set_double("cpu_nice",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.nice*100.0/cpu_info_.total);
    
    data->set_double("cpu_idle",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.idle*100.0/cpu_info_.total);

    data->set_double("cpu_wait",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.wait*100.0/cpu_info_.total);
    
    data->set_double("cpu_irq",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.irq*100.0/cpu_info_.total);
    
    data->set_double("cpu_soft_irq",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.soft_irq*100.0/cpu_info_.total);
    
    data->set_double("cpu_stolen",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     cpu_info_.stolen*100.0/cpu_info_.total);
    

    //Load average
    sigar_loadavg_get(sig_,&loadavg_);
    
    data->set_double("load_one",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     loadavg_.loadavg[0]);
    
    data->set_double("load_five",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     loadavg_.loadavg[1]);

    data->set_double("load_fifteen",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     loadavg_.loadavg[2]);
    
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
