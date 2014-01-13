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

#include "net_load.hpp"


using namespace std;

/** 
 * @brief Constructor of the net_load class.
 * 
 * Constructor of the net_load class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
net_load::net_load(string plugin_id,
		   map<string,string> properties)
{
    // Customize if needed
    if(!initialize_plugin(properties))
	throw runtime_error("net_load plugin could not be initialized");
    
}

/** 
 * @brief Destructor of the net_load class.
 * 
 * Destructor of the memory class.
 */
net_load::~net_load()
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
bool net_load::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    sigar_open(&sig_);

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    
    strcpy(hostname_,net_info.host_name);
    
    return true;
}

/** 
 * @brief Gets the list of the network interfaces of a machine and publishes their 
 * status.
 * 
 * Gets the network interfaces of a machine using Hyperic Sigar and publishes the status
 * of them using the method <code>publish_information</code> -- defined and implemented
 * in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool net_load::generate_and_publish_information(DDSDynamicDataWriter *writer,
						DDS_DynamicData *data)
{

    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);


    sigar_net_interface_list_get(sig_,&iflist_);
  
    for(unsigned int i = 0; i < iflist_.number; i++) {
	sigar_net_interface_config_get(sig_,iflist_.data[i],&ifconfig_);
	
	//Interface config
	data->set_string("device",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 ifconfig_.name);
	
	data->set_string("type",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 ifconfig_.type);
	
	data->set_string("description",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 ifconfig_.description);

	//Deal with net addresses
	char hwaddr[100];
	char address[100];
	char destination[100];
	char broadcast[100];

	sigar_net_address_to_string(sig_,&ifconfig_.hwaddr,hwaddr);
	sigar_net_address_to_string(sig_,&ifconfig_.address,address);
	sigar_net_address_to_string(sig_,&ifconfig_.destination,destination);
	sigar_net_address_to_string(sig_,&ifconfig_.broadcast,broadcast);

	data->set_string("hwaddr",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 hwaddr);

	data->set_string("address",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 address);
	
	data->set_string("destination",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 destination);

	data->set_string("broadcast",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 broadcast);

	data->set_long("flags",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifconfig_.flags);

	data->set_long("mtu",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifconfig_.mtu);	

	data->set_long("metric",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifconfig_.metric);

	//Interface Stat	
	sigar_net_interface_stat_get(sig_,iflist_.data[i],&ifstat_);
	
	//received
	data->set_longlong("rx_packets",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.rx_packets);

	data->set_longlong("rx_bytes",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.rx_bytes);

	data->set_long("rx_dropped",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.rx_dropped);

	data->set_long("rx_overruns",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.rx_overruns);
	
	data->set_long("rx_frame",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.rx_frame);

	
	//transmited
	data->set_longlong("tx_packets",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_packets);

	data->set_longlong("tx_bytes",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_bytes);

	data->set_long("tx_errors",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_errors);

	data->set_long("tx_dropped",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_dropped);

	data->set_long("tx_overruns",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_overruns);

	data->set_long("tx_collisions",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_collisions);

	data->set_long("tx_carrier",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       ifstat_.tx_carrier);

	timestamp_ = time(NULL);
	data->set_long("ts",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       timestamp_);
	
	if(!publish_information(writer, data))
	    return false;
	
    }

    sigar_net_interface_list_destroy(sig_,&iflist_);
    return true;
    
}

