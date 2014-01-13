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

#include "proc.hpp"


using namespace std;

/** 
 * @brief Constructor of the proc class.
 * 
 * Constructor of the proc class.
 * @param plugin_id Name of the plugin.
 * @param properties Map of properties (will be empty in this plugin).
 */
proc::proc(string plugin_id,
		   map<string,string> properties)
{
    // Customize if needed
    if(!initialize_plugin(properties))
	throw runtime_error("proc plugin could not be initialized");
    
}

/** 
 * @brief Destructor of the proc class.
 * 
 * Destructor of the memory class.
 */
proc::~proc()
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
bool proc::initialize_plugin(map<string,string> properties) 
{
    // Customize if needed
    sigar_open(&sig_);

    sigar_net_info_t net_info;
    sigar_net_info_get(sig_, &net_info);
    
    strcpy(hostname_,net_info.host_name);
    
    return true;
}

/** 
 * @brief Gets the list of the processes of a machine and publishes their 
 * status.
 * 
 * Gets the list of processes of a machine using Hyperic Sigar and publishes the status
 * of them using the method  <code>publish_information</code> -- defined and implemented
 * in the base class.
 * @param writer DDS Dynamic DataWriter.
 * @param data DDS Dynamic DataWriter to fill--using DDS Dynamic Data methods.
 * 
 * @return True if everything was right.
 */
bool proc::generate_and_publish_information(DDSDynamicDataWriter *writer,
					    DDS_DynamicData *data)
{

    data->set_string("hostname",
		     DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		     hostname_);


    sigar_proc_list_get(sig_,&proclist_);
  
    for(unsigned int i = 0; i < proclist_.number; i++) {
	
	//State
	sigar_proc_state_get(sig_,proclist_.data[i],&procstate_);
		
	data->set_long("pid",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proclist_.data[i]);
	
	data->set_string("name",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 procstate_.name);

	data->set_char("state",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procstate_.state);

	data->set_long("ppid",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procstate_.ppid);

	data->set_long("tty",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procstate_.tty);

	data->set_long("priority",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procstate_.priority);
	
	data->set_long("processor",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procstate_.processor);

	data->set_long("nice",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procstate_.nice);
	
	//Cred
	sigar_proc_cred_get(sig_,proclist_.data[i],&proccred_);

	data->set_long("uid",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccred_.uid);

	data->set_long("gid",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccred_.gid);

	data->set_long("euid",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccred_.euid);

	data->set_long("egid",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccred_.egid);

	//Cred name
	sigar_proc_cred_name_get(sig_,proclist_.data[i],&proccredname_);
	data->set_string("user",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 proccredname_.user);

	data->set_string("group",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 proccredname_.group);
			 
	
	//CPU
	sigar_proc_cpu_get(sig_,proclist_.data[i],&proccpu_);

	data->set_longlong("cpu_start_time",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccpu_.start_time);

	data->set_long("cpu_user",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccpu_.user);
	
	data->set_long("cpu_sys",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccpu_.sys);
	
	data->set_long("cpu_total",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccpu_.total);
	
	data->set_longlong("cpu_last_time",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       proccpu_.last_time);

	data->set_double("cpu_percent",
			 DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
			 proccpu_.percent*100.0);

	
	//Stat
	sigar_proc_mem_get(sig_,proclist_.data[i],&procmem_);

	data->set_long("mem_size",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procmem_.size/1024);
	
	data->set_long("mem_resident",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procmem_.resident/1024);
	
	data->set_long("mem_share",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procmem_.share/1024);

	data->set_long("mem_minor_faults",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procmem_.minor_faults);

	data->set_long("mem_major_faults",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procmem_.major_faults);

	data->set_long("mem_page_faults",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       procmem_.page_faults);


	timestamp_ = time(NULL);
	data->set_long("ts",
		       DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
		       timestamp_);
	
	if(!publish_information(writer, data))
	    return false;
	
    }

    sigar_proc_list_destroy(sig_,&proclist_);
    return true;
    
}

