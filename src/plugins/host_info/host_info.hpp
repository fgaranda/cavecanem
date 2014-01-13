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

#ifndef HOST_INFO_HPP
#define HOST_INFO_HPP

#ifdef WIN32
#define DLL_EXPORTS __declspec(dllexport)
#else
#define DLL_EXPORTS
#endif

#include <ctime>
#include <map>

extern "C" {
#include <sigar.h>
}

#include <plugin.hpp>

/** 
 * @class host_info
 * This class defines the host_info plugin. The objective of this plugin is
 * to get and publish some general information related to the host. 
 * To achieve this objective it uses the Hyperic Sigar library.
 * @return 
 */
class DLL_EXPORTS host_info : public cc_plugin {
 public:
    host_info(std::string plugin_id,
	 std::map<std::string,std::string> properties);
    virtual ~host_info();
    bool generate_and_publish_information(DDSDynamicDataWriter *writer,
					  DDS_DynamicData *data);

    virtual std::string plugin_class() 
	{ 
	    return "host_info";
	}
    
 private:
    bool initialize_plugin(std::map<std::string, std::string> properties);  
    sigar_t *sig_;
    sigar_sys_info_t sysinfo_;
    sigar_uptime_t uptime_;
    long timestamp_;
    char hostname_[SIGAR_MAXHOSTNAMELEN];

};


/** 
 * @brief Defines the "C" create function of the host_info plugin
 * (class factory).
 * 
 * Defines the "C" create function of the plugin host_info. It returns a new
 * object of the class <code>host_info</code>.
 * @param plugin_id The name of the plugin
 * @param properties Map of the properties of the plugin.
 * 
 * @return 
 */
extern "C" DLL_EXPORTS cc_plugin* create_host_info(std::string plugin_id,
				 std::map<std::string,std::string> properties) {
    return new host_info(plugin_id,properties);
}

#endif //HOST_INFO_HPP
