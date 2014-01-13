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

#ifndef NET_LOAD_HPP
#define NET_LOAD_HPP

#ifdef WIN32
#define DLL_EXPORTS __declspec(dllexport)
#else
#define DLL_EXPORTS
#endif

#include <ctime>
#include <map>
extern "C" {
#include <sigar.h>
#include <sigar_format.h>
}
#include <plugin.hpp>

/** 
 * @class net_load
 * This class defines the net_load plugin. The objective of this plugin is to 
 * get and publish the status of the network interfaces of a machine. To achieve
 * this objetive it uses the Hyperic Sigar library.
 */
class DLL_EXPORTS net_load : public cc_plugin {
 public:

    net_load(std::string plugin_id,
	     std::map<std::string,std::string> properties);
    virtual ~net_load();
    
    bool generate_and_publish_information(DDSDynamicDataWriter *writer,
					  DDS_DynamicData *data);

    virtual std::string plugin_class() 
    { 
	    return "net_load";
    }

 private:
    bool initialize_plugin(std::map<std::string, std::string> properties);  
    sigar_t *sig_;
    sigar_net_interface_list_t iflist_;
    sigar_net_interface_config_t ifconfig_;
    sigar_net_interface_stat_t ifstat_;
    long timestamp_;
    char hostname_[SIGAR_MAXHOSTNAMELEN];

};

/** 
 * @brief Defines the "C" create function of the plugin net_load
 * (class factory).
 * 
 * Defines the "C" create function of the plugin memory. It returns a new
 * object of the class <code>net_load</code>.
 * @param plugin_id The name of the plugin
 * @param properties Map of the properties of the plugin.
 * 
 * @return 
 */
extern "C" DLL_EXPORTS cc_plugin* create_net_load(std::string plugin_id,
				      std::map<std::string,std::string> properties) {
    return new net_load(plugin_id,properties);
}

#endif //NET_LOAD_HPP
