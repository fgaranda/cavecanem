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

#ifndef CPU_HPP
#define CPU_HPP

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
 * @class cpu
 * This class defines the cpu plugin. The objective of this plugin is
 * to get and publish some information related to the use and load of the CPU. 
 * To achieve this objective it uses the Hyperic Sigar library.
 * @return 
 */
class DLL_EXPORTS cpu : public cc_plugin {
 public:
    cpu(std::string plugin_id,
        std::map<std::string,std::string> properties);
    virtual ~cpu();
    bool generate_and_publish_information(DDSDynamicDataWriter *writer,
					  DDS_DynamicData *data);

    virtual std::string plugin_class() 
	{ 
	    return "cpu";
	}
    
 private:
    bool initialize_plugin(std::map<std::string, std::string> properties);  
    sigar_t *sig_;
    sigar_cpu_t cpu_info_;
    sigar_loadavg_t loadavg_;
    long timestamp_;
    char hostname_[SIGAR_MAXHOSTNAMELEN];
};


/** 
 * @brief Defines the "C" create function of the cpu plugin
 * (class factory).
 * 
 * Defines the "C" create function of the plugin cpu. It returns a new
 * object of the class <code>cpu</code>.
 * @param plugin_id The name of the plugin
 * @param properties Map of the properties of the plugin.
 * 
 * @return 
 */
extern "C" DLL_EXPORTS cc_plugin* create_cpu(std::string plugin_id,
				 std::map<std::string,std::string> properties) {
    return new cpu(plugin_id,properties);
}

#endif //CPU_HPP
