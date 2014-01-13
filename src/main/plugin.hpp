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

#ifndef PLUGIN_HPP
#define PLUGIN_HPP

#include <ndds/ndds_cpp.h>
#include <iostream>
#include <map>
#include <stdexcept>

class cc_plugin {

    // protected:
    //     ~cc_plugin(void) {}

public:
    /** 
     * @brief Returns the name of the plugin.
     *
     * Must be defined by each plugin and must be unique across plugins
     * @return Returns the name of the plugin.
     */
    virtual std::string plugin_class() = 0;
  

    /** 
     * @brief The plugin gathers the information and publishes it.
     * 
     * @param writer A pointer to the DDS DynamicDataWriter.
     * @param data A pointer to the DDS Dynamic Data to fill.
     * 
     * @return Returns true if everything was correct and false if not.
     */
    virtual bool generate_and_publish_information(DDSDynamicDataWriter *writer,
						  DDS_DynamicData *data) = 0;
    
    /** 
     * @brief Plugins must use this method to publish the information in generate_and_publish_information().
     * 
     * Abstracts plugin developers from the publication of the gathered information using DDS. Therefore, 
     * each plugin must call this method whithin generate_and_publish_information() to publish.
     * @param writer A pointer to the DDS DynamicDataWriter.
     * @param data A pointer to the filled DDS Dynamic Data.
     * 
     * @return 
     */
    virtual bool publish_information(DDSDynamicDataWriter *writer,
				     DDS_DynamicData *data) 
    {
	DDS_InstanceHandle_t instance_handle = DDS_HANDLE_NIL;
	DDS_ReturnCode_t retcode = writer->write(*data,instance_handle);
	if (retcode != DDS_RETCODE_OK) {
	    std::cerr << "Error writing instance" << std::endl;
	    return false;
	}
	return true;
    }
  
    /** 
     * @brief Deletes the plugin.
     * 
     * Deletes the plugin using the C++ function <code>delete()</code>.
     */
    void destroy_plugin() 
    { 
	delete this;
    }

};

/** 
 * @brief Typedefs the function to create the plugins.
 * 
 * Typedefs the function to create a new plugin (create_function).
 * @param plugin_id Name of the plugin.
 * @param properties Map of plugin properties.
 * 
 * @return 
 */
typedef cc_plugin* cc_create_plugin_t(std::string plugin_id, 
				      std::map<std::string,std::string> properties);


#endif //PLUGIN_HPP
