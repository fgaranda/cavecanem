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


#ifndef PLUGIN_MANAGER_HPP
#define PLUGIN_MANAGER_HPP

#include <iostream>
#include <map>

#include <ndds/osapi/osapi_library.h>
#include <ndds/ndds_cpp.h>

#include "plugin.hpp"
#include "xml_parser.hpp"

#ifndef CAVECANEM_DIR
#define CAVECANEM_DIR ""
#endif


/** 
 * @class dynamicdata_info
 * Stores the information related to the dynamic data used to publish
 * the plugin information in the DDS Global Data Space, that is, a 
 * DDS Dynamic DataWriter and the DDS Dynamic Data.
 */
struct dynamicdata_info {
    DDSDynamicDataWriter *writer;
    DDS_DynamicData *data;
};

/** 
 * @class plugin_manager
 * Addresses the load and unload of plugins. This process involves
 * the initialization and destruction of DDS entities used within the
 * plugins.
 */
class plugin_manager {
public:
    plugin_manager(std::string cfgfile);
    ~plugin_manager();

    bool initialize_dds(int domain_id, 
			std::string qos_file,
			std::string qos_library,
			std::string qos_profile);
    bool load_plugins();
    void publish_plugins_information();
    void unload_plugins();
    bool shutdown_dds();

private:
    bool load_plugin(std::string plugin_name, 
		     std::string dir);

    bool create_dds_participant_and_publisher(int domain_id,
					      std::string qos_configuration_file,
					      std::string qos_library,
					      std::string qos_profile);
    
    bool create_dds_topic_and_datawriter(std::string plugin_name,
					 std::string qos_library,
					 std::string qos_profile,
					 std::string topic_name,
					 DDS_TypeCode *type_code,
					 DDS_DataWriterQos *datawriter_qos);
    

    //    bool create_topics_and_datawriters();
    std::map<std::string, cc_plugin *> plugin_map_;
    void *library_;
    //    std::map<std::string, cc_create_plugin_t*> plugin_factory_map_;

    DDSDomainParticipant *participant_;
    DDSPublisher *publisher_;

    DDSDynamicDataWriter *disk_writer_;
    DDS_DynamicData *disk_data_;

    std::map<std::string, cc_plugin *> plugins_factmap_;
    std::map<std::string, void *> libraries_map_;
    std::map<std::string, dynamicdata_info> dynamicdata_info_map_;

    cc_general_properties general_properties_;
    std::map<std::string, cc_plugin_properties> plugin_properties_map_;
    std::map<std::string, int> period_counter_map_;
};

#endif //PLUGIN_MANAGER_HPP
