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


#include "plugin_manager.hpp"

using namespace std;

/** 
 * @brief Constructor of the plugin_manager class
 * 
 * The constructor of the plugin_manager class parses the general configuration
 * file by XML_parser. Then, it loads the plugins indicated in the file by using 
 * load_plugins(), and finally it creates all the DDS entities trough initialize_dds().
 * @param cfgfile General XML configuration file.
 */
plugin_manager::plugin_manager(string cfgfile)
{

    //Here we should get all the XML information
    //to deal with the plugins, etc.
    if(XML_parser::get_singleton()->parse_general_configuration_file(cfgfile))
	general_properties_ = XML_parser::get_singleton()->get_general_properties();

    if(!load_plugins()) {
	unload_plugins();
	throw runtime_error("The plugin manager was not able to load all the plugins");
    }
    
    if(!initialize_dds(general_properties_.domain_id,
    		       general_properties_.qos_file,
    		       general_properties_.qos_library,
    		       general_properties_.qos_profile)) {
	throw runtime_error("The plugin manager was not able to initialize DDS on all the plugins");
	shutdown_dds();
	unload_plugins();
    }
    
}

 
/** 
 * @brief Destructor of the class plugin_manager.
 * 
 * The destructor of the class plugin_manager shutdowns all the DDS entities 
 * and unloads all the plugins allocated by load_plugins() by using shutdown_dds() and
 * unload_plugins().
 */
plugin_manager::~plugin_manager()
{
    shutdown_dds();
    unload_plugins();
}


/** 
 * @brief Loads all the cc_plugins specified in the general configuration file
 * 
 * Loads the plugins specified in the general configuration file for each plugin
 * library -- directory containing plugin definitions.
 *
 * @return True if plugins were loaded correctly and False if they were not.
 */
bool plugin_manager::load_plugins()
{
    for(map<string, list<string> >::iterator it = general_properties_.plugin_list_map.begin();
	it != general_properties_.plugin_list_map.end(); ++it)
	for(list<string>::iterator it2 = (it->second).begin();
	    it2 != (it->second).end(); ++it2)
	    if(!load_plugin(*it2,it->first)) //(name,dir)
		return false;
    
    return true;
}

/**
 * @brief Unloads all the plugins loaded in load_plugins()
 *
 * This method iterates both through the plugin_map_ and the libraries_map_ to clean
 * up plugins and libraries.
 */
void plugin_manager::unload_plugins()
{
    for(map<string, cc_plugin*>::iterator it = plugin_map_.begin();
	it != plugin_map_.end(); ++it)
	it->second->destroy_plugin();
    
    for(map<string, void*>::iterator it = libraries_map_.begin();
	it != libraries_map_.end(); ++it)
	RTIOsapiLibrary_close(it->second);
}

/**
 * @brief Loads a plugin.
 * 
 * This method loads a plugin given its plugin name and the directory were 
 * its XML configuration file is stored. To achieve this goal it parses the
 * XML file using the <code>parse_plugin_configuration_file()</code> method of the XML_parser 
 * class and the <code>get_plugin_properties()</code> of the same class to get the properties.
 * @param plugin_name Name of the plugin.
 * @param dir Directory were the XML configuration file of the plugin is stored.
 */
bool plugin_manager::load_plugin(string plugin_name, string plugin_library)
{

    //TODO: if we want to put both dynamic libraries and configuration files
    //within the same directory we would have to change this line.
    // string library_path(LIBDIR);
	string cavecanem_dir(CAVECANEM_DIR);
    if(!XML_parser::get_singleton()->
       parse_plugin_configuration_file(string(cavecanem_dir + "/" +
					      plugin_library +"/" +
					      plugin_name + "/" +
					      plugin_name+".xml"))) {
	return false;
    }
           
    plugin_properties_map_[plugin_name] = 
        XML_parser::get_singleton()->get_plugin_properties(plugin_name);

    libraries_map_[plugin_name] = RTIOsapiLibrary_open((cavecanem_dir + "/" +
							plugin_library + "/" +
							plugin_name + "/" +
							plugin_properties_map_[plugin_name].dll).c_str(),
						       RTI_OSAPI_LIBRARY_RTLD_NOW);

    if(libraries_map_[plugin_name] == NULL) {
        return false;
    }

    cc_create_plugin_t * create_fnc = (cc_create_plugin_t *)
	RTIOsapiLibrary_getSymbolAddress(libraries_map_[plugin_name], 
					 plugin_properties_map_[plugin_name].create_function.c_str());

    try {
	plugin_map_[plugin_name] = create_fnc(plugin_name, 
					      plugin_properties_map_[plugin_name].plugin_config);
        if(plugin_map_[plugin_name] == NULL) {
	        return false;
	    }
    } catch (exception& e) {
      cerr << e.what() << endl;
	  return false;
    }
    //If everything was correct we set the period counter for the plugin
    // period_counter_map_[plugin_name] = plugin_properties_map_[plugin_name].publishing_period;
    period_counter_map_[plugin_name] = 0;

    return true;
    
}


/** 
 * @brief Creates all the DDS entities that plugins need.
 * 
 * It creates the DDS Domain Participant and DDS Publisher--shared by all the plugins--
 * using the method create_dds_participant_and_publisher() and creates the DDS Topic
 * and DDS DataWriter for each plugin calling create_dds_topic_and_datawriter().
 * @param domain_id DDS Domain ID
 * @param qos_configuration_file XML configuration file for the QoS.
 * @param qos_library Name of the QoS library.
 * @param qos_profile Name of the QoS profile (if "default" it loads the default RTI DDS QoS settings).
 * 
 * @return Returns true if everything was initialized correctly and false if it was not.
 */
bool plugin_manager::initialize_dds(int domain_id, 
				    string qos_configuration_file,
				    string qos_library,
				    string qos_profile)
{
    //Create DomainParticipant and the Publisher
    if(!create_dds_participant_and_publisher(domain_id, qos_configuration_file, qos_library, qos_profile)) {
	    return  false;
    }

    //..then we create a DataWriter for each plugin
    for(map<string, cc_plugin*>::iterator it = plugin_map_.begin();
    	it != plugin_map_.end(); ++it) {
    	if(!create_dds_topic_and_datawriter(it->first,
					    plugin_properties_map_[it->first].qos_library,
					    plugin_properties_map_[it->first].qos_profile,
					    plugin_properties_map_[it->first].topic_name,
					    (DDS_TypeCode *)plugin_properties_map_[it->first].type_code,
					    (DDS_DataWriterQos *)plugin_properties_map_[it->first].datawriter_qos)) {
	        shutdown_dds();
	        return false;
	    }
    }

    return true;
}


/** 
 * @brief Creates a DDS Domain Participant and DDS Publisher.
 * 
 * It creates a DDS Domain Participant and a DDS Publisher from which we will create
 * the topics and DataWriters for each plugin.
 *
 * @param domain_id  DDS Domain ID
 * @param qos_configuration_file XML configuration file.
 * @param qos_library Name of the QoS library.
 * @param qos_profile Name of the QoS profile (if "default" it loads default RTI DDS QoS settings).
 * 
 * @return Returns true if everything went good and false if it was not.
 */
bool plugin_manager::create_dds_participant_and_publisher(int domain_id,
							  string qos_configuration_file,
							  string qos_library,
							  string qos_profile)
{

    DDS_DomainParticipantFactoryQos factory_qos;
    DDSTheParticipantFactory->get_qos(factory_qos);
    factory_qos.profile.url_profile.ensure_length(1,1);
    factory_qos.profile.url_profile[0] = DDS_String_dup(qos_configuration_file.c_str());
    
    DDSTheParticipantFactory->set_qos(factory_qos);


    if (qos_profile == "default") { //We use the default QoS profile

	//Created DDS Domain Participant
	participant_ = DDSTheParticipantFactory->
	    create_participant(domain_id, //Domain ID
			       DDS_PARTICIPANT_QOS_DEFAULT, //QoS
			       NULL, //Listener
			       DDS_STATUS_MASK_NONE);
	if (participant_ == NULL) {
	    cerr << "create_participant error" << endl;
	    return false;
	}

	//Created DDS Publisher
	publisher_ = participant_->create_publisher(DDS_PUBLISHER_QOS_DEFAULT,
						    NULL,
						    DDS_STATUS_MASK_NONE);
	if (publisher_ == NULL) {
	    cerr << "create_publisher error" << endl;
	    return false;
	}
    }
  
    else { //We have defined a QoS profile within a QoS library
	participant_ = DDSTheParticipantFactory->
	    create_participant_with_profile(domain_id,
					    qos_library.c_str(),
					    qos_profile.c_str(),
					    NULL,
					    DDS_STATUS_MASK_NONE);
	if (participant_ == NULL) {
	    cerr << "create_participant_with_profile error" << endl;
	    return false;
	}
    
	publisher_ = participant_->
	    create_publisher_with_profile(qos_library.c_str(), //library
					  qos_profile.c_str(), //profile
					  NULL, // listener
					  DDS_STATUS_MASK_NONE);
	if (publisher_ == NULL) {
	    cerr << "create_publisher_with_profile error" << endl;
	    return false;    
	}
    }


    return true;
}


/** 
 * @brief Creates a DDS Topic and a DDS DataWriter a plugin.
 * 
 * Creates a DDS Topic and a DDS DataWriter for a plugin according to a set of
 * parameters.
 * @param plugin_name Name of the plugin.
 * @param qos_library Name of the QoS library. It will not be used if the datawriter_qos is not NULL.
 * @param qos_profile Name of the QoS profile (if "default" the default RTI DDS QoS settings will be loaded). It will not be used if the datawriter_qos is not NULL.
 * @param topic_name Name of the topic (if it is not indicated it will be named after the plugin's name.
 * @param type_code DDS Type Code.
 * @param datawriter_qos QoS for the DDS DataWriter (if it is not set, the DataWriter's QoS will be set according to the qos_library and qos_profile parameters).
 * 
 * @return Returns true if the entities were created correctly and false if they were not.
 */
bool plugin_manager::create_dds_topic_and_datawriter(std::string plugin_name,
						     std::string qos_library,
						     std::string qos_profile,
						     std::string topic_name,
						     DDS_TypeCode *type_code,
						     DDS_DataWriterQos *datawriter_qos)
{
    
    DDS_TypeCodeFactory *typecode_factory = NULL;
    DDSTopic *topic = NULL;
    DDSDataWriter *writer = NULL;
    DDSDynamicDataTypeSupport *type_support = NULL;
    const char *type_name = NULL;

    DDS_ReturnCode_t retcode;

    typecode_factory = DDS_TypeCodeFactory::get_instance();

    
    //Create type code for disk type    
    if(type_code == NULL) {
	cerr << "error creating " << plugin_name << " typecode" << endl;
	return false;
    }
    
    //create dynamic type support for type code
    type_support = new DDSDynamicDataTypeSupport(type_code,
						 DDS_DYNAMIC_DATA_TYPE_PROPERTY_DEFAULT);
    if(type_support == NULL) {
	cerr << plugin_name << "Error in creating type support" << endl;
	return false;
    }
    type_name = type_support->get_type_name();

    //Register type before creating topic
    retcode = type_support->register_type(participant_, type_name);
    if (retcode != DDS_RETCODE_OK) {
        cerr << plugin_name << "register_type error " << endl;
	return false;
    }

    //Create topic
    topic = participant_->create_topic(topic_name.c_str(),
				       type_name, 
				       DDS_TOPIC_QOS_DEFAULT, 
				       NULL /* listener */,
				       DDS_STATUS_MASK_NONE);
    if (topic == NULL) {
        cerr << topic_name << "create_topic error" << endl;
        return false;
    }
    
    if(datawriter_qos == NULL) {
	//Create DataWriter
	if(qos_profile == "default") { //We use the default QoS profile
	    writer = publisher_->create_datawriter(topic, 
						   DDS_DATAWRITER_QOS_DEFAULT, 
						   NULL /* listener */,
						   DDS_STATUS_MASK_NONE);
	}
	
		else { //We use a Qos profile defined within a QoS library
			writer = publisher_->
			create_datawriter_with_profile(topic, 
							   qos_library.c_str() /*library*/, 
							   qos_profile.c_str() /*profile*/,
							   NULL /* listener */,
							   DDS_STATUS_MASK_NONE);
		}
    }

    else { //If specified DataWriter QoS
	datawriter_qos = ( DDS_DataWriterQos*) &DDS_DATAWRITER_QOS_DEFAULT;
	writer = publisher_->create_datawriter(topic,
		                   //DDS_DATAWRITER_QOS_DEFAULT,
					       *datawriter_qos,
					       NULL,
					       DDS_STATUS_MASK_NONE);
    }
    
    if (writer == NULL) {
	cerr << plugin_name << "Create_datawriter error" << endl;
	return false;
    }
    
    dynamicdata_info_map_[plugin_name].writer = NULL;
    dynamicdata_info_map_[plugin_name].writer = DDSDynamicDataWriter::narrow(writer);
    if (dynamicdata_info_map_[plugin_name].writer == NULL) {
	cerr << plugin_name << "DataWriter narrow error" << endl;
	return false;
    }
    
    /* Create data sample for writing */
    dynamicdata_info_map_[plugin_name].data = type_support->create_data();
    if (dynamicdata_info_map_[plugin_name].data == NULL) {
        cerr << "create_data error" << endl;
	return false;
    }
    
    return true;
}


/** 
 * @brief Deletes all the DDS Entities initialized in initialize_dds()
 * 
 * Deletes all the DDS entities initialized by <code>initialize_dds()</code>, 
 * including the DDS Domain Participant.
 *
 * @return It indicates wether the plugins were shutdowned correctly or not.
 */
bool plugin_manager::shutdown_dds()
{
    DDS_ReturnCode_t retcode;
    if (participant_ != NULL) {
        retcode = participant_->delete_contained_entities();
        if (retcode != DDS_RETCODE_OK) {
            cerr << "delete_contained_entities error" << endl;
            return false;
        }
	
        retcode = DDSTheParticipantFactory->delete_participant(participant_);
        if (retcode != DDS_RETCODE_OK) {
            cerr << "Delete_participant error" << endl;
            return false;
        }
    }

    return true;
}


/** 
 * @brief Calls all the loaded plugins to publish.
 * 
 * Calls the publishing method of all the plugins loaded. It also controls the publishing rate
 * of each function.
 *
 */
void plugin_manager::publish_plugins_information()
{

    for(map<string, cc_plugin*>::iterator it = plugin_map_.begin();
	it != plugin_map_.end(); ++it) {
	//Checks if it is its turn to publish
	if(period_counter_map_[it->first] <= 0) {
	    it->second->
		generate_and_publish_information(dynamicdata_info_map_[it->first].writer,
						 dynamicdata_info_map_[it->first].data);
	    period_counter_map_[it->first] =  plugin_properties_map_[it->first].publishing_period - general_properties_.publishing_period;

	}

	else {
	    period_counter_map_[it->first] -= general_properties_.publishing_period;

	}
    }
    DDS_Duration_t publishing_period;
    publishing_period.sec = general_properties_.publishing_period;
    publishing_period.nanosec = 0;
    NDDSUtility::sleep(publishing_period);

}

