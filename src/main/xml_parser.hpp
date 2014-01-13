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


#ifndef XML_PARSER_HPP
#define XML_PARSER_HPP

#include <iostream>
#include <string>
#include <list>
#include <cstdlib>
#include <map>
#include <string.h>

#include <ndds/ndds_cpp.h>
#include <osapi/osapi_heap.h>
#include <osapi/osapi_bufferUtils.h>
#include <dds_c/dds_c_xml.h>
#include <osapi/osapi_log.h>
#include <log/log_makeheader.h>
#include <log/log_common.h>

#define XML_CAVECANEM_MAX_NUMBER_OF_NON_EXTENSION_TAGS 1000
#define DTD_CAVECANEM_LINE_NUMBER 13
#define DTD_CAVECANEM_EXTENSION_NUMBER 12
#define DTD_CAVECANEM_PLUGIN_LINE_NUMBER 354
#define DTD_CAVECANEM_PLUGIN_EXTENSION_NUMBER 11

#ifndef CAVECANEM_DIR
#define CAVECANEM_DIR ""
#endif


/** 
 * @class RTIXMLCaveCanemExtensionObjectElement
 * Elements (object attribute tags) of the extension class object.
 */

struct RTIXMLCaveCanemExtensionObjectElement {
    /* Attributes of the element (object attribute tag) */
    char **attr;
    /* Number of attributes of the element */
    int attr_length;
    /* Text within the 'start tag' and the 'end tag' of the element */
    char *element_text;    
    /* Tag name of the element */
    char *tag_name;
};


/** 
 * @class RTIXMLCaveCanemExtensionObject 
 * The extension classes are used to create XML objects. 
 * Each extension class is associated to a XML tag and they must be registered with the parser
 */
struct RTIXMLCaveCanemExtensionObject{
    /* Base class. */
    struct DDS_XMLObject base; /* Should be the first */
    /* Attributes of the object tag */
    char **attr;
    /* Number of attributes of the element */
    int attr_length;
    /* Index for next available place in the tagElements array */
    int current_element_index;
    /* Array for the elements (object attribute tags) of the object tag */
    struct RTIXMLCaveCanemExtensionObjectElement * tag_elements[XML_CAVECANEM_MAX_NUMBER_OF_NON_EXTENSION_TAGS];
};

/** 
 * @class cc_general_properties 
 * This structure stores the general properties of Cave Canem
 * got from a XML configuration file.
 */
struct cc_general_properties {
    int publishing_period;
    int domain_id;
    std::string qos_file;
    std::string qos_library;
    std::string qos_profile;
    std::map<std::string, std::list<std::string> > plugin_list_map;
};


/** 
 * @class cc_plugin_properties
 * This structure stores the properties of a plugin got from a 
 * XML configuration file.
 */
struct cc_plugin_properties {
    //   std::string name;
    std::string dll;
    std::string create_function;
    int publishing_period;
    std::string qos_profile;
    std::string qos_library;
    std::string topic_name;
    std::map<std::string, std::string> plugin_config;
    const struct DDS_DataWriterQos *datawriter_qos;
    struct DDS_TypeCode *type_code;
};



struct DDS_XMLObject *XML_parser_new(const struct DDS_XMLExtensionClass * extension_class,
				    const struct DDS_XMLObject * parent_object,
				    const char **attr,
				    struct DDS_XMLContext * context);

void XML_parser_delete(struct DDS_XMLObject * self);

void XML_parser_start(struct DDS_XMLObject *self,
		      const char *tag_name,
		      const char **attr,
		      struct DDS_XMLContext *context);


void XML_parser_general_end(struct DDS_XMLObject *self,
			    const char *tag_name,
			    const char *element_text,
			    struct DDS_XMLContext *context);

void XML_parser_plugin_end(struct DDS_XMLObject *self,
			   const char *tag_name,
			   const char *element_text,
			   struct DDS_XMLContext *context);



RTIBool RTIXMLCaveCanemExtensionObject_initialize(RTIXMLCaveCanemExtensionObject * self,
						  const struct DDS_XMLExtensionClass * extension_class,
						  const struct DDS_XMLObject * parent_object,
						  const char ** attr,
						  struct DDS_XMLContext * context);

void RTIXMLCaveCanemExtensionObject_finalize(struct RTIXMLCaveCanemExtensionObject * self);



/** 
 * @class XML_parser
 * 
 * @brief This class parses all XML configurations files needed in Cave Canem.
 */
class XML_parser {
private:
    static XML_parser *the_singleton_;
    XML_parser();

    bool register_general_extensions(struct DDS_XMLParser *self,
    				     struct DDS_XMLExtensionClass **user_extensions);
    bool register_plugin_extensions(struct DDS_XMLParser *self,
    				    struct DDS_XMLExtensionClass **user_extensions);
    
    cc_general_properties general_properties_;
    std::map<std::string,cc_plugin_properties> plugin_properties_map_;

    //Temporal library plugin list
    std::list<std::string> tmp_plugin_list_;
    cc_plugin_properties tmp_plugin_properties_;

public:
    /** 
     * @brief Provides access to the XML_parser singleton class.
     * 
     * Provides access to the XML_parser singleton class.
     * @return Returns a reference to the object.
     */
    static XML_parser *get_singleton()
    {
	if(!the_singleton_)
	    the_singleton_ = new XML_parser;
	return the_singleton_;
    }
    
    /** 
     * @brief Destructor of the class XML_parser.
     *  Destructor of the class XML_parser.
     */
    ~XML_parser() {}

    bool parse_general_configuration_file(std::string cfg_file);
    bool parse_plugin_configuration_file(std::string cfg_file);
        
    void set_publishing_period(int publishing_period);
    void set_domain_id(int domain_id);
    void set_qos_file(std::string qos_file);
    void set_qos_default_library(std::string qos_library);
    void set_qos_default_profile(std::string qos_profile);
    void set_plugin_library(std::string dir, std::list<std::string> plugin_list);
    
    //Temporal setting methods for general properties
    void add_tmp_plugin(std::string tmp_plugin);
    std::list<std::string> get_tmp_plugin_list();
    void clear_tmp_plugin_list();

    void set_plugin_properties(std::string plugin_name);

    //Temporal setting methods for a given plugin properties
    void set_tmp_plugin_properties_dll(std::string dll);
    void set_tmp_plugin_properties_create_function(std::string create_function);
    void set_tmp_plugin_properties_qos_library(std::string qos_library);
    void set_tmp_plugin_properties_qos_profile(std::string qos_profile);
    void set_tmp_plugin_properties_topic_name(std::string topic_name);
    void set_tmp_plugin_properties_add_element(std::string name,std::string value);
    void set_tmp_plugin_properties_type_code(struct DDS_TypeCode *type_code);
    void set_tmp_plugin_properties_datawriter_qos(const struct DDS_DataWriterQos *datawriter_qos);
    void set_tmp_plugin_properties_publishing_period(int publishing_period);
    // void set_tmp_plugin_properties_datawriter_qos(struct DataWriterQos *datawriter_qos);
    const struct DDS_TypeCode* get_type_code_from_XML(struct DDS_XMLObject *xml,
						     const char *type_name,
						     struct DDS_XMLContext *context1);
	
	
    cc_general_properties get_general_properties();
    cc_plugin_properties get_plugin_properties(std::string plugin_name);

    


};

#endif //XML_PARSER_HPP
