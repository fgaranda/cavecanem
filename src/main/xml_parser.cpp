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


#include "xml_parser.hpp"

using namespace std;


XML_parser *XML_parser::the_singleton_ = 0;


/** 
 * @brief Constructor of the XML_parser class.
 * 
 * The constructor of the XML_parser class is empty.
 */
XML_parser::XML_parser()
{
    

}

/** 
 * @brief Parses a general configuration file.
 * 
 * Defines the DTD of the general configuration file. Registers our custom extensions 
 * by using the register_general_extensions() method and finally it parses the file.
 * @param cfg_file General configuration file to be parsed.
 * 
 * @return  Returns true if the configuration file was parsed correctly and false if
 it was not.
 */
bool XML_parser::parse_general_configuration_file(string cfg_file)
{
    struct DDS_XMLParser *parser     = NULL;
    struct DDS_XMLObject *root       = NULL;
    cc_general_properties general_properties;
    
    struct DDS_XMLExtensionClass *user_extensions[DTD_CAVECANEM_EXTENSION_NUMBER] = 
	{NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    
    const char * CAVECANEM_DTD[DTD_CAVECANEM_LINE_NUMBER] = {
	"<!ELEMENT cavecanem (general,dds_properties,plugins)>\n",
	"<!ELEMENT general (publishing_period_sec)>\n",
	"<!ELEMENT publishing_period_sec (#PCDATA)>\n",
	"<!ELEMENT dds_properties (dds_domain_id,dds_qos_file,dds_qos_default_library,dds_qos_default_profile)>\n",
	"<!ELEMENT dds_domain_id (#PCDATA)>\n",
	"<!ELEMENT dds_qos_file (#PCDATA)>\n",
	"<!ELEMENT dds_qos_default_library (#PCDATA)>\n",
	"<!ELEMENT dds_qos_default_profile (#PCDATA)>\n",
	"<!ELEMENT plugins (plugin_library*)>\n",
	"<!ELEMENT plugin_library (plugin+|plugin_regex)>\n",
	"<!ATTLIST plugin_library dir CDATA #REQUIRED>",
	"<!ELEMENT plugin_regex (#PCDATA)>\n",
	"<!ELEMENT plugin (#PCDATA)>\n"
    };
    
    parser = DDS_XMLParser_new();
    if(parser == NULL) {
	cerr << "Error creating XML parser" << endl;
	return false;
    }

    if(!register_general_extensions(parser,user_extensions)) {
    	DDS_XMLParser_delete(parser);
    	return false;
    }
    
    root =  DDS_XMLParser_parse_from_file(parser, 
					  CAVECANEM_DTD,
					  DTD_CAVECANEM_LINE_NUMBER,
					  cfg_file.c_str(),
					  NULL);
    
    if(root == NULL) {
	cerr << cfg_file << " is not a valid configuration file" << endl;
	DDS_XMLParser_delete(parser);
	return false;
    }

    DDS_XMLParser_delete(parser);
    return true;

    
}


/** 
 * @brief Parses a plugin configuration file.
 * 
 * Defines the DTD for the XML configuration file of a plugin. Registers our custom extensions 
 * by using the register_plugin_extensions() method and finally parses the file.
 * @param cfg_file The plugin configuration file--including its route--that we want to parse.
 * 
 * @return Returns true if the parsing was right and false if it was not.
 */
bool XML_parser::parse_plugin_configuration_file(string cfg_file)
{
 
    cc_plugin_properties plugin_properties;
    struct DDS_XMLParser *parser     = NULL;
    struct DDS_XMLObject *root       = NULL;
    
    struct DDS_XMLExtensionClass *user_extensions[DTD_CAVECANEM_PLUGIN_EXTENSION_NUMBER] = 
	{NULL, NULL, NULL, NULL,NULL, NULL, NULL, NULL, NULL, NULL};
    
    const char * CAVECANEM_PLUGIN_DTD[DTD_CAVECANEM_PLUGIN_LINE_NUMBER] = {
	"<!ELEMENT plugin (dll,create_function,publishing_period_sec,dds_properties,plugin_config,type_definition)>\n",
	"<!ATTLIST plugin name CDATA #REQUIRED>\n",
	"<!ELEMENT dll (#PCDATA)>\n",
	"<!ELEMENT create_function (#PCDATA)>\n",
	"<!ELEMENT publishing_period_sec (#PCDATA)>\n",
	"<!ELEMENT dds_properties (dds_qos_library|dds_qos_profile|dds_topic_name|datawriter_qos)>\n",
	"<!ELEMENT dds_qos_library (#PCDATA)>\n",
	"<!ELEMENT dds_qos_profile (#PCDATA)>\n",
	"<!ELEMENT dds_topic_name (#PCDATA)>\n",
	"<!ELEMENT datawriter_qos (durability|durability_service|deadline|latency_budget|liveliness|reliability|destination_order|history|resource_limits|transport_priority|lifespan|user_data|ownership|ownership_strength|writer_data_lifecycle|writer_resource_limits|protocol|transport_selection|unicast|type_support|publish_mode|property|batch|multi_channel|encapsulation)*>\n",
	"<!ATTLIST datawriter_qos name CDATA #IMPLIED>\n",
	"<!ATTLIST datawriter_qos base_name CDATA #IMPLIED>\n",
	"<!ATTLIST datawriter_qos base_qos_name CDATA #IMPLIED>\n",
	"<!ATTLIST datawriter_qos topic_filter CDATA #IMPLIED>\n",
	"<!ELEMENT user_data (value)>\n",
	"<!ELEMENT entity_factory (autoenable_created_entities)>\n",
	"<!ELEMENT wire_protocol (participant_id|rtps_auto_id_kind|rtps_host_id|rtps_app_id|rtps_instance_id|rtps_well_known_ports|rtps_reserved_port_mask)*>\n",
	"<!ELEMENT transport_builtin (mask)>\n",
	"<!ELEMENT default_unicast (value)>\n",
	"<!ELEMENT discovery (enabled_transports|initial_peers|multicast_receive_addresses|metatraffic_transport_priority|accept_unknown_peers)*>\n",
	"<!ELEMENT resource_limits (local_writer_allocation|local_reader_allocation|local_publisher_allocation|local_subscriber_allocation|local_topic_allocation|remote_writer_allocation|remote_reader_allocation|remote_participant_allocation|matching_writer_reader_pair_allocation|matching_reader_writer_pair_allocation|ignored_entity_allocation|content_filtered_topic_allocation|content_filter_allocation|read_condition_allocation|query_condition_allocation|outstanding_asynchronous_sample_allocation|flow_controller_allocation|local_writer_hash_buckets|local_reader_hash_buckets|local_publisher_hash_buckets|local_subscriber_hash_buckets|instance_hash_buckets|local_topic_hash_buckets|remote_writer_hash_buckets|remote_reader_hash_buckets|remote_participant_hash_buckets|matching_writer_reader_pair_hash_buckets|matching_reader_writer_pair_hash_buckets|ignored_entity_hash_buckets|content_filtered_topic_hash_buckets|content_filter_hash_buckets|flow_controller_hash_buckets|max_gather_destinations|participant_user_data_max_length|topic_data_max_length|publisher_group_data_max_length|subscriber_group_data_max_length|writer_user_data_max_length|reader_user_data_max_length|max_partitions|max_partition_cumulative_characters|type_code_max_serialized_length|contentfilter_property_max_length|participant_property_list_max_length|participant_property_string_max_length|writer_property_list_max_length|writer_property_string_max_length|reader_property_list_max_length|reader_property_string_max_length|max_samples|max_instances|max_samples_per_instance|initial_samples|initial_instances|channel_seq_max_length|channel_filter_expression_max_length)*>\n",
	"<!ELEMENT event (thread|initial_count|max_count)*> \n",
	"<!ELEMENT receiver_pool (thread|buffer_size|buffer_alignment)*> \n",
	"<!ELEMENT database (thread|shutdown_timeout|cleanup_period|shutdown_cleanup_period|initial_records|max_skiplist_level|max_weak_references|initial_weak_references)*> \n",
	"<!ELEMENT discovery_config (participant_liveliness_lease_duration|participant_liveliness_assert_period|remote_participant_purge_kind|max_liveliness_loss_detection_period|initial_participant_announcements|min_initial_participant_announcement_period|max_initial_participant_announcement_period|participant_reader_resource_limits|publication_reader|publication_reader_resource_limits|subscription_reader|subscription_reader_resource_limits|publication_writer|subscription_writer|builtin_discovery_plugins|participant_message_reader|participant_message_writer|participant_proxy_reader|participant_state_writer)*>\n",
	"<!ELEMENT property (value)> \n",
	"<!ELEMENT participant_name (name)> \n",
	"<!ELEMENT topic_data (value)> \n",
	"<!ELEMENT durability (kind|direct_communication)*> \n",
	"<!ELEMENT durability_service (service_cleanup_delay|history_kind|history_depth|max_samples|max_instances|max_samples_per_instance)*> \n",
	"<!ELEMENT deadline (period)> \n",
	"<!ELEMENT latency_budget (duration)> \n",
	"<!ELEMENT liveliness (kind|lease_duration)*> \n",
	"<!ELEMENT reliability (kind|max_blocking_time)*> \n",
	"<!ELEMENT destination_order (kind|source_timestamp_tolerance)*> \n",
	"<!ELEMENT history (kind|depth|refilter)*> \n",
	"<!ELEMENT transport_priority (value)> \n",
	"<!ELEMENT lifespan (duration)> \n",
	"<!ELEMENT ownership (kind)>\n",
	"<!ELEMENT presentation (access_scope|coherent_access|ordered_access)*> \n",
	"<!ELEMENT partition (name)> \n",
	"<!ELEMENT group_data (value)> \n",
	"<!ELEMENT asynchronous_publisher (disable_asynchronous_write|disable_asynchronous_batch|thread|asynchronous_batch_thread|asynchronous_batch_blocking_kind)*>\n",
	"<!ELEMENT exclusive_area (use_shared_exclusive_area|level)> \n",
	"<!ELEMENT ownership_strength (value)> \n",
	"<!ELEMENT writer_data_lifecycle (autodispose_unregistered_instances)> \n",
	"<!ELEMENT writer_resource_limits (initial_concurrent_blocking_threads|max_concurrent_blocking_threads|max_remote_reader_filters|initial_batches|max_batches|instance_replacement|replace_empty_instances|autoregister_instances)*>\n",
	"<!ELEMENT protocol (virtual_guid|rtps_object_id|push_on_write|disable_positive_acks|disable_inline_keyhash|serialize_key_with_dispose|rtps_reliable_writer|rtps_reliable_reader|expects_inline_qos|propagate_dispose_of_unregistered_instances|vendor_specific_entity)*> \n",
	"<!ELEMENT transport_selection (enabled_transports)> \n",
	"<!ELEMENT unicast (value)> \n",
	"<!ELEMENT type_support (plugin_data)> \n",
	"<!ELEMENT publish_mode (kind|flow_controller_name)*> \n",
	"<!ELEMENT time_based_filter (minimum_separation)> \n",
	"<!ELEMENT reader_data_lifecycle (autopurge_nowriter_samples_delay|autopurge_disposed_samples_delay)*> \n",
	"<!ELEMENT reader_resource_limits (max_remote_writers|max_remote_writers_per_instance|max_samples_per_remote_writer|max_infos|initial_remote_writers|initial_remote_writers_per_instance|initial_infos|initial_outstanding_reads|max_outstanding_reads|max_samples_per_read|disable_fragmentation_support|max_fragmented_samples|initial_fragmented_samples|max_fragmented_samples_per_remote_writer|max_fragments_per_sample|dynamically_allocate_fragmented_samples|max_total_instances|max_remote_virtual_writers_per_instance|initial_remote_virtual_writers_per_instance|max_query_condition_filters)*> \n",
	"<!ELEMENT multicast (value)> \n",
	"<!ELEMENT batch (enable|max_data_bytes|max_meta_data_bytes|max_samples|max_flush_delay|source_timestamp_resolution|thread_safe_write)*>\n",
	"<!ELEMENT multi_channel (channels|filter_name)*> \n",
	"<!ELEMENT encapsulation (value)> \n",
	"<!ELEMENT value (#PCDATA|element)*> \n",
	"<!ELEMENT autoenable_created_entities (#PCDATA)> \n",
	"<!ELEMENT participant_id (#PCDATA)> \n",
	"<!ELEMENT rtps_auto_id_kind (#PCDATA)> \n",
	"<!ELEMENT rtps_host_id (#PCDATA)> \n",
	"<!ELEMENT rtps_app_id (#PCDATA)> \n",
	"<!ELEMENT rtps_instance_id (#PCDATA)> \n",
	"<!ELEMENT rtps_well_known_ports (port_base|domain_id_gain|participant_id_gain|builtin_multicast_port_offset|builtin_unicast_port_offset|user_multicast_port_offset|user_unicast_port_offset)*>\n",
	"<!ELEMENT port_base (#PCDATA)>\n",
	"<!ELEMENT domain_id_gain (#PCDATA)> \n",
	"<!ELEMENT participant_id_gain (#PCDATA)> \n",
	"<!ELEMENT builtin_multicast_port_offset (#PCDATA)> \n",
	"<!ELEMENT builtin_unicast_port_offset (#PCDATA)> \n",
	"<!ELEMENT user_multicast_port_offset (#PCDATA)> \n",
	"<!ELEMENT user_unicast_port_offset (#PCDATA)> \n",
	"<!ELEMENT rtps_reserved_port_mask (#PCDATA)> \n",
	"<!ELEMENT mask (#PCDATA)> \n",
	"<!ELEMENT element (#PCDATA|receive_port|transports|name|value|propagate|receive_address|domain_filter|type_config|path|file_name|type|register_top_level|max_string|max_sequence|type_name|registered_type_name|filter_expression|kind|port|address|multicast_settings|encapsulations)*> \n",
	"<!ELEMENT encapsulations (element)*> \n",
	"<!ELEMENT receive_port (#PCDATA)> \n",
	"<!ELEMENT transports (element)*> \n",
	"<!ELEMENT enabled_transports (element)*> \n",
	"<!ELEMENT initial_peers (element)*> \n",
	"<!ELEMENT multicast_receive_addresses (element)*> \n",
	"<!ELEMENT metatraffic_transport_priority (#PCDATA)> \n",
	"<!ELEMENT accept_unknown_peers (#PCDATA)> \n",
	"<!ELEMENT local_writer_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT initial_count (#PCDATA)> \n",
	"<!ELEMENT max_count (#PCDATA)> \n",
	"<!ELEMENT incremental_count (#PCDATA)> \n",
	"<!ELEMENT local_reader_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT local_publisher_allocation (initial_count|max_count|incremental_count)*>\n",
	"<!ELEMENT local_subscriber_allocation (initial_count|max_count|incremental_count)*>\n",
	"<!ELEMENT local_topic_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT remote_writer_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT remote_reader_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT remote_participant_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT matching_writer_reader_pair_allocation (initial_count|max_count|incremental_count)*>\n",
	"<!ELEMENT matching_reader_writer_pair_allocation (initial_count|max_count|incremental_count)*>\n",
	"<!ELEMENT ignored_entity_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT content_filtered_topic_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT content_filter_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT read_condition_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT query_condition_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT outstanding_asynchronous_sample_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT flow_controller_allocation (initial_count|max_count|incremental_count)*> \n",
	"<!ELEMENT local_writer_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT local_reader_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT local_publisher_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT local_subscriber_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT local_topic_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT remote_writer_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT remote_reader_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT remote_participant_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT matching_writer_reader_pair_hash_buckets (#PCDATA)>\n",
	"<!ELEMENT matching_reader_writer_pair_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT ignored_entity_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT content_filtered_topic_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT content_filter_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT flow_controller_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT max_gather_destinations (#PCDATA)> \n",
	"<!ELEMENT participant_user_data_max_length (#PCDATA)> \n",
	"<!ELEMENT topic_data_max_length (#PCDATA)> \n",
	"<!ELEMENT publisher_group_data_max_length (#PCDATA)> \n",
	"<!ELEMENT subscriber_group_data_max_length (#PCDATA)> \n",
	"<!ELEMENT writer_user_data_max_length (#PCDATA)> \n",
	"<!ELEMENT reader_user_data_max_length (#PCDATA)> \n",
	"<!ELEMENT max_partitions (#PCDATA)> \n",
	"<!ELEMENT max_partition_cumulative_characters (#PCDATA)> \n",
	"<!ELEMENT type_code_max_serialized_length (#PCDATA)> \n",
	"<!ELEMENT contentfilter_property_max_length (#PCDATA)> \n",
	"<!ELEMENT participant_property_list_max_length (#PCDATA)> \n",
	"<!ELEMENT participant_property_string_max_length (#PCDATA)> \n",
	"<!ELEMENT writer_property_list_max_length (#PCDATA)> \n",
	"<!ELEMENT writer_property_string_max_length (#PCDATA)> \n",
	"<!ELEMENT reader_property_list_max_length (#PCDATA)> \n",
	"<!ELEMENT reader_property_string_max_length (#PCDATA)> \n",
	"<!ELEMENT thread (mask|priority|stack_size|cpu_list|cpu_rotation)*> \n",
	"<!ELEMENT asynchronous_batch_thread (mask|priority|stack_size|cpu_list|cpu_rotation)*> \n",
	"<!ELEMENT priority (#PCDATA)> \n",
	"<!ELEMENT stack_size (#PCDATA)> \n",
	"<!ELEMENT cpu_list (element)*> \n",
	"<!ELEMENT cpu_rotation (#PCDATA)> \n",
	"<!ELEMENT buffer_size (#PCDATA)> \n",
	"<!ELEMENT buffer_alignment (#PCDATA)> \n",
	"<!ELEMENT shutdown_timeout (sec|nanosec)*> \n",
	"<!ELEMENT sec (#PCDATA)> \n",
	"<!ELEMENT nanosec (#PCDATA)> \n",
	"<!ELEMENT cleanup_period (sec|nanosec)*> \n",
	"<!ELEMENT shutdown_cleanup_period (sec|nanosec)*> \n",
	"<!ELEMENT initial_records (#PCDATA)> \n",
	"<!ELEMENT max_skiplist_level (#PCDATA)> \n",
	"<!ELEMENT max_weak_references (#PCDATA)> \n",
	"<!ELEMENT initial_weak_references (#PCDATA)> \n",
	"<!ELEMENT participant_liveliness_lease_duration (sec|nanosec)*> \n",
	"<!ELEMENT participant_liveliness_assert_period (sec|nanosec)*> \n",
	"<!ELEMENT remote_participant_purge_kind (#PCDATA)> \n",
	"<!ELEMENT max_liveliness_loss_detection_period (sec|nanosec)*> \n",
	"<!ELEMENT initial_participant_announcements (#PCDATA)> \n",
	"<!ELEMENT min_initial_participant_announcement_period (sec|nanosec)*> \n",
	"<!ELEMENT max_initial_participant_announcement_period (sec|nanosec)*> \n",
	"<!ELEMENT participant_reader_resource_limits (initial_samples|max_samples|initial_infos|max_infos|initial_outstanding_reads|max_outstanding_reads|max_samples_per_read)*>\n",
	"<!ELEMENT initial_samples (#PCDATA)> \n",
	"<!ELEMENT max_samples (#PCDATA)> \n",
	"<!ELEMENT initial_infos (#PCDATA)> \n",
	"<!ELEMENT max_infos (#PCDATA)> \n",
	"<!ELEMENT initial_outstanding_reads (#PCDATA)\n>",
	"<!ELEMENT max_outstanding_reads (#PCDATA)> \n",
	"<!ELEMENT max_samples_per_read (#PCDATA)> \n",
	"<!ELEMENT publication_reader (min_heartbeat_response_delay|max_heartbeat_response_delay|heartbeat_suppression_duration|nack_period)*> \n",
	"<!ELEMENT min_heartbeat_response_delay (sec|nanosec)*>\n",
	"<!ELEMENT max_heartbeat_response_delay (sec|nanosec)*> \n",
	"<!ELEMENT heartbeat_suppression_duration (sec|nanosec)*> \n",
	"<!ELEMENT nack_period (sec|nanosec)*> \n",
	"<!ELEMENT publication_reader_resource_limits (initial_samples|max_samples|initial_infos|max_infos|initial_outstanding_reads|max_outstanding_reads|max_samples_per_read)*> \n",
	"<!ELEMENT subscription_reader (min_heartbeat_response_delay|max_heartbeat_response_delay|heartbeat_suppression_duration|nack_period)*> \n",
	"<!ELEMENT subscription_reader_resource_limits (initial_samples|max_samples|initial_infos|max_infos|initial_outstanding_reads|max_outstanding_reads|max_samples_per_read)*> \n",
	"<!ELEMENT participant_message_reader (min_heartbeat_response_delay|max_heartbeat_response_delay|heartbeat_suppression_duration|nack_period)*>\n",
	"<!ELEMENT participant_proxy_reader (min_heartbeat_response_delay|max_heartbeat_response_delay|heartbeat_suppression_duration|nack_period)*> \n",
	"<!ELEMENT publication_writer (low_watermark|high_watermark|heartbeat_period|fast_heartbeat_period|late_joiner_heartbeat_period|max_heartbeat_retries|inactivate_nonprogressing_readers|heartbeats_per_max_samples|min_nack_response_delay|max_nack_response_delay|disable_positive_acks_min_sample_keep_duration|disable_positive_acks_max_sample_keep_duration|disable_positive_acks_sample_min_separation|disable_positive_acks_enable_adaptive_sample_keep_duration|disable_positive_acks_enable_spin_wait|disable_positive_acks_decrease_sample_keep_duration_factor|disable_positive_acks_increase_sample_keep_duration_factor|nack_suppression_duration|max_bytes_per_nack_response|min_send_window_size|max_send_window_size|send_window_update_period|send_window_increase_factor|send_window_decrease_factor)*> \n",
	"<!ELEMENT low_watermark (#PCDATA)> \n",
	"<!ELEMENT high_watermark (#PCDATA)> \n",
	"<!ELEMENT heartbeat_period (sec|nanosec)*> \n",
	"<!ELEMENT fast_heartbeat_period (sec|nanosec)*>\n",
	"<!ELEMENT late_joiner_heartbeat_period (sec|nanosec)*> \n",
	"<!ELEMENT send_window_update_period (sec|nanosec)*> \n",
	"<!ELEMENT max_heartbeat_retries (#PCDATA)> \n",
	"<!ELEMENT inactivate_nonprogressing_readers (#PCDATA)> \n",
	"<!ELEMENT heartbeats_per_max_samples (#PCDATA)> \n",
	"<!ELEMENT disable_positive_acks_increase_sample_keep_duration_factor (#PCDATA)> \n",
	"<!ELEMENT disable_positive_acks_decrease_sample_keep_duration_factor (#PCDATA)> \n",
	"<!ELEMENT disable_positive_acks_enable_adaptive_sample_keep_duration (#PCDATA)> \n",
	"<!ELEMENT disable_positive_acks_enable_spin_wait (#PCDATA)> \n",
	"<!ELEMENT min_nack_response_delay (sec|nanosec)*> \n",
	"<!ELEMENT max_nack_response_delay (sec|nanosec)*> \n",
	"<!ELEMENT nack_suppression_duration (sec|nanosec)*> \n",
	"<!ELEMENT disable_positive_acks_min_sample_keep_duration (sec|nanosec)*> \n",
	"<!ELEMENT disable_positive_acks_max_sample_keep_duration (sec|nanosec)*> \n",
	"<!ELEMENT disable_positive_acks_sample_min_separation (sec|nanosec)*> \n",
	"<!ELEMENT max_bytes_per_nack_response (#PCDATA)> \n",
	"<!ELEMENT min_send_window_size (#PCDATA)> \n",
	"<!ELEMENT max_send_window_size (#PCDATA)> \n",
	"<!ELEMENT send_window_increase_factor (#PCDATA)> \n",
	"<!ELEMENT send_window_decrease_factor (#PCDATA)> \n",
	"<!ELEMENT subscription_writer (low_watermark|high_watermark|heartbeat_period|fast_heartbeat_period|late_joiner_heartbeat_period|max_heartbeat_retries|inactivate_nonprogressing_readers|heartbeats_per_max_samples|min_nack_response_delay|max_nack_response_delay|disable_positive_acks_min_sample_keep_duration|disable_positive_acks_max_sample_keep_duration|disable_positive_acks_sample_min_separation|disable_positive_acks_enable_adaptive_sample_keep_duration|disable_positive_acks_enable_spin_wait|disable_positive_acks_decrease_sample_keep_duration_factor|disable_positive_acks_increase_sample_keep_duration_factor|nack_suppression_duration|max_bytes_per_nack_response|min_send_window_size|max_send_window_size|send_window_update_period|send_window_increase_factor|send_window_decrease_factor)*>\n",
	"<!ELEMENT participant_message_writer (low_watermark|high_watermark|heartbeat_period|fast_heartbeat_period|late_joiner_heartbeat_period|max_heartbeat_retries|inactivate_nonprogressing_readers|heartbeats_per_max_samples|min_nack_response_delay|max_nack_response_delay|disable_positive_acks_min_sample_keep_duration|disable_positive_acks_max_sample_keep_duration|disable_positive_acks_sample_min_separation|disable_positive_acks_enable_adaptive_sample_keep_duration|disable_positive_acks_enable_spin_wait|disable_positive_acks_decrease_sample_keep_duration_factor|disable_positive_acks_increase_sample_keep_duration_factor|nack_suppression_duration|max_bytes_per_nack_response|min_send_window_size|max_send_window_size|send_window_update_period|send_window_increase_factor|send_window_decrease_factor)*>\n",
	"<!ELEMENT participant_state_writer (low_watermark|high_watermark|heartbeat_period|fast_heartbeat_period|late_joiner_heartbeat_period|max_heartbeat_retries|inactivate_nonprogressing_readers|heartbeats_per_max_samples|min_nack_response_delay|max_nack_response_delay|disable_positive_acks_min_sample_keep_duration|disable_positive_acks_max_sample_keep_duration|disable_positive_acks_sample_min_separation|disable_positive_acks_enable_adaptive_sample_keep_duration|disable_positive_acks_enable_spin_wait|disable_positive_acks_decrease_sample_keep_duration_factor|disable_positive_acks_increase_sample_keep_duration_factor|nack_suppression_duration|max_bytes_per_nack_response|min_send_window_size|max_send_window_size|send_window_update_period|send_window_increase_factor|send_window_decrease_factor)*>\n",
	"<!ELEMENT builtin_discovery_plugins (#PCDATA)> \n",
	"<!ELEMENT name (#PCDATA|element)*> \n",
	"<!ELEMENT propagate (#PCDATA)> \n",
	"<!ELEMENT kind (#PCDATA)> \n",
	"<!ELEMENT direct_communication (#PCDATA)> \n",
	"<!ELEMENT service_cleanup_delay (sec|nanosec)*> \n",
	"<!ELEMENT history_kind (#PCDATA)> \n",
	"<!ELEMENT history_depth (#PCDATA)> \n",
	"<!ELEMENT max_instances (#PCDATA)> \n",
	"<!ELEMENT max_samples_per_instance (#PCDATA)> \n",
	"<!ELEMENT initial_instances (#PCDATA)> \n",
	"<!ELEMENT instance_hash_buckets (#PCDATA)> \n",
	"<!ELEMENT period (sec|nanosec)*> \n",
	"<!ELEMENT duration (sec|nanosec)*> \n",
	"<!ELEMENT lease_duration (sec|nanosec)*> \n",
	"<!ELEMENT max_blocking_time (sec|nanosec)*> \n",
	"<!ELEMENT source_timestamp_tolerance (sec|nanosec)*> \n",
	"<!ELEMENT depth (#PCDATA)> \n",
	"<!ELEMENT refilter (#PCDATA)> \n",
	"<!ELEMENT access_scope (#PCDATA)> \n",
	"<!ELEMENT coherent_access (#PCDATA)> \n",
	"<!ELEMENT ordered_access (#PCDATA)> \n",
	"<!ELEMENT disable_asynchronous_write (#PCDATA)> \n",
	"<!ELEMENT disable_asynchronous_batch (#PCDATA)> \n",
	"<!ELEMENT asynchronous_batch_blocking_kind (#PCDATA)> \n",
	"<!ELEMENT use_shared_exclusive_area (#PCDATA)> \n",
	"<!ELEMENT level (#PCDATA)> \n",
	"<!ELEMENT initial_concurrent_blocking_threads (#PCDATA)> \n",
	"<!ELEMENT max_concurrent_blocking_threads (#PCDATA)> \n",
	"<!ELEMENT max_remote_reader_filters (#PCDATA)> \n",
	"<!ELEMENT initial_batches (#PCDATA)> \n",
	"<!ELEMENT max_batches (#PCDATA)> \n",
	"<!ELEMENT autoregister_instances (#PCDATA)> \n",
	"<!ELEMENT instance_replacement (#PCDATA)> \n",
	"<!ELEMENT replace_empty_instances (#PCDATA)> \n",
	"<!ELEMENT virtual_guid (value)> \n",
	"<!ELEMENT rtps_object_id (#PCDATA)> \n",
	"<!ELEMENT push_on_write (#PCDATA)> \n",
	"<!ELEMENT disable_positive_acks (#PCDATA)> \n",
	"<!ELEMENT disable_inline_keyhash (#PCDATA)> \n",
	"<!ELEMENT serialize_key_with_dispose (#PCDATA)> \n",
	"<!ELEMENT rtps_reliable_writer (low_watermark|high_watermark|heartbeat_period|fast_heartbeat_period|late_joiner_heartbeat_period|max_heartbeat_retries|inactivate_nonprogressing_readers|heartbeats_per_max_samples|min_nack_response_delay|max_nack_response_delay|disable_positive_acks_min_sample_keep_duration|disable_positive_acks_max_sample_keep_duration|disable_positive_acks_sample_min_separation|disable_positive_acks_enable_adaptive_sample_keep_duration|disable_positive_acks_enable_spin_wait|disable_positive_acks_decrease_sample_keep_duration_factor|disable_positive_acks_increase_sample_keep_duration_factor|nack_suppression_duration|max_bytes_per_nack_response|min_send_window_size|max_send_window_size|send_window_update_period|send_window_increase_factor|send_window_decrease_factor)*> \n",
	"<!ELEMENT plugin_data (#PCDATA)> \n",
	"<!ELEMENT autodispose_unregistered_instances (#PCDATA)> \n",
	"<!ELEMENT flow_controller_name (#PCDATA)> \n",
	"<!ELEMENT minimum_separation (sec|nanosec)*> \n",
	"<!ELEMENT autopurge_nowriter_samples_delay (sec|nanosec)*> \n",
	"<!ELEMENT autopurge_disposed_samples_delay (sec|nanosec)*> \n",
	"<!ELEMENT max_remote_writers (#PCDATA)> \n",
	"<!ELEMENT max_remote_writers_per_instance (#PCDATA)> \n",
	"<!ELEMENT max_samples_per_remote_writer (#PCDATA)> \n",
	"<!ELEMENT initial_remote_writers (#PCDATA)> \n",
	"<!ELEMENT initial_remote_writers_per_instance (#PCDATA)> \n",
	"<!ELEMENT disable_fragmentation_support (#PCDATA)> \n",
	"<!ELEMENT max_fragmented_samples (#PCDATA)> \n",
	"<!ELEMENT initial_fragmented_samples (#PCDATA)> \n",
	"<!ELEMENT max_fragmented_samples_per_remote_writer (#PCDATA)> \n",
	"<!ELEMENT max_fragments_per_sample (#PCDATA)> \n",
	"<!ELEMENT dynamically_allocate_fragmented_samples (#PCDATA)> \n",
	"<!ELEMENT max_total_instances (#PCDATA)> \n",
	"<!ELEMENT rtps_reliable_reader (min_heartbeat_response_delay|max_heartbeat_response_delay|heartbeat_suppression_duration|nack_period)*> \n",
	"<!ELEMENT receive_address (#PCDATA)> \n",
	"<!ELEMENT expects_inline_qos (#PCDATA)> \n",
	"<!ELEMENT propagate_dispose_of_unregistered_instances (#PCDATA)> \n",
	"<!ELEMENT vendor_specific_entity (#PCDATA)> \n",
	"<!ELEMENT enable (#PCDATA)> \n",
	"<!ELEMENT max_data_bytes (#PCDATA)> \n",
	"<!ELEMENT max_meta_data_bytes (#PCDATA)> \n",
	"<!ELEMENT max_flush_delay (sec|nanosec)*> \n",
	"<!ELEMENT source_timestamp_resolution (sec|nanosec)*> \n",
	"<!ELEMENT thread_safe_write (#PCDATA)> \n",
	"<!ELEMENT channels (element)*> \n",
	"<!ELEMENT filter_name (#PCDATA)> \n",
	"<!ELEMENT filter_expression (#PCDATA)> \n",
	"<!ELEMENT multicast_settings (element)*> \n",
	"<!ELEMENT port (#PCDATA)> \n",
	"<!ELEMENT address (#PCDATA)> \n",
	"<!ELEMENT channel_seq_max_length (#PCDATA)> \n",
	"<!ELEMENT channel_filter_expression_max_length (#PCDATA)> \n",
	"<!ELEMENT max_remote_virtual_writers_per_instance (#PCDATA)> \n",
	"<!ELEMENT initial_remote_virtual_writers_per_instance (#PCDATA)> \n",
	"<!ELEMENT max_query_condition_filters (#PCDATA)> \n",
	"<!ELEMENT type_library (include|const|directive|struct|valuetype|sparse_valuetype|union|typedef|module|enum|forward_dcl)+> \n",
	"<!ATTLIST type_library name NMTOKEN #IMPLIED> \n",
	"<!ELEMENT plugin_config (plugin_element*)>\n",
	"<!ELEMENT plugin_element (#PCDATA)>\n",
	"<!ATTLIST plugin_element name CDATA #REQUIRED>\n",
	"<!ELEMENT type_definition (include|const|directive|struct|valuetype|union|typedef|module|enum|forward_dcl)+>\n",
	"<!ATTLIST type_definition type_name CDATA #REQUIRED>\n",
	"<!ELEMENT module (include|const|directive|struct|union|typedef|module|enum|valuetype|forward_dcl)+>\n",
	"<!ATTLIST module name NMTOKEN #REQUIRED>\n",
	"<!ELEMENT valuetype (const?|member|directive?)+>\n",
	"<!ATTLIST valuetype name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST valuetype baseClass CDATA #IMPLIED>\n",
	"<!ATTLIST valuetype typeModifier (custom|none|truncatable|abstract) #IMPLIED>\n",
	"<!ATTLIST valuetype topLevel (true|false|1|0) \"true\">\n",
	"<!ELEMENT include EMPTY>\n",
	"<!ATTLIST include file CDATA #REQUIRED >\n",
	"<!ELEMENT struct (member|directive)+>\n",
	"<!ATTLIST struct name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST struct topLevel (true|false|1|0) \"true\">\n",
	"<!ELEMENT union (discriminator,(case|directive)+)>\n",
	"<!ATTLIST union name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST union topLevel (true|false|1|0) \"true\">\n",
	"<!ELEMENT const EMPTY>\n",
	"<!ATTLIST const name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST const value CDATA #REQUIRED>\n",
	"<!ATTLIST const type (char|string|short|long|float|boolean|double|octet|wchar|wstring|longLong|unsignedLongLong|longShort|longDouble|unsignedShort|unsignedLong|nonBasic) #REQUIRED>\n",
	"<!ATTLIST const nonBasicTypeName CDATA #IMPLIED>\n",
	"<!ATTLIST const resolveName (true|false|1|0) #IMPLIED>\n",
	"<!ELEMENT discriminator EMPTY>\n",
	"<!ATTLIST discriminator type (char|string|short|long|float|boolean|double|octet|wchar|wstring|longLong|unsignedLongLong|longShort|longDouble|unsignedShort|unsignedLong|nonBasic) #REQUIRED>\n",
	"<!ATTLIST discriminator nonBasicTypeName CDATA #IMPLIED>\n",
	"<!ELEMENT case ((caseDiscriminator)+,member)>\n",
	"<!ELEMENT caseDiscriminator EMPTY>\n",
	"<!ATTLIST caseDiscriminator value CDATA #REQUIRED>\n",
	"<!ELEMENT member EMPTY>\n",
	"<!ATTLIST member name NMTOKEN #IMPLIED>\n",
	"<!ATTLIST member visibility (public|private) #IMPLIED>\n",
	"<!ATTLIST member pointer (true|false|1|0) #IMPLIED>\n",
	"<!ATTLIST member type (char|string|short|long|float|boolean|double|octet|wchar|wstring|longLong|unsignedLongLong|longShort|longDouble|unsignedShort|unsignedLong|nonBasic) #REQUIRED>\n",
	"<!ATTLIST member nonBasicTypeName CDATA #IMPLIED>\n",
	"<!ATTLIST member bitField CDATA #IMPLIED>\n",
	"<!ATTLIST member stringMaxLength CDATA #IMPLIED>\n",
	"<!ATTLIST member sequenceMaxLength CDATA #IMPLIED>\n",
	"<!ATTLIST member key (true|false|1|0) \"false\">\n",
	"<!ATTLIST member resolveName (true|false|1|0) #IMPLIED>\n",
	"<!ATTLIST member arrayDimensions CDATA #IMPLIED>\n",
	"<!ELEMENT typedef EMPTY>\n",
	"<!ATTLIST typedef name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST typedef type (char|string|short|long|float|boolean|double|octet|wchar|wstring|longLong|unsignedLongLong|longShort|longDouble|unsignedShort|unsignedLong|nonBasic) #REQUIRED>\n",
	"<!ATTLIST typedef nonBasicTypeName CDATA #IMPLIED>\n",
	"<!ATTLIST typedef stringMaxLength CDATA #IMPLIED>\n",
	"<!ATTLIST typedef sequenceMaxLength CDATA #IMPLIED>\n",
	"<!ATTLIST typedef pointer (true|false|1|0) #IMPLIED>\n",
	"<!ATTLIST typedef resolveName (true|false|1|0) #IMPLIED>\n",
	"<!ATTLIST typedef arrayDimensions CDATA #IMPLIED>\n",
	"<!ATTLIST typedef topLevel (true|false|1|0) \"true\">\n",
	"<!ELEMENT enum (enumerator)+>\n",
	"<!ATTLIST enum name NMTOKEN #REQUIRED>\n",
	"<!ELEMENT enumerator EMPTY>\n",
	"<!ATTLIST enumerator name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST enumerator value CDATA #IMPLIED>\n",
	"<!ELEMENT forward_dcl EMPTY>\n",
	"<!ATTLIST forward_dcl name NMTOKEN #REQUIRED>\n",
	"<!ATTLIST forward_dcl kind NMTOKEN #REQUIRED>\n",
	"<!ELEMENT directive (#PCDATA) >\n",
	"<!ATTLIST directive kind (copy|copyC|copyJava|copyDeclaration|copyCDeclaration|copyJavaDeclaration|copyCppcli|copyCppcliDeclaration) #REQUIRED>\n"
    };


    parser = DDS_XMLParser_new();
    if(parser == NULL) {
	cerr << "Error creating XML parser" << endl;
	return false;
    }
	
    if(!register_plugin_extensions(parser,user_extensions)) {
    	DDS_XMLParser_delete(parser);
    	return false;
    }
    
    root =  DDS_XMLParser_parse_from_file(parser, 
					  CAVECANEM_PLUGIN_DTD,
					  DTD_CAVECANEM_PLUGIN_LINE_NUMBER,
					  cfg_file.c_str(),
					  NULL);
    
    if(root == NULL) {
	cerr << cfg_file << " is not a valid configuration file" << endl;
	DDS_XMLParser_delete(parser);
	return false;
    }
    
        
    DDS_XMLParser_delete(parser);
    return true; 
	
}


/** 
 * @brief Registers the XML extension classes for parsing the general properties.
 *
 * Registers all the custom extensions classes created for parsing the XML file of the
 * general configuration.
 * @param parser The XML_parser
 * @param user_extensions The user extension class
 * 
 * @return Returns true if the extensions were registered and false if they were not.
 */
bool XML_parser::register_general_extensions(struct DDS_XMLParser *parser,
					     struct DDS_XMLExtensionClass **user_extensions)
{
    int i = 0;
    //Here I should register parser extensions...
    user_extensions[i++] = DDS_XMLExtensionClass_new("cavecanem", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);


    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'cavecanem'" << endl;
	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("general", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'general'" << endl;
    	return NULL;
    }



    user_extensions[i++] = DDS_XMLExtensionClass_new("publishing_period_sec",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);

    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'publishing_period_sec'" << endl;
    	return false;
    }


    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_properties",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'dds__properties'" << endl;
    	return false;
    }


    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_domain_id",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);

    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'domain_id'" << endl;
    	return false;
    }


    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_qos_file",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'qos_file'" << endl;
    	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_qos_default_library",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'qos_file'" << endl;
    	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_qos_default_profile",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'qos_file'" << endl;
    	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("plugins",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);

    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'plugins'" << endl;
    	return false;
    }

	
    user_extensions[i++] = DDS_XMLExtensionClass_new("plugin_library",
						     NULL,
						     DDS_BOOLEAN_TRUE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);

    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'plugin_library'" << endl;
    	return false;
    }


    user_extensions[i++] = DDS_XMLExtensionClass_new("plugin",
						     NULL,
						     DDS_BOOLEAN_TRUE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);

    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'plugin'" << endl;
    	return false;
    }


    user_extensions[i++] = DDS_XMLExtensionClass_new("plugin_regex",
						     NULL,
						     DDS_BOOLEAN_TRUE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_general_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);

    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'plugin_regex'" << endl;
    	return false;
    }


	

    for(int i=0; i<DTD_CAVECANEM_EXTENSION_NUMBER; i++)// {
	if(!DDS_XMLParser_register_extension_class(parser, user_extensions[i]))
 	    cerr << "Error registering the extension "  << endl;

    // }
    

    return true;

}




/** 
 * @brief Registers the XML extension classes for parsing the plugin configuration files.
 *
 * It registers all the custom extensions classes created for parsing the XML configuration
 * file of a plugin.
 * @param self The XML_parser
 * @param user_extensions The user extension class
 * 
 * @return Returns true if the extensions were registered and false if they were not.
 */
bool XML_parser::register_plugin_extensions(struct DDS_XMLParser *self,
					    struct DDS_XMLExtensionClass **user_extensions) 
{
    int i=0;
    user_extensions[i++] = DDS_XMLExtensionClass_new("plugin", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'plugin'" << endl;
	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("dll", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'dll'" << endl;
	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("create_function", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'create_function'" << endl;
	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("publishing_period_sec", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'publishing_period_sec'" << endl;
	return false;
    }


    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_properties", 
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'dds_properties'" << endl;
	return false;
    }

  
    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_qos_library",
    						     NULL,
    						     DDS_BOOLEAN_FALSE,
    						     DDS_BOOLEAN_TRUE,
    						     XML_parser_start,
    						     XML_parser_plugin_end,
    						     XML_parser_new, 
    						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'qos_library'" << endl;
    	return false;
    }
    
    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_qos_profile",
    						     NULL,
    						     DDS_BOOLEAN_FALSE,
    						     DDS_BOOLEAN_TRUE,
    						     XML_parser_start,
    						     XML_parser_plugin_end,
    						     XML_parser_new, 
    						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'qos_profile'" << endl;
    	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("dds_topic_name",
    						     NULL,
    						     DDS_BOOLEAN_FALSE,
    						     DDS_BOOLEAN_TRUE,
    						     XML_parser_start,
    						     XML_parser_plugin_end,
    						     XML_parser_new, 
    						     XML_parser_delete,
						     NULL);
    
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'dds_topic_name'" << endl;
    	return false;
    }

						  
    user_extensions[i++] = DDS_XMLExtensionClass_new("plugin_config",
						     NULL,
						     DDS_BOOLEAN_FALSE,
						     DDS_BOOLEAN_TRUE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'plugin_config'" << endl;
	return false;
    }

	
    user_extensions[i++] = DDS_XMLExtensionClass_new("plugin_element",
						     NULL,
						     DDS_BOOLEAN_TRUE,
						     DDS_BOOLEAN_FALSE,
						     XML_parser_start,
						     XML_parser_plugin_end,
						     XML_parser_new, 
						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'element'" << endl;
	return false;
    }

    user_extensions[i++] = DDS_XMLExtensionClass_new("type_definition",
    						     NULL,
    						     DDS_BOOLEAN_TRUE,
    						     DDS_BOOLEAN_FALSE,
    						     XML_parser_start,
    						     XML_parser_plugin_end,
    						     XML_parser_new, 
    						     XML_parser_delete,
						     NULL);
    if(user_extensions[i-1] == NULL) {
    	cerr << "RTIXMLExtensionClass_new Error: could not install custom extension 'types'" << endl;
    	return false;
    }


    for(int i=0; i<DTD_CAVECANEM_PLUGIN_EXTENSION_NUMBER; i++)
	if(!DDS_XMLParser_register_extension_class(self, user_extensions[i]))
	    cerr << "Error registering the extension " << endl;
    
    return true;
}



/** 
 * @brief Sets the publishing period of the general configuration.
 * 
 * Sets the rate for calling the plugins to publish.
 * @param publishing_period This parameter indicates the rate of calling the plugins
 * to publish.
 */
void XML_parser::set_publishing_period(int publishing_period)
{

    if(publishing_period <= 0)
	general_properties_.publishing_period = 1;

    else 
	general_properties_.publishing_period = publishing_period;
}


/** 
 * @brief Sets the DDS Domain.
 *
 * Sets the DDS Domain in which the plugins will publish information. 
 * @param domain_id DDS Domain ID.
 */
void XML_parser::set_domain_id(int domain_id)
{
    general_properties_.domain_id = domain_id;
}


/** 
 * @brief Sets the file from which all the plugins will load their QoS.
 * 
 * @param qos_file QoS definitions file.
 */
void XML_parser::set_qos_file(string qos_file)
{
    qos_file = string(CAVECANEM_DIR) + "/" + qos_file;
    general_properties_.qos_file = qos_file;
}



/** 
 * @brief Sets the QoS default library for DDS Domain Participant and DDS Publisher.
 * 
 * Sets the QoS library for the DDS Domain Participant and the DDS Publisher.
 * @param qos_library Name of the QoS library.
 */
void XML_parser::set_qos_default_library(string qos_library)
{
    general_properties_.qos_library = qos_library;
}


/** 
 * @brief Sets the QoS default library for DDS Domain Participant and DDS Publisher
 * 
 * Sets the QoS profile for the DDS Domain Participant and the DDS Publisher.
 * @param qos_profile Name of the QoS profile.
 */
void XML_parser::set_qos_default_profile(string qos_profile)
{
    general_properties_.qos_profile = qos_profile;
}



/** 
 * @brief Stores a new plugin library in the plugin_library_map_.
 * 
 * Given a dir and a plugin list, this method stores them in the plugin_library_map_.
 * @param dir Plugin library directory.
 * @param plugin_list List of plugins whithin the plugin library directory.
 */
void XML_parser::set_plugin_library(string dir, list<string> plugin_list)
{
    general_properties_.plugin_list_map[dir] = plugin_list;
}



/** 
 * @brief Returns the general properties of Cave Canem.
 * 
 * Returns a structure with the general properties of Cave Canem once
 * the XML general configuration file has been parsed and read.
 * @return 
 */
cc_general_properties XML_parser::get_general_properties()
{
    return general_properties_;
}


/** 
 * @brief Stores temporally the name of a plugin in a list, that will be included whithin a plugin library afterwards.
 * 
 * This method stores a plugin name in a temporal list that corresponds to
 * the plugins contained whithin the directory of a plugin library.
 * @param tmp_plugin The name of the plugin to be stored.
 */
void XML_parser::add_tmp_plugin(string tmp_plugin)
{
    tmp_plugin_list_.push_back(tmp_plugin);
}


/** 
 * @brief Returns the temporal list of plugins.
 * 
 * Returns the temporal list of plugins to be loaded from a plugin library.
 * @return The list of plugins to be from a plugin library.
 */
list<string> XML_parser::get_tmp_plugin_list()
{
    return tmp_plugin_list_;
}


/** 
 * @brief Cleans the temporal list of plugins.
 * 
 * Cleans the temporal list of plugins.
 */
void XML_parser::clear_tmp_plugin_list()
{
    tmp_plugin_list_.clear();
}


/** 
 * @brief Sets the name of the dynamic library of a plugin.
 *  
 * Sets the name of a dynamic library in the temporal structure
 * that stores the information of the plugin while it is being extracted.
 * @param dll The dynamic library name.
 */
void XML_parser::set_tmp_plugin_properties_dll(string dll)
{
    tmp_plugin_properties_.dll = dll;
}


/** 
 * @brief Sets the create function of a plugin.
 * 
 * Sets the name of the create function of the plugin in the temporal
 * structure that stores the information of a plugin while it is being extrated.
 * @param create_function Name of the create function
 */
void XML_parser::set_tmp_plugin_properties_create_function(string create_function)
{
    tmp_plugin_properties_.create_function = create_function;
}


/** 
 * @brief Sets the QoS library for a plugin.
 * 
 * Sets the name of the QoS library for a plugin in the temporal structure
 * that stores the information of a plugin while it is being created.
 * @param qos_library DDS QoS library for the plugin's DataWriter.
 */
void XML_parser::set_tmp_plugin_properties_qos_library(string qos_library)
{
    tmp_plugin_properties_.qos_library = qos_library;
}


/** 
 * @brief Sets the QoS profile for a plugin.
 * 
 * Sets the name of the QoS profile for a plugin in the temporal structure
 * that stores the information of a plugin while it is being created.
 * @param qos_profile DDS QoS profile for the plugin's DataWriter.
 */
void XML_parser::set_tmp_plugin_properties_qos_profile(string qos_profile)
{
    tmp_plugin_properties_.qos_profile = qos_profile;
}


/** 
 * @brief Adds an element to the plugin elements list.
 * 
 * Adds a new element for the plugin list of elements in the temporal structure
 * that stores the information of a plugin while it is being created.
 * @param name Name of the plugin element.
 * @param value Value of the plugin element.
 */
void XML_parser::set_tmp_plugin_properties_add_element(string name,string value)
{
    tmp_plugin_properties_.plugin_config[name] = value;
}


/** 
 * @brief Sets the typecode of the plugin.
 * 
 * Sets the typecode of the plugin in the temporal structure
 * that stores the information of a plugin while it is being created.
 * @param type_code Type Code of the plugin's data type.
 */
void XML_parser::set_tmp_plugin_properties_type_code(struct DDS_TypeCode* type_code)
{
    tmp_plugin_properties_.type_code = type_code;
}


/** 
 * @brief Sets the QoS for the DDS DataWriter if defined (the QoS).
 * 
 * Sets the QoS for the DDS DataWriter that the plugin will use if it is 
 * defined. If it is not defined, the qos_library and qos_profile parameters 
 * will decide the QoS of it.
 * @param datawriter_qos DDS DataWriter QoS for the plugin's datawriter.
 */
void XML_parser::set_tmp_plugin_properties_datawriter_qos(const struct DDS_DataWriterQos *datawriter_qos)
{
    tmp_plugin_properties_.datawriter_qos = datawriter_qos;
}


/** 
 * Sets the publishing rate of the plugin.
 *  
 * Sets the publishing rate of the plugin in the temporal structure
 * that stores the information of a plugin while it is being created.
 * @param publishing_period Publishing rate of the plugin.
 */
void XML_parser::set_tmp_plugin_properties_publishing_period(int publishing_period)
{
    if(publishing_period <= 0)
	tmp_plugin_properties_.publishing_period = 1;
    else
	tmp_plugin_properties_.publishing_period = publishing_period;
}

/** 
 * Sets the topic name--if defined--of the plugin.
 * 
 * Sets the topic name in the temporal structure that stores the 
 * information of a plugin while it is being created.
 * @param topic_name Name of the topic.
 */
void XML_parser::set_tmp_plugin_properties_topic_name(string topic_name)
{
    tmp_plugin_properties_.topic_name = topic_name;
}

/** 
 * Sets the plugin properties store in the temporal cc_plugin_properties structure.
 * 
 * Stores the plugin properties in the plugin_properties_map_ taking the contents
 * of the tmp_plugin_properties_ structure.
 * @param plugin_name Name of the plugin.
 */
void XML_parser::set_plugin_properties(string plugin_name)
{
    if(tmp_plugin_properties_.topic_name.size() > 0) {
	plugin_properties_map_[plugin_name] = tmp_plugin_properties_;
    }
    
    else {
	tmp_plugin_properties_.topic_name = plugin_name;
	plugin_properties_map_[plugin_name] = tmp_plugin_properties_; 
    }
    
    tmp_plugin_properties_.dll = "";
    tmp_plugin_properties_.create_function = "";
    tmp_plugin_properties_.qos_library = "";
    tmp_plugin_properties_.qos_profile = "";
    tmp_plugin_properties_.datawriter_qos = NULL;
    tmp_plugin_properties_.topic_name = "";
    tmp_plugin_properties_.plugin_config.clear();

}


/** 
 * @brief This method returns the properties of a plugin.
 *
 * It returns the properties of a plugin after a correct parsing. 
 * @param plugin_name Name of the plugin.
 * 
 * @return The properties of the plugin stored in a cc_plugin_properties structure.
 */
cc_plugin_properties XML_parser::get_plugin_properties(string plugin_name)
{
    return plugin_properties_map_[plugin_name];
}



/** 
 * @brief Called when a new start tag is found inside the element of a extension class.
 *
 * Function called when a new start tag is found inside the element associated 
 * to the extension class of the input object.
 * 
 * @param self Pointer to the XML Object.
 * @param tag_name Name of the tag.
 * @param attr List of attributes associated to the start tag.
 * @param context Pointer to the XML context.
 */
void XML_parser_start(struct DDS_XMLObject *self,
		      const char *tag_name,
		      const char **attr,
		      struct DDS_XMLContext *context)
{



    int i = 0, length = 0;
    const char **str = NULL;
    RTIXMLCaveCanemExtensionObjectElement *element = NULL;
    RTIXMLCaveCanemExtensionObject *object = 
	(RTIXMLCaveCanemExtensionObject *)self;

    

    // RTIXMLLog_testPrecondition(context == NULL, return);
    // RTIXMLLog_testPrecondition(self == NULL || tag_name == NULL, context->error = RTI_TRUE; return);

    RTIOsapiHeap_allocateStructure(&element, RTIXMLCaveCanemExtensionObjectElement);
    
    if (element == NULL) {
        // RTIXMLLog_exception( METHOD_NAME,
        //                      &RTI_OSAPI_MEMORY_LOG_OUT_OF_HEAP_STRUCT_d,
        //                      sizeof(struct RTIXMLCaveCanemExtensionObjectElement));
        /* We relase the memory of each element in the finalize method*/
        context->error = RTI_TRUE;
        return;
    }
    
    element->tag_name = REDAString_duplicate(tag_name);

    if (element->tag_name == NULL) {
	// RTIXMLLog_exception(METHOD_NAME,
        //                     &RTI_OSAPI_MEMORY_LOG_OUT_OF_HEAP_STRING_d,
        //                     strlen(tag_name));
	/* We relase the memory of each element in the finalize method*/
        context->error = RTI_TRUE;
        return;
    }
    
    /* Gets to know the attributes matrix size */
    for (str = attr; *str != '\0'; str++) {
        ++length;
    }
    
    /* length is always goint to be either 1 or an odd value */
    element->attr_length = length;

    /* Copying attributes */
    if (length > 0) {
        /* Allocate memory for the attributes of the element */
        RTIOsapiHeap_allocateArray(&element->attr, element->attr_length+1, char *);

        if (element->attr == NULL) {
            // RTIXMLLog_exception(METHOD_NAME,
            //                 &RTI_OSAPI_MEMORY_LOG_OUT_OF_HEAP_ARRAY_dd,
            //                 element->attr_length, sizeof(char *));

            context->error = RTI_TRUE;
            return;
        }

        for (i = 0; i < element->attr_length; i++) {    
            RTIOsapiHeap_allocateString(&element->attr[i], (int)strlen(attr[i]));

            if (element->attr[i] == NULL) {
                // RTIXMLLog_exception(METHOD_NAME,
                //             &RTI_OSAPI_MEMORY_LOG_OUT_OF_HEAP_STRING_d,
                //             strlen(attr[i]));
		
                context->error = RTI_TRUE;
                return;
            }
            strcpy(element->attr[i], attr[i]);
        }


    }

    /* Storing the RTIXMLCaveCanemExtensionObjectElement */
    if( object->current_element_index < XML_CAVECANEM_MAX_NUMBER_OF_NON_EXTENSION_TAGS){
        object->tag_elements[object->current_element_index++] = element;
	
    } 
    else {
	// RTIXMLLog_exception( METHOD_NAME,
        //                      &RTI_LOG_ANY_s,
        //                      "error processing object tag: number of non tags overpassed");

	/* We relase the memory of each element in the finalize method*/
        context->error = DDS_BOOLEAN_TRUE;
        return;
    } 

}    


/** 
 * @brief Stores the general information while parsing the general XML configuration file.
 * 
 * Called each time it is found a custom extension class defined by us, it stores
 * all the information needed from the general XML configuration file.
 * @param self Pointer to the XML object.
 * @param tag_name Name of the tag.
 * @param element_text The element text.
 * @param context Pointer to the XML context. 
 */
void XML_parser_general_end(struct DDS_XMLObject *self,
			    const char *tag_name,
			    const char *element_text,
			    struct DDS_XMLContext *context)
{


    //printf("%s %s\n", METHOD_NAME, tagName); 
    struct RTIXMLCaveCanemExtensionObject * object = (struct RTIXMLCaveCanemExtensionObject *)self;
    

    if(!strcmp(tag_name,"publishing_period_sec")) {
	// aux_general_properties.publishing_period = atoi(element_text);
	XML_parser::get_singleton()->set_publishing_period(atoi(element_text));
    }
    else if(!strcmp(tag_name,"dds_domain_id")) {
	// aux_general_properties.domain_id = atoi(element_text);
	XML_parser::get_singleton()->set_domain_id(atoi(element_text));
    }
    else if(!strcmp(tag_name,"dds_qos_file")) {
	// aux_general_properties.qos_file = string(element_text);
	XML_parser::get_singleton()->set_qos_file(string(element_text));
    }
    else if(!strcmp(tag_name,"dds_qos_default_library")) {
	XML_parser::get_singleton()->set_qos_default_library(string(element_text));
    }
    else if(!strcmp(tag_name,"dds_qos_default_profile")) {
	XML_parser::get_singleton()->set_qos_default_profile(string(element_text));
    }
    else if(!strcmp(tag_name,"plugin_library")) {
	string dir(RTIXMLHelper_getAttribute((const char**)object->attr, "dir"));

	list<string> tmp_plugin_list = 
	    XML_parser::get_singleton()->get_tmp_plugin_list();
	XML_parser::get_singleton()->set_plugin_library(dir,tmp_plugin_list);

	XML_parser::get_singleton()->clear_tmp_plugin_list();
    }
    else if(!strcmp(tag_name, "plugin")) {
	XML_parser::get_singleton()->add_tmp_plugin(string(element_text));

    }
    else if(!strcmp(tag_name,"plugin_regex")) {
    }
   
}


/** 
 * @brief Stores the general information while parsing the general XML configuration file.
 * 
 * Called each time it is found a custom extension class defined by us, it stores
 * all the information needed from the general XML configuration file.
 * @param self Pointer to the XML object.
 * @param tag_name Name of the tag.
 * @param element_text The element text.
 * @param context Pointer to the XML context. 
 */
void XML_parser_plugin_end(struct DDS_XMLObject *self,
			   const char *tag_name,
			   const char *element_text,
			   struct DDS_XMLContext *context)
{

  
   struct RTIXMLCaveCanemExtensionObject * object = (struct RTIXMLCaveCanemExtensionObject *)self;
    
    //Load plugin configuration-----------------------------------
    if(!strcmp(tag_name,"plugin")) {
    	string name(RTIXMLHelper_getAttribute((const char**)object->attr, "name"));
	XML_parser::get_singleton()->set_plugin_properties(name);
    }

    //DLL of the plugin-------------------------------------------
    else if(!strcmp(tag_name,"dll")) {
	XML_parser::get_singleton()->set_tmp_plugin_properties_dll(string(element_text));
    }
  
    //Create function of the plugin-------------------------------
    else if(!strcmp(tag_name,"create_function")) {
	XML_parser::get_singleton()->set_tmp_plugin_properties_create_function(string(element_text));
    }
    
    else if(!strcmp(tag_name, "publishing_period_sec")) { 
	XML_parser::get_singleton()->set_tmp_plugin_properties_publishing_period(atoi(element_text));
    }
    //dds properties of the plugin--------------------------------
    else if(!strcmp(tag_name,"dds_properties")) {
	struct DDS_XMLObject *xml_object;
	const char *aux_tag_name;

	xml_object = DDS_XMLObject_get_first_child((struct DDS_XMLObject *)self);
	
	while (xml_object != NULL) {
	    aux_tag_name = DDS_XMLObject_get_tag_name(xml_object);
	    
	    //DataWriter QoS
	    if(!strcmp(aux_tag_name, "datawriter_qos")) {

		const struct DDS_DataWriterQos *datawriter_qos;

		datawriter_qos = 
		    DDS_XMLDataWriterQos_get_dds_qos((struct DDS_XMLDataWriterQos *) 
						     xml_object);

		XML_parser::get_singleton()->set_tmp_plugin_properties_datawriter_qos(datawriter_qos);

	    }
	    
	    xml_object = DDS_XMLObject_get_next_sibling(xml_object);
	}
    }

	    
    //DDS QoS Library
    else if(!strcmp(tag_name, "dds_qos_library")) {
	XML_parser::get_singleton()->set_tmp_plugin_properties_qos_library(string(element_text));
    }
    
    //DDS QoS Profile
    else if(!strcmp(tag_name, "dds_qos_profile")) {
	XML_parser::get_singleton()->set_tmp_plugin_properties_qos_profile(string(element_text));
    }
    
    else if(!strcmp(tag_name, "dds_topic_name")) {
	XML_parser::get_singleton()->set_tmp_plugin_properties_topic_name(string(element_text));
    }

    //Plugin elements--------------------------------------
    else if(!strcmp(tag_name, "plugin_element")) {
    	string name(RTIXMLHelper_getAttribute((const char**)object->attr, "name"));
	XML_parser::get_singleton()->
	    set_tmp_plugin_properties_add_element(name,
						  string(element_text));
    }

    //Type definition-------------------------------------
    else if(!strcmp(tag_name, "type_definition")) {

    	const char* type_name = 
    	RTIXMLHelper_getAttribute((const char**)object->attr, "type_name");

    	const struct DDS_TypeCode* aux_typecode = 
    	    XML_parser::get_singleton()->get_type_code_from_XML(self,
    								type_name,
    								context);
    	XML_parser::get_singleton()->
    	    set_tmp_plugin_properties_type_code((DDS_TypeCode *) aux_typecode);
	
    }

       
}


/** 
 * @brief Function used to create a new XML object.
 * 
 * Function used to create a new XML object.
 * @param extension_class Extension class of the new object.
 * @param parent_object Pointer to the parent object.
 * @param attr XML attributes associated to the object that is going to be created.
 * @param context Pointer to the XML context.
 * 
 * @return If there is an error, context->error must be set to DDS_BOOLEAN_TRUE.
 */
 struct DDS_XMLObject * XML_parser_new(const struct DDS_XMLExtensionClass *extension_class,
				     const struct DDS_XMLObject *parent_object,
				     const char **attr,
				     struct DDS_XMLContext *context)
{
    struct RTIXMLCaveCanemExtensionObject *me = NULL;


    RTIOsapiHeap_allocateStructure(&me, struct RTIXMLCaveCanemExtensionObject);


    if (me == NULL) {
	cerr << "Error: me NULL " << endl;
	context->error = DDS_BOOLEAN_TRUE;
        return NULL;
    }
    
    /* Initializes the RTIXMLCaveCanemExtensionObject object  */
    if (!RTIXMLCaveCanemExtensionObject_initialize(me, extension_class, parent_object, attr, context)) {
        cerr << "Error: init extension" << endl;
	RTIOsapiHeap_freeStructure(me);
	context->error = DDS_BOOLEAN_TRUE;
        return NULL;
    }

    return &me->base;
}


/** 
 * @brief Function used to delete an extension class object.
 * 
 * Function used to delete an extension class object.
 * @param self XML Object we want to delete.
 */
void XML_parser_delete(struct DDS_XMLObject * self)
{

    struct RTIXMLCaveCanemExtensionObject * object = (struct RTIXMLCaveCanemExtensionObject *)self;
    

    RTIXMLCaveCanemExtensionObject_finalize(object);
    RTIOsapiHeap_freeStructure(object);    
}



/** 
 * @brief Initializes the RTIXMLCaveCanemExtensionObject.
 * 
 * Initializes the RTIXMLCaveCanemExtensionObject.
 * @param self Pointer to the RTIXMLExtensionClass to be initialized.
 * @param extension_class Pointer to the DDS_XMLExtensionClass.
 * @param parent_object Pointer to the parent object.
 * @param attr XML attributes associated to the object.
 * @param context Pointer to the XML context.
 * 
 * @return 
 */
RTIBool RTIXMLCaveCanemExtensionObject_initialize(struct RTIXMLCaveCanemExtensionObject * self,
						  const struct DDS_XMLExtensionClass * extension_class,
						  const struct DDS_XMLObject * parent_object,
						  const char ** attr,
						  struct DDS_XMLContext * context) 
{    

    int i = 0, j = 0, length = 0;
    const char ** str = NULL;
    const char * name = NULL;

    if (self->base.parent._init == DDS_XML_MAGIC_NUMBER) {
        return DDS_BOOLEAN_TRUE;
    }
    
    RTIOsapiMemory_zero(self,sizeof(struct RTIXMLCaveCanemExtensionObject));

    /* Gets to know the attributes matrix size */
    for (str = attr; *str != '\0'; str++) {
        ++length;
    }

    /* length is always goint to be an odd value */
    self->attr_length = length;

    /* Initializing attributes */
    if (length > 0) {
        /* Allocate memory for the attributes of the given input object */
        RTIOsapiHeap_allocateArray(&self->attr, self->attr_length+1, char *);

        if (self->attr == NULL) {
            // RTIXMLLog_exception(METHOD_NAME,
	    // 			&RTI_OSAPI_MEMORY_LOG_OUT_OF_HEAP_ARRAY_dd,
	    // 			self->attr_length, sizeof(char *));
            self->attr_length = 0;

            context->error = DDS_BOOLEAN_TRUE;
            return DDS_BOOLEAN_FALSE;
        }

        for (i = 0; i < self->attr_length; i++) {
            RTIOsapiHeap_allocateString(&self->attr[i], (int)strlen(attr[i]));

            if (self->attr[i] == NULL) {
                // RTIXMLLog_exception(METHOD_NAME,
                //             &RTI_OSAPI_MEMORY_LOG_OUT_OF_HEAP_STRING_d,
                //             strlen(attr[i]));

                for (j = 0; self->attr[j] != NULL; j++) {
                    RTIOsapiHeap_freeString(self->attr[j]);
                }
                RTIOsapiHeap_freeArray(self->attr);
                self->attr_length = 0;
                context->error = DDS_BOOLEAN_TRUE;
                return DDS_BOOLEAN_FALSE;
            }
            strcpy(self->attr[i], attr[i]);
        }
    }

    /* Initializing RTIXMLParserObjectElement array */
    for( i = 0; i < XML_CAVECANEM_MAX_NUMBER_OF_NON_EXTENSION_TAGS; i++){
        self->tag_elements[i] = NULL;
    }

    name = RTIXMLHelper_getAttribute(attr,"name");

    /* Initializes the RTIXMLObject with the name */
    if (!DDS_XMLObject_initialize(&self->base, extension_class, parent_object, name, NULL)) {

	// RTIXMLLog_exception( METHOD_NAME, &RTI_LOG_INIT_FAILURE_s, 
        //                      "RTIXMLCaveCanemExtensionObject" );
	
        for( i = 0; i < self->attr_length; i++){
            if (self->attr[i] != NULL) {            
                RTIOsapiHeap_freeString(self->attr[i]);
            }
        }
        RTIOsapiHeap_freeArray(self->attr);
        self->attr_length = 0;

        context->error = DDS_BOOLEAN_TRUE;
        return DDS_BOOLEAN_FALSE;
    }


    return DDS_BOOLEAN_TRUE;       

}


/** 
 * @brief Finalizes the RTIXMLCaveCanemExtensionObject.
 * 
 * Finalizes RTIXMLCaveCanemExtensionObject.
 * @param self RTIXMLCaveCanemExtensionObject.
 */
void RTIXMLCaveCanemExtensionObject_finalize(struct RTIXMLCaveCanemExtensionObject * self)
{

    struct RTIXMLCaveCanemExtensionObjectElement * ptr = NULL;
    int counter = 0, i = 0;

    // RTIXMLLog_testPrecondition(self == NULL, return);
    
    if (self->base.parent._init != DDS_XML_MAGIC_NUMBER) {
        return;
    }

    /* Finalizing elements (object attribute tags) of the given input object */
    ptr = self->tag_elements[counter];

    while (ptr != NULL && counter < XML_CAVECANEM_MAX_NUMBER_OF_NON_EXTENSION_TAGS){

        /* Finalizing tagName */
        if (ptr->tag_name != NULL) {
            RTIOsapiHeap_freeString(ptr->tag_name);
        }

        /* Finalizing elementText */
        if (ptr->element_text != NULL) {
            RTIOsapiHeap_freeString(ptr->element_text);
        }

        /* Finalizing attributes */
        if (ptr->attr != NULL) {
            for( i = 0; i < ptr->attr_length; i++) {
                if (ptr->attr[i] != NULL) {                
                    RTIOsapiHeap_freeString(ptr->attr[i]);
                }
            }
            /* Finalizing array of the attributes */
            RTIOsapiHeap_freeArray(ptr->attr);
        }

        /* Finalizing the object attribute tag itself */
        RTIOsapiHeap_freeStructure(ptr);

        /* Pointer to the previous freed element should be set to NULL */
        self->tag_elements[counter] = NULL;

        /* Next element to free */
        ptr = self->tag_elements[++counter];    
    }

    /* Finalizing attributes of the given input object */
    if (self->attr != NULL) {
        for( i = 0; i < self->attr_length; i++){
            if (self->attr[i] != NULL) {
                RTIOsapiHeap_freeString(self->attr[i]);
            }
        }

        RTIOsapiHeap_freeArray(self->attr);
    }

    /* Finalizing the base RTIXMLObject of the given input object */    
    DDS_XMLObject_finalize(&self->base);  

}


/** 
 * @brief Returns a DDS Type Code given a DDS XML Object
 * 
 * Returns a DDS Type Code looking for the XML definition of the data types 
 * contained whithin the tag <type_definition>.
 * @param xml XML Object containing the data types.
 * @param type_name Name of the data type associated to the topic.
 * @param context1 XML Contect.
 * 
 * @return 
 */
const struct DDS_TypeCode* XML_parser::get_type_code_from_XML(struct DDS_XMLObject *xml,
							      const char *type_name,
							      struct DDS_XMLContext *context1)
{
    struct DDS_XMLObject * xml_object = NULL;
    const struct DDS_TypeCode * type_code;
    const char * tag_name = NULL;
    struct DDS_XMLContext tmp_context, *context;


    if(xml == NULL) {
	cerr << "XML definition of " << type_name << " type is empty" << endl;
	return NULL;
    }

    context = context1 ? context1 : &tmp_context;

    xml_object = DDS_XMLObject_get_root(xml);
    if(xml_object == NULL){
	cerr << "Error getting DOM from the definition of " << type_name << endl;
        context->error = RTI_TRUE;
        return NULL;
    }

    /* Find the 'types' tag if any, that should be at the first level */

    xml_object = DDS_XMLObject_get_first_child(xml_object);
    while (xml_object != NULL) {
        if (!strcmp("type_definition", DDS_XMLObject_get_tag_name(xml_object))) {
            break;
        }
        xml_object = DDS_XMLObject_get_next_sibling(xml_object);
    }
    
    if(xml_object == NULL){
        cerr << "No tag 'type_defininiton', so no type definitions at all" << endl;
        return NULL;
    }

    xml_object = DDS_XMLObject_lookup(xml_object, type_name);

    if(xml_object == NULL){
        /* This type is not defined */
        return NULL;
    }

    tag_name = DDS_XMLObject_get_tag_name(xml_object);

    if (tag_name == NULL || 
        (strcmp(tag_name,"struct") &&
        strcmp(tag_name,"union") &&
        strcmp(tag_name,"enum") &&
        strcmp(tag_name,"valuetype") &&
        strcmp(tag_name,"sparse_valuetype"))) {
	cerr << "This is not a type definition" << endl;
        context->error = RTI_TRUE;
        return NULL;
    }

    type_code = DDS_XMLTypeCode_get_dds_typecode((struct DDS_XMLTypeCode *)xml_object);
    if(type_code == NULL){
        /* Parser error: requesting something that is not a type definition */
	cerr << type_name << ": Bad type definition" << endl;
        context->error = RTI_TRUE;
        return NULL;
    }

    return type_code;

}
