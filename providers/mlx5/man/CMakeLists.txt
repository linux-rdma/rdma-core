rdma_man_pages(
  mlx5dv_alloc_dm.3.md
  mlx5dv_alloc_var.3.md
  mlx5dv_create_cq.3.md
  mlx5dv_create_flow.3.md
  mlx5dv_create_flow_action_modify_header.3.md
  mlx5dv_create_flow_action_packet_reformat.3.md
  mlx5dv_create_flow_matcher.3.md
  mlx5dv_create_mkey.3.md
  mlx5dv_create_qp.3.md
  mlx5dv_crypto_login.3.md
  mlx5dv_dci_stream_id_reset.3.md
  mlx5dv_dek_create.3.md
  mlx5dv_devx_alloc_uar.3.md
  mlx5dv_devx_create_cmd_comp.3.md
  mlx5dv_devx_create_event_channel.3.md
  mlx5dv_devx_get_event.3.md
  mlx5dv_devx_obj_create.3.md
  mlx5dv_devx_qp_modify.3.md
  mlx5dv_devx_query_eqn.3.md
  mlx5dv_devx_subscribe_devx_event.3.md
  mlx5dv_devx_umem_reg.3.md
  mlx5dv_dm_map_op_addr.3.md
  mlx5dv_dr_flow.3.md
  mlx5dv_dump.3.md
  mlx5dv_flow_action_esp.3.md
  mlx5dv_get_clock_info.3
  mlx5dv_get_vfio_device_list.3.md
  mlx5dv_init_obj.3
  mlx5dv_is_supported.3.md
  mlx5dv_map_ah_to_qp.3.md
  mlx5dv_mkey_check.3.md
  mlx5dv_modify_qp_lag_port.3.md
  mlx5dv_modify_qp_sched_elem.3.md
  mlx5dv_modify_qp_udp_sport.3.md
  mlx5dv_open_device.3.md
  mlx5dv_pp_alloc.3.md
  mlx5dv_qp_cancel_posted_send_wrs.3.md
  mlx5dv_query_device.3
  mlx5dv_query_port.3.md
  mlx5dv_query_qp_lag_port.3.md
  mlx5dv_reserved_qpn_alloc.3.md
  mlx5dv_sched_node_create.3.md
  mlx5dv_ts_to_ns.3
  mlx5dv_wr_mkey_configure.3.md
  mlx5dv_vfio_get_events_fd.3.md
  mlx5dv_vfio_process_events.3.md
  mlx5dv_wr_post.3.md
  mlx5dv_wr_set_mkey_crypto.3.md
  mlx5dv_wr_set_mkey_sig_block.3.md
  mlx5dv.7
)
rdma_alias_man_pages(
 mlx5dv_alloc_var.3 mlx5dv_free_var.3
 mlx5dv_create_mkey.3 mlx5dv_destroy_mkey.3
 mlx5dv_crypto_login.3 mlx5dv_crypto_login_query_state.3
 mlx5dv_crypto_login.3 mlx5dv_crypto_logout.3
 mlx5dv_dek_create.3 mlx5dv_dek_query.3
 mlx5dv_dek_create.3 mlx5dv_dek_destroy.3
 mlx5dv_devx_alloc_uar.3 mlx5dv_devx_free_uar.3
 mlx5dv_devx_create_cmd_comp.3 mlx5dv_devx_destroy_cmd_comp.3
 mlx5dv_devx_create_event_channel.3 mlx5dv_devx_destroy_event_channel.3
 mlx5dv_devx_create_cmd_comp.3 mlx5dv_devx_get_async_cmd_comp.3
 mlx5dv_devx_obj_create.3 mlx5dv_devx_general_cmd.3
 mlx5dv_devx_obj_create.3 mlx5dv_devx_obj_destroy.3
 mlx5dv_devx_obj_create.3 mlx5dv_devx_obj_query.3
 mlx5dv_devx_obj_create.3 mlx5dv_devx_obj_query_async.3
 mlx5dv_devx_obj_create.3 mlx5dv_devx_obj_modify.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_qp_query.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_cq_modify.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_cq_query.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_wq_modify.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_wq_query.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_srq_modify.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_srq_query.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_ind_tbl_modify.3
 mlx5dv_devx_qp_modify.3 mlx5dv_devx_ind_tbl_query.3
 mlx5dv_devx_subscribe_devx_event.3 mlx5dv_devx_subscribe_devx_event_fd.3
 mlx5dv_devx_umem_reg.3 mlx5dv_devx_umem_dereg.3
 mlx5dv_devx_umem_reg.3 mlx5dv_devx_umem_reg_ex.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_aso.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_dest_table.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_dest_ib_port.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_dest_ibv_qp.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_dest_devx_tir.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_dest_vport.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_dest_array.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_flow_counter.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_drop.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_default_miss.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_flow_sampler.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_flow_meter.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_modify_header.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_packet_reformat.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_pop_vlan.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_push_vlan.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_create_tag.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_destroy.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_modify_aso.3
 mlx5dv_dr_flow.3 mlx5dv_dr_action_modify_flow_meter.3
 mlx5dv_dr_flow.3 mlx5dv_dr_aso_other_domain_link.3
 mlx5dv_dr_flow.3 mlx5dv_dr_aso_other_domain_unlink.3
 mlx5dv_dr_flow.3 mlx5dv_dr_domain_allow_duplicate_rules.3
 mlx5dv_dr_flow.3 mlx5dv_dr_domain_create.3
 mlx5dv_dr_flow.3 mlx5dv_dr_domain_destroy.3
 mlx5dv_dr_flow.3 mlx5dv_dr_domain_sync.3
 mlx5dv_dr_flow.3 mlx5dv_dr_domain_set_reclaim_device_memory.3
 mlx5dv_dr_flow.3 mlx5dv_dr_matcher_create.3
 mlx5dv_dr_flow.3 mlx5dv_dr_matcher_destroy.3
 mlx5dv_dr_flow.3 mlx5dv_dr_matcher_set_layout.3
 mlx5dv_dr_flow.3 mlx5dv_dr_rule_create.3
 mlx5dv_dr_flow.3 mlx5dv_dr_rule_destroy.3
 mlx5dv_dr_flow.3 mlx5dv_dr_table_create.3
 mlx5dv_dr_flow.3 mlx5dv_dr_table_destroy.3
 mlx5dv_dump.3 mlx5dv_dump_dr_domain.3
 mlx5dv_dump.3 mlx5dv_dump_dr_matcher.3
 mlx5dv_dump.3 mlx5dv_dump_dr_rule.3
 mlx5dv_dump.3 mlx5dv_dump_dr_table.3
 mlx5dv_pp_alloc.3 mlx5dv_pp_free.3
 mlx5dv_reserved_qpn_alloc.3 mlx5dv_reserved_qpn_dealloc.3
 mlx5dv_sched_node_create.3 mlx5dv_sched_leaf_create.3
 mlx5dv_sched_node_create.3 mlx5dv_sched_leaf_destroy.3
 mlx5dv_sched_node_create.3 mlx5dv_sched_leaf_modify.3
 mlx5dv_sched_node_create.3 mlx5dv_sched_node_destroy.3
 mlx5dv_sched_node_create.3 mlx5dv_sched_node_modify.3
 mlx5dv_wr_mkey_configure.3 mlx5dv_wr_set_mkey_access_flags.3
 mlx5dv_wr_mkey_configure.3 mlx5dv_wr_set_mkey_layout_interleaved.3
 mlx5dv_wr_mkey_configure.3 mlx5dv_wr_set_mkey_layout_list.3
 mlx5dv_wr_post.3 mlx5dv_wr_set_dc_addr.3
 mlx5dv_wr_post.3 mlx5dv_wr_set_dc_addr_stream.3
 mlx5dv_wr_post.3 mlx5dv_qp_ex_from_ibv_qp_ex.3
 mlx5dv_wr_post.3 mlx5dv_wr_memcpy.3
 mlx5dv_wr_post.3 mlx5dv_wr_mr_interleaved.3
 mlx5dv_wr_post.3 mlx5dv_wr_mr_list.3
 mlx5dv_wr_post.3 mlx5dv_wr_raw_wqe.3
)
