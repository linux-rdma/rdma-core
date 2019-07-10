rdma_man_pages(
  ibv_advise_mr.3.md
  ibv_alloc_dm.3
  ibv_alloc_mw.3
  ibv_alloc_null_mr.3.md
  ibv_alloc_parent_domain.3
  ibv_alloc_pd.3
  ibv_alloc_td.3
  ibv_asyncwatch.1
  ibv_attach_counters_point_flow.3.md
  ibv_attach_mcast.3.md
  ibv_bind_mw.3
  ibv_create_ah.3
  ibv_create_ah_from_wc.3
  ibv_create_comp_channel.3
  ibv_create_counters.3.md
  ibv_create_cq.3
  ibv_create_cq_ex.3
  ibv_modify_cq.3
  ibv_create_flow.3
  ibv_create_flow_action.3.md
  ibv_create_qp.3
  ibv_create_qp_ex.3
  ibv_create_rwq_ind_table.3
  ibv_create_srq.3
  ibv_create_srq_ex.3
  ibv_create_wq.3
  ibv_devices.1
  ibv_devinfo.1
  ibv_event_type_str.3.md
  ibv_fork_init.3.md
  ibv_get_async_event.3
  ibv_get_cq_event.3
  ibv_get_device_guid.3.md
  ibv_get_device_list.3.md
  ibv_get_device_name.3.md
  ibv_get_pkey_index.3.md
  ibv_get_srq_num.3.md
  ibv_inc_rkey.3.md
  ibv_modify_qp.3
  ibv_modify_qp_rate_limit.3
  ibv_modify_srq.3
  ibv_modify_wq.3
  ibv_open_device.3
  ibv_open_qp.3
  ibv_open_xrcd.3
  ibv_poll_cq.3
  ibv_post_recv.3
  ibv_post_send.3
  ibv_post_srq_ops.3
  ibv_post_srq_recv.3
  ibv_query_device.3
  ibv_query_device_ex.3
  ibv_query_gid.3.md
  ibv_query_pkey.3.md
  ibv_query_port.3
  ibv_query_qp.3
  ibv_query_rt_values_ex.3
  ibv_query_srq.3
  ibv_rate_to_mbps.3.md
  ibv_rate_to_mult.3.md
  ibv_rc_pingpong.1
  ibv_read_counters.3.md
  ibv_reg_mr.3
  ibv_req_notify_cq.3.md
  ibv_rereg_mr.3.md
  ibv_resize_cq.3.md
  ibv_srq_pingpong.1
  ibv_uc_pingpong.1
  ibv_ud_pingpong.1
  ibv_wr_post.3.md
  ibv_xsrq_pingpong.1
  )
rdma_alias_man_pages(
  ibv_alloc_dm.3 ibv_free_dm.3
  ibv_alloc_dm.3 ibv_reg_dm_mr.3
  ibv_alloc_dm.3 ibv_memcpy_to_dm.3
  ibv_alloc_dm.3 ibv_memcpy_from_dm.3
  ibv_alloc_mw.3 ibv_dealloc_mw.3
  ibv_alloc_pd.3 ibv_dealloc_pd.3
  ibv_alloc_td.3 ibv_dealloc_td.3
  ibv_attach_mcast.3 ibv_detach_mcast.3
  ibv_create_ah.3 ibv_destroy_ah.3
  ibv_create_ah_from_wc.3 ibv_init_ah_from_wc.3
  ibv_create_comp_channel.3 ibv_destroy_comp_channel.3
  ibv_create_counters.3 ibv_destroy_counters.3
  ibv_create_cq.3 ibv_destroy_cq.3
  ibv_create_flow.3 ibv_destroy_flow.3
  ibv_create_flow_action.3 ibv_destroy_flow_action.3
  ibv_create_flow_action.3 ibv_modify_flow_action.3
  ibv_create_qp.3 ibv_destroy_qp.3
  ibv_create_rwq_ind_table.3 ibv_destroy_rwq_ind_table.3
  ibv_create_srq.3 ibv_destroy_srq.3
  ibv_create_wq.3 ibv_destroy_wq.3
  ibv_event_type_str.3 ibv_node_type_str.3
  ibv_event_type_str.3 ibv_port_state_str.3
  ibv_get_async_event.3 ibv_ack_async_event.3
  ibv_get_cq_event.3 ibv_ack_cq_events.3
  ibv_get_device_list.3 ibv_free_device_list.3
  ibv_open_device.3 ibv_close_device.3
  ibv_open_xrcd.3 ibv_close_xrcd.3
  ibv_rate_to_mbps.3 mbps_to_ibv_rate.3
  ibv_rate_to_mult.3 mult_to_ibv_rate.3
  ibv_reg_mr.3 ibv_dereg_mr.3
  ibv_wr_post.3 ibv_wr_abort.3
  ibv_wr_post.3 ibv_wr_complete.3
  ibv_wr_post.3 ibv_wr_start.3
  ibv_wr_post.3 ibv_wr_atomic_cmp_swp.3
  ibv_wr_post.3 ibv_wr_atomic_fetch_add.3
  ibv_wr_post.3 ibv_wr_bind_mw.3
  ibv_wr_post.3 ibv_wr_local_inv.3
  ibv_wr_post.3 ibv_wr_rdma_read.3
  ibv_wr_post.3 ibv_wr_rdma_write.3
  ibv_wr_post.3 ibv_wr_rdma_write_imm.3
  ibv_wr_post.3 ibv_wr_send.3
  ibv_wr_post.3 ibv_wr_send_imm.3
  ibv_wr_post.3 ibv_wr_send_inv.3
  ibv_wr_post.3 ibv_wr_send_tso.3
  ibv_wr_post.3 ibv_wr_set_inline_data.3
  ibv_wr_post.3 ibv_wr_set_inline_data_list.3
  ibv_wr_post.3 ibv_wr_set_sge.3
  ibv_wr_post.3 ibv_wr_set_sge_list.3
  ibv_wr_post.3 ibv_wr_set_ud_addr.3
  ibv_wr_post.3 ibv_wr_set_xrc_srqn.3
  )
