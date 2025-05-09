/*
 * These snippets belong in a function like do_execute_actions() in lib/odp-execute.c
 * 'packet' is 'struct dp_packet *'. 'a' is the current OpenFlow action.
 */

/* ... (Inside OFPAT_VENDOR case, after checking vendor is NX_VENDOR_ID) ... */
// const struct nx_action_header *nah = (const struct nx_action_header *)a;
// uint16_t subtype = ntohs(nah->subtype);

switch (subtype) {
    case NXAST_CUSTOM_ENCRYPT: {
        /* WARNING: TOY XOR cipher - NOT SECURE. For data manipulation demo only. */
        unsigned char xor_key = 0xAA;
        size_t i;

        if (packet->l3_ofs != UINT16_MAX && packet->l4_ofs != UINT16_MAX) {
            unsigned char *l4_data = (unsigned char*)dp_packet_l4(packet);
            size_t l4_len = dp_packet_size(packet) - ((unsigned char*)l4_data - (unsigned char*)dp_packet_data(packet));
            if (l4_data && l4_len > 0) {
                for (i = 0; i < l4_len; ++i) {
                    l4_data[i] ^= xor_key;
                }
            }
        }
        /* Checksums for L3/L4 payload likely invalidated. OVS may handle this later. */
        break;
    }

    case NXAST_CUSTOM_RANDOM_DELAY: {
        /* WARNING: usleep() in packet path is VERY BAD for performance. Illustrative only. */
        const struct nx_action_random_delay *nxd = (const struct nx_action_random_delay *)a;
        uint32_t max_delay_us = ntohl(nxd->max_delay_us);
        if (max_delay_us > 0) {
            usleep(random_uint32() % max_delay_us);
        }
        break;
    }

    case NXAST_CUSTOM_POLICE: {
        /* WARNING: Highly simplified. Real policer needs per-flow state & locking. This is stateless. */
        /* Conceptual: drop 10% of packets. Actual drop needs more specific handling. */
        if ((random_uint32() % 100) < 10) {
            // VLOG_INFO("CUSTOM_POLICE: Packet dropped (conceptual)");
            return; /* Exit action processing for this packet, effectively dropping it. */
        }
        break;
    }

    case NXAST_CUSTOM_TRAFFIC_PAD: {
        const struct nx_action_traffic_pad *nxp = (const struct nx_action_traffic_pad *)a;
        uint16_t target_min_len = ntohs(nxp->target_min_len);
        size_t current_len = dp_packet_size(packet);

        if (current_len < target_min_len) {
            size_t padding_needed = target_min_len - current_len;
            void *padding_ptr;

            /* Define MAX_PADDING_SIZE appropriately to prevent excessive allocation */
            if (padding_needed > 0 && padding_needed < 2000 /*MAX_PADDING_SIZE*/) {
                padding_ptr = dp_packet_put_uninit(packet, padding_needed);
                if (padding_ptr) {
                    memset(padding_ptr, 0, padding_needed);

                    /* CRITICAL: Update L3/L4 length fields & handle checksums. */
                    if (packet->l3_ofs != UINT16_MAX) {
                        struct ip_header *iph = dp_packet_l3(packet);
                        if (iph && iph->ip_v == 4) { /* Assuming IPv4 */
                            iph->ip_tot_len = htons(ntohs(iph->ip_tot_len) + padding_needed);
                            if (iph->ip_proto == IPPROTO_UDP && packet->l4_ofs != UINT16_MAX) {
                                struct udp_header *udph = dp_packet_l4(packet);
                                if (udph) {
                                    udph->udp_len = htons(ntohs(udph->udp_len) + padding_needed);
                                }
                            }
                        } else if (iph && iph->ip_v == 6) { /* Assuming IPv6 */
                             struct ovs_16aligned_ip6_hdr *ip6h = dp_packet_l3(packet);
                             ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) + padding_needed);
                        }
                    }
                    /* Mark checksums for recomputation by clearing validation flags. */
                    if (packet->ol_flags & PKT_TX_IP_CSUM) {
                        packet->ol_flags &= ~PKT_TX_IP_CSUM_VALID;
                    }
                    if (packet->ol_flags & PKT_TX_L4_CSUM) {
                       packet->ol_flags &= ~PKT_TX_L4_CSUM_VALID;
                    }
                }
            }
        }
        break;
    }
    /* ... other NXAST_ cases ... */
}
/* ... (End of OFPAT_VENDOR / main switch) ... */