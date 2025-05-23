#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*Initialise 256 bit key and IV for cipher. Returns 0 on success, 1 on failure*/
int aes_init(const char *keydata, unsigned int keydata_len, unsigned char *key, unsigned char *iv)
{
    const unsigned char *salt = "1234554321";

    if (!EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, (unsigned char *)keydata, keydata_len, 5, key, iv))
    {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }
    return 0;
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

switch (subtype)
{
case NXAST_CUSTOM_ENCRYPT:
{
    unsigned char xor_key = 0xAA;

    unsigned char key[EVP_MAX_KEY_LENGTH], iv[EVP_MAX_IV_LENGTH];
    const char *password = "password";
    int i;

    unsigned char plaintext[1024], ciphertext[1024];
    int len;
    strcpy(plaintext, (unsigned char *)dp_packet_l4(packet));

    aes_init(password, (unsigned int)strlen(password), key, iv);

    len = encrypt(plaintext, (int)strlen(plaintext), key, iv, ciphertext);

    if (packet->l3_ofs != UINT16_MAX && packet->l4_ofs != UINT16_MAX)
    {
        size_t l4_len = dp_packet_size(packet) - ((unsigned char *)l4_data - (unsigned char *)dp_packet_data(packet));
        if (l4_data && l4_len > 0)
        {
            for (i = 0; i < l4_len; ++i)
            {
                l4_data[i] = ciphertext[i];
            }
        }
    }

    break;
}

case NXAST_CUSTOM_RANDOM_DELAY:
{
    /* WARNING: usleep() in packet path is VERY BAD for performance. Illustrative only. */
    const struct nx_action_random_delay *nxd = (const struct nx_action_random_delay *)a;
    uint32_t max_delay_us = ntohl(nxd->max_delay_us);
    if (max_delay_us > 0)
    {
        usleep(random_uint32() % max_delay_us);
    }
    break;
}

case NXAST_CUSTOM_POLICY:
{
    /* Highly simplified. Real policer needs per-flow state & locking. This is stateless and for demo only. */
    /* Conceptual: drop 10% of packets. Actual drop needs more specific handling. */
    if ((random_uint32() % 100) < 10)
    {
        // VLOG_INFO("CUSTOM_POLICE: Packet dropped (conceptual)");
        return; /* Exit action processing for this packet, effectively dropping it. */
    }
    break;
}

case NXAST_CUSTOM_TRAFFIC_PAD:
{
    const struct nx_action_traffic_pad *nxp = (const struct nx_action_traffic_pad *)a;
    uint16_t target_min_len = ntohs(nxp->target_min_len);
    size_t current_len = dp_packet_size(packet);

    if (current_len < target_min_len)
    {
        size_t padding_needed = target_min_len - current_len;
        void *padding_ptr;

        /* Define MAX_PADDING_SIZE appropriately to prevent excessive allocation */
        if (padding_needed > 0 && padding_needed < 2000 /*MAX_PADDING_SIZE*/)
        {
            padding_ptr = dp_packet_put_uninit(packet, padding_needed);
            if (padding_ptr)
            {
                memset(padding_ptr, 0, padding_needed);

                /* CRITICAL: Update L3/L4 length fields & handle checksums. */
                if (packet->l3_ofs != UINT16_MAX)
                {
                    struct ip_header *iph = dp_packet_l3(packet);
                    if (iph && iph->ip_v == 4)
                    { /* Assuming IPv4 */
                        iph->ip_tot_len = htons(ntohs(iph->ip_tot_len) + padding_needed);
                        if (iph->ip_proto == IPPROTO_UDP && packet->l4_ofs != UINT16_MAX)
                        {
                            struct udp_header *udph = dp_packet_l4(packet);
                            if (udph)
                            {
                                udph->udp_len = htons(ntohs(udph->udp_len) + padding_needed);
                            }
                        }
                    }
                    else if (iph && iph->ip_v == 6)
                    { /* Assuming IPv6 */
                        struct ovs_16aligned_ip6_hdr *ip6h = dp_packet_l3(packet);
                        ip6h->ip6_plen = htons(ntohs(ip6h->ip6_plen) + padding_needed);
                    }
                }
                /* Mark checksums for recomputation by clearing validation flags. */
                if (packet->ol_flags & PKT_TX_IP_CSUM)
                {
                    packet->ol_flags &= ~PKT_TX_IP_CSUM_VALID;
                }
                if (packet->ol_flags & PKT_TX_L4_CSUM)
                {
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