/*
 * Copyright (C) 2019-2022 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sbi-path.h"

static ausf_context_t self;

int __ausf_log_domain;

static OGS_POOL(ausf_ue_pool, ausf_ue_t);

static int context_initialized = 0;

static const uint8_t default_edhoc_responder_r[32] = {
    0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x44, 0x45,
    0x52, 0x5f, 0x44, 0x55, 0x4d, 0x4d, 0x59, 0x5f,
    0x52, 0x5f, 0x30, 0x31, 0x52, 0x45, 0x53, 0x50,
    0x4f, 0x4e, 0x44, 0x45, 0x52, 0x5f, 0x30, 0x32,
};

static const uint8_t default_edhoc_psk_cred[] = {
    0xA2, 0x02, 0x69, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x64, 0x65,
    0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20,
    0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF,
    0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};

static int ausf_context_parse_hex(
        const char *field, const char *value,
        uint8_t *buf, size_t buf_size, size_t *out_len)
{
    size_t value_len = 0;

    ogs_assert(field);
    ogs_assert(value);
    ogs_assert(buf);
    ogs_assert(out_len);

    value_len = strlen(value);
    if (value_len == 0 || (value_len % 2) != 0) {
        ogs_error("AUSF EDHOC `%s` must be a non-empty even-length hex string",
                field);
        return OGS_ERROR;
    }

    *out_len = value_len / 2;
    if (*out_len > buf_size) {
        ogs_error("AUSF EDHOC `%s` is too large [%zu bytes > %zu bytes]",
                field, *out_len, buf_size);
        return OGS_ERROR;
    }

    memset(buf, 0, buf_size);
    ogs_ascii_to_hex((char *)value, value_len, buf, buf_size);
    return OGS_OK;
}

void ausf_context_init(void)
{
    ogs_assert(context_initialized == 0);

    /* Initialize AUSF context */
    memset(&self, 0, sizeof(ausf_context_t));

    ogs_log_install_domain(&__ausf_log_domain, "ausf", ogs_core()->log.level);

    ogs_pool_init(&ausf_ue_pool, ogs_global_conf()->max.ue);

    ogs_list_init(&self.ausf_ue_list);
    self.suci_hash = ogs_hash_make();
    ogs_assert(self.suci_hash);
    self.supi_hash = ogs_hash_make();
    ogs_assert(self.supi_hash);

    context_initialized = 1;
}

void ausf_context_final(void)
{
    ogs_assert(context_initialized == 1);

    ausf_ue_remove_all();

    ogs_assert(self.suci_hash);
    ogs_hash_destroy(self.suci_hash);
    ogs_assert(self.supi_hash);
    ogs_hash_destroy(self.supi_hash);

    ogs_pool_final(&ausf_ue_pool);

    context_initialized = 0;
}

ausf_context_t *ausf_self(void)
{
    return &self;
}

static int ausf_context_prepare(void)
{
    memcpy(self.edhoc.private_key, default_edhoc_responder_r,
            sizeof(default_edhoc_responder_r));
    self.edhoc.private_key_len = sizeof(default_edhoc_responder_r);

    memcpy(self.edhoc.credential, default_edhoc_psk_cred,
            sizeof(default_edhoc_psk_cred));
    self.edhoc.credential_len = sizeof(default_edhoc_psk_cred);

    return OGS_OK;
}

static int ausf_context_validation(void)
{
    if (self.edhoc.private_key_len != sizeof(self.edhoc.private_key)) {
        ogs_error("AUSF EDHOC private_key must decode to %zu bytes",
                sizeof(self.edhoc.private_key));
        return OGS_ERROR;
    }

    if (self.edhoc.credential_len == 0) {
        ogs_error("AUSF EDHOC credential must not be empty");
        return OGS_ERROR;
    }

    return OGS_OK;
}

int ausf_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;
    int idx = 0;

    document = ogs_app()->document;
    ogs_assert(document);

    rv = ausf_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if ((!strcmp(root_key, "ausf")) &&
            (idx++ == ogs_app()->config_section_id)) {
            ogs_yaml_iter_t ausf_iter;
            ogs_yaml_iter_recurse(&root_iter, &ausf_iter);
            while (ogs_yaml_iter_next(&ausf_iter)) {
                const char *ausf_key = ogs_yaml_iter_key(&ausf_iter);
                ogs_assert(ausf_key);
                if (!strcmp(ausf_key, "default")) {
                    /* handle config in sbi library */
                } else if (!strcmp(ausf_key, "sbi")) {
                    /* handle config in sbi library */
                } else if (!strcmp(ausf_key, "nrf")) {
                    /* handle config in sbi library */
                } else if (!strcmp(ausf_key, "scp")) {
                    /* handle config in sbi library */
                } else if (!strcmp(ausf_key, "service_name")) {
                    /* handle config in sbi library */
                } else if (!strcmp(ausf_key, "discovery")) {
                    /* handle config in sbi library */
                } else if (!strcmp(ausf_key, "edhoc")) {
                    ogs_yaml_iter_t edhoc_iter;
                    ogs_yaml_iter_recurse(&ausf_iter, &edhoc_iter);
                    while (ogs_yaml_iter_next(&edhoc_iter)) {
                        const char *edhoc_key = ogs_yaml_iter_key(&edhoc_iter);
                        const char *v = ogs_yaml_iter_value(&edhoc_iter);

                        ogs_assert(edhoc_key);
                        if (!strcmp(edhoc_key, "private_key")) {
                            if (!v || ausf_context_parse_hex(
                                        edhoc_key, v,
                                        self.edhoc.private_key,
                                        sizeof(self.edhoc.private_key),
                                        &self.edhoc.private_key_len) != OGS_OK)
                                return OGS_ERROR;
                        } else if (!strcmp(edhoc_key, "credential")) {
                            if (!v || ausf_context_parse_hex(
                                        edhoc_key, v,
                                        self.edhoc.credential,
                                        sizeof(self.edhoc.credential),
                                        &self.edhoc.credential_len) != OGS_OK)
                                return OGS_ERROR;
                        } else {
                            ogs_warn("unknown key `%s`", edhoc_key);
                        }
                    }
                } else
                    ogs_warn("unknown key `%s`", ausf_key);
            }
        }
    }

    rv = ausf_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

ausf_ue_t *ausf_ue_add(char *suci)
{
    ausf_event_t e;
    ausf_ue_t *ausf_ue = NULL;

    ogs_assert(suci);

    ogs_pool_id_calloc(&ausf_ue_pool, &ausf_ue);
    if (!ausf_ue) {
        ogs_error("ogs_pool_id_calloc() failed");
        return NULL;
    }

    ausf_ue->ctx_id =
        ogs_msprintf("%d", (int)ogs_pool_index(&ausf_ue_pool, ausf_ue));
    ogs_assert(ausf_ue->ctx_id);

    ausf_ue->suci = ogs_strdup(suci);
    ogs_assert(ausf_ue->suci);
    ogs_hash_set(self.suci_hash, ausf_ue->suci, strlen(ausf_ue->suci), ausf_ue);

    memset(&e, 0, sizeof(e));
    e.ausf_ue_id = ausf_ue->id;
    ogs_fsm_init(&ausf_ue->sm, ausf_ue_state_initial, ausf_ue_state_final, &e);

    ogs_list_add(&self.ausf_ue_list, ausf_ue);

    return ausf_ue;
}

void ausf_ue_remove(ausf_ue_t *ausf_ue)
{
    ausf_event_t e;

    ogs_assert(ausf_ue);

    ogs_list_remove(&self.ausf_ue_list, ausf_ue);

    memset(&e, 0, sizeof(e));
    e.ausf_ue_id = ausf_ue->id;
    ogs_fsm_fini(&ausf_ue->sm, &e);

    /* Free SBI object memory */
    ogs_sbi_object_free(&ausf_ue->sbi);

    ogs_assert(ausf_ue->ctx_id);
    ogs_free(ausf_ue->ctx_id);

    ogs_assert(ausf_ue->suci);
    ogs_hash_set(self.suci_hash, ausf_ue->suci, strlen(ausf_ue->suci), NULL);
    ogs_free(ausf_ue->suci);

    if (ausf_ue->supi) {
        ogs_hash_set(self.supi_hash,
                ausf_ue->supi, strlen(ausf_ue->supi), NULL);
        ogs_free(ausf_ue->supi);
    }

    AUTH_EVENT_CLEAR(ausf_ue);
    if (ausf_ue->auth_event.client)
        ogs_sbi_client_remove(ausf_ue->auth_event.client);

    if (ausf_ue->serving_network_name)
        ogs_free(ausf_ue->serving_network_name);
    
    ogs_pool_id_free(&ausf_ue_pool, ausf_ue);
}

void ausf_ue_remove_all(void)
{
    ausf_ue_t *ausf_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.ausf_ue_list, next, ausf_ue)
        ausf_ue_remove(ausf_ue);
}

ausf_ue_t *ausf_ue_find_by_suci(char *suci)
{
    ogs_assert(suci);
    return (ausf_ue_t *)ogs_hash_get(self.suci_hash, suci, strlen(suci));
}

ausf_ue_t *ausf_ue_find_by_supi(char *supi)
{
    ogs_assert(supi);
    return (ausf_ue_t *)ogs_hash_get(self.supi_hash, supi, strlen(supi));
}

ausf_ue_t *ausf_ue_find_by_suci_or_supi(char *suci_or_supi)
{
    ogs_assert(suci_or_supi);
    if (strncmp(suci_or_supi, "suci-", strlen("suci-")) == 0)
        return ausf_ue_find_by_suci(suci_or_supi);
    else
        return ausf_ue_find_by_supi(suci_or_supi);
}

ausf_ue_t *ausf_ue_find_by_ctx_id(char *ctx_id)
{
    ogs_assert(ctx_id);
    return ogs_pool_find(&ausf_ue_pool, atoll(ctx_id));
}

ausf_ue_t *ausf_ue_find_by_id(ogs_pool_id_t id)
{
    return ogs_pool_find_by_id(&ausf_ue_pool, id);
}

int get_ue_load(void)
{
    return (((ogs_pool_size(&ausf_ue_pool) -
            ogs_pool_avail(&ausf_ue_pool)) * 100) /
            ogs_pool_size(&ausf_ue_pool));
}
