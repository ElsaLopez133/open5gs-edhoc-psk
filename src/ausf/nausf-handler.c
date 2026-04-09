/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
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
#include "nnrf-handler.h"
#include "nausf-handler.h"
#include "lakers.h"

static const uint8_t edhoc_responder_r[32] = {
    0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x44, 0x45,
    0x52, 0x5f, 0x44, 0x55, 0x4d, 0x4d, 0x59, 0x5f,
    0x52, 0x5f, 0x30, 0x31, 0x52, 0x45, 0x53, 0x50,
    0x4f, 0x4e, 0x44, 0x45, 0x52, 0x5f, 0x30, 0x32,
};

static const uint8_t edhoc_psk_cred[] = {
    0xA2, 0x02, 0x69, 0x72, 0x65, 0x73, 0x70, 0x6F, 0x6E, 0x64, 0x65,
    0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20,
    0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF,
    0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};

/* Demo initiator credential used by resolver callback for ByReference message_3. */
static const uint8_t edhoc_psk_cred_i[] = {
    0xA2, 0x02, 0x69, 0x69, 0x6E, 0x69, 0x74, 0x69, 0x61, 0x74, 0x6F,
    0x72, 0x08, 0xA1, 0x01, 0xA3, 0x01, 0x04, 0x02, 0x41, 0x10, 0x20,
    0x50, 0x50, 0x93, 0x0F, 0xF4, 0x62, 0xA7, 0x7A, 0x35, 0x40, 0xCF,
    0x54, 0x63, 0x25, 0xDE, 0xA2, 0x14,
};

typedef struct edhoc_cred_resolver_ctx_s {
    const uint8_t *cred;
    size_t cred_len;
} edhoc_cred_resolver_ctx_t;

static int8_t edhoc_resolve_cred_i(
        const IdCred *id_cred_i, CredentialC *cred_out, void *context)
{
    edhoc_cred_resolver_ctx_t *ctx = context;

    ogs_assert(id_cred_i);
    ogs_assert(cred_out);
    ogs_assert(ctx);
    ogs_assert(ctx->cred);
    ogs_assert(ctx->cred_len);

    /* Demo resolver: always return one fixed Initiator PSK credential.
     * FIXME: parse id_cred_i (e.g., kid) and fetch the matching credential
     * from UDM/UDR-backed subscriber data instead of hardcoded bytes. */
    (void)id_cred_i;
    return credential_new_symmetric(cred_out, ctx->cred, ctx->cred_len);
}

static bool edhoc_extract_message_from_eap(
        const char *hex_payload, EdhocMessageBuffer *message, uint8_t *eap_id)
{
    uint8_t payload[256];
    int eap_length;
    int payload_len;

    ogs_assert(hex_payload);
    ogs_assert(message);

    memset(message, 0, sizeof(*message));

    payload_len = strlen(hex_payload);
    if (payload_len == 0 || (payload_len % 2) != 0)
        return false;

    payload_len /= 2;
    if (payload_len < 5 || payload_len > (int)sizeof(payload))
        return false;

    ogs_ascii_to_hex((char *)hex_payload, strlen(hex_payload),
            payload, sizeof(payload));

    eap_length = ((int)payload[2] << 8) | payload[3];
    if (eap_length != payload_len)
        return false;

    /* We currently carry EDHOC in EAP Notification packets. */
    if (payload[0] != 0x02 || payload[4] != 0x02)
        return false;

    if ((payload_len - 5) <= 0 ||
        (payload_len - 5) > (int)sizeof(message->content))
        return false;

    if (eap_id)
        *eap_id = payload[1];

    message->len = payload_len - 5;
    memcpy(message->content, payload + 5, message->len);

    return true;
}

static bool edhoc_build_eap_request_hex(
        uint8_t eap_id, const EdhocMessageBuffer *message, char **hex_payload)
{
    uint8_t eap_packet[512];
    int eap_packet_len;

    ogs_assert(message);
    ogs_assert(hex_payload);

    *hex_payload = NULL;

    if (message->len == 0 || message->len > (sizeof(eap_packet) - 5))
        return false;

    eap_packet_len = 5 + message->len;
    eap_packet[0] = 0x01; /* EAP Request */
    eap_packet[1] = eap_id;
    eap_packet[2] = (eap_packet_len >> 8) & 0xff;
    eap_packet[3] = eap_packet_len & 0xff;
    eap_packet[4] = 0x02; /* EAP Notification */
    memcpy(eap_packet + 5, message->content, message->len);

    *hex_payload = ogs_malloc((eap_packet_len * 2) + 1);
    ogs_assert(*hex_payload);
    ogs_hex_to_ascii(eap_packet, eap_packet_len,
            *hex_payload, (eap_packet_len * 2) + 1);

    return true;
}
bool ausf_nausf_auth_handle_authenticate(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_authentication_info_t *AuthenticationInfo = NULL;
    char *serving_network_name = NULL;
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    AuthenticationInfo = recvmsg->AuthenticationInfo;
    if (!AuthenticationInfo) {
        ogs_error("[%s] No AuthenticationInfo", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No AuthenticationInfo", ausf_ue->suci, NULL));
        return false;
    }

    serving_network_name = AuthenticationInfo->serving_network_name;
    if (!serving_network_name) {
        ogs_error("[%s] No servingNetworkName", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No servingNetworkName", ausf_ue->suci, NULL));
        return false;
    }

    if (ausf_ue->serving_network_name)
        ogs_free(ausf_ue->serving_network_name);
    ausf_ue->serving_network_name = ogs_strdup(serving_network_name);
    ogs_assert(ausf_ue->serving_network_name);
    ausf_ue->edhoc_in_progress = false;
    memset(&ausf_ue->edhoc_responder, 0, sizeof(ausf_ue->edhoc_responder));
    ausf_ue->edhoc_c_i = 0;
    ausf_ue->edhoc_c_r = 0;

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_get,
            ausf_ue, stream, AuthenticationInfo->resynchronization_info);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

bool ausf_nausf_auth_handle_authenticate_confirmation(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_message_t sendmsg;
    ogs_sbi_response_t *response = NULL;
    OpenAPI_confirmation_data_t *ConfirmationData = NULL;
    OpenAPI_confirmation_data_response_t ConfirmationDataResponse;
    char *res_star_string = NULL;
    uint8_t res_star[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    ConfirmationData = recvmsg->ConfirmationData;
    if (!ConfirmationData) {
        ogs_error("[%s] No ConfirmationData", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData", ausf_ue->suci, NULL));
        return false;
    }

    res_star_string = ConfirmationData->res_star;
    if (!res_star_string) {
        ogs_error("[%s] No ConfirmationData.resStar", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData.resStar", ausf_ue->suci, NULL));
        return false;
    }

    if (ausf_ue->auth_type == OpenAPI_auth_type_EDHOC_PSK) {
        EdhocMessageBuffer message_from_ue;
        EdhocMessageBuffer message_2;
        CredentialC cred_r;
        EadItemsC ead_1;
        EadItemsC ead_2;
        EadItemsC ead_3;
        IdCred id_cred_i;
        edhoc_cred_resolver_ctx_t resolver_ctx;
        uint8_t c_i = 0;
        uint8_t c_r = 0;
        uint8_t eap_id = 0;
        char *message_2_hex = NULL;
        int8_t edhoc_rc;

        if (!edhoc_extract_message_from_eap(
                    res_star_string, &message_from_ue, &eap_id)) {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
        } else {
            if (!ausf_ue->edhoc_in_progress) {
                /* First EDHOC leg: parse message_1 and return message_2 with
                 * AUTHENTICATION_ONGOING so AMF relays it to UE. */
                memset(&ead_1, 0, sizeof(ead_1));
                memset(&ead_2, 0, sizeof(ead_2));
                memset(&message_2, 0, sizeof(message_2));
                memset(&cred_r, 0, sizeof(cred_r));

                edhoc_rc = responder_new(&ausf_ue->edhoc_responder);
                if (edhoc_rc == 0)
                    edhoc_rc = responder_process_message_1(
                            &ausf_ue->edhoc_responder,
                            &message_from_ue, &c_i, &ead_1);
                if (edhoc_rc == 0)
                    edhoc_rc = credential_new_symmetric(&cred_r,
                            edhoc_psk_cred, sizeof(edhoc_psk_cred));
                if (edhoc_rc == 0)
                    edhoc_rc = responder_prepare_message_2(
                            &ausf_ue->edhoc_responder,
                            (const BytesP256ElemLen *)edhoc_responder_r,
                            &cred_r, ByReference,
                            &c_r, &ead_2, &message_2);
                if (edhoc_rc == 0)
                    edhoc_rc = edhoc_build_eap_request_hex(
                            (uint8_t)(eap_id + 1),
                            &message_2, &message_2_hex) ? 0 : -1;

                if (edhoc_rc != 0) {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                    ogs_error("EDHOC: failed to generate message_2 for UE[%s] [rc=%d]",
                            ausf_ue->suci, edhoc_rc);
                } else {
                    ausf_ue->edhoc_in_progress = true;
                    ausf_ue->edhoc_c_i = c_i;
                    ausf_ue->edhoc_c_r = c_r;

                    memset(&ConfirmationDataResponse, 0, sizeof(ConfirmationDataResponse));
                    ConfirmationDataResponse.auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_ONGOING;
                    ConfirmationDataResponse.kseaf = message_2_hex;
                    ConfirmationDataResponse.supi = ausf_ue->supi;

                    memset(&sendmsg, 0, sizeof(sendmsg));
                    sendmsg.ConfirmationDataResponse = &ConfirmationDataResponse;

                    response = ogs_sbi_build_response(&sendmsg, OGS_SBI_HTTP_STATUS_OK);
                    ogs_assert(response);
                    ogs_assert(true == ogs_sbi_server_send_response(stream, response));

                    ogs_info("EDHOC: generated message_2 for UE[%s] [m1_len=%zu,m2_len=%zu,c_i=%u,c_r=%u]",
                            ausf_ue->suci, (size_t)message_from_ue.len,
                            (size_t)message_2.len,
                            ausf_ue->edhoc_c_i, ausf_ue->edhoc_c_r);

                    ogs_free(message_2_hex);
                    return true;
                }
            } else {
                /* Second EDHOC leg: parse message_3 using resolver-based lookup
                 * for ByReference ID_CRED_PSK. */
                memset(&ead_3, 0, sizeof(ead_3));
                memset(&id_cred_i, 0, sizeof(id_cred_i));
                memset(&resolver_ctx, 0, sizeof(resolver_ctx));
                resolver_ctx.cred = edhoc_psk_cred_i;
                resolver_ctx.cred_len = sizeof(edhoc_psk_cred_i);
                if (message_from_ue.len < 1) {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                    ogs_error("EDHOC: message_3 too short for UE[%s] [len=%zu]",
                            ausf_ue->suci, (size_t)message_from_ue.len);
                } else {
                    edhoc_rc = responder_parse_message_3_with_cred_resolver(
                            &ausf_ue->edhoc_responder,
                            &message_from_ue, &id_cred_i, &ead_3,
                            edhoc_resolve_cred_i, &resolver_ctx);
                    if (edhoc_rc != 0) {
                        ausf_ue->auth_result =
                            OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                        ogs_error("EDHOC: failed to parse message_3 for UE[%s] [rc=%d]",
                                ausf_ue->suci, edhoc_rc);
                    } else {
                        ausf_ue->auth_result =
                            OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
                        ausf_ue->edhoc_in_progress = false;
                        ogs_info("EDHOC: parsed message_3 for UE[%s] [len=%zu]",
                                ausf_ue->suci, (size_t)message_from_ue.len);
                    }
                }
            }
        }

        r = ausf_sbi_discover_and_send(
                OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
                ausf_nudm_ueau_build_result_confirmation_inform,
                ausf_ue, stream, NULL);
        ogs_expect(r == OGS_OK);
        ogs_assert(r != OGS_ERROR);

        return true;
    }

    ogs_ascii_to_hex(res_star_string, strlen(res_star_string),
            res_star, sizeof(res_star));

    if (memcmp(res_star, ausf_ue->xres_star, OGS_MAX_RES_LEN) != 0) {
        ogs_log_hexdump(OGS_LOG_WARN, res_star, OGS_MAX_RES_LEN);
        ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres_star, OGS_MAX_RES_LEN);

        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
    } else {
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
    }

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_result_confirmation_inform,
            ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}

bool ausf_nausf_auth_handle_authenticate_delete(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    int r;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    r = ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_auth_removal_ind,
            ausf_ue, stream, NULL);
    ogs_expect(r == OGS_OK);
    ogs_assert(r != OGS_ERROR);

    return true;
}
