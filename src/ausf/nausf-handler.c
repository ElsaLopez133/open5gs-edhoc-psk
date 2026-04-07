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

static const char *edhoc_dummy_response = "EDHOC-RESPONSE";

static bool edhoc_dummy_response_matches(const char *hex_payload)
{
    uint8_t payload[256];
    int payload_len;

    ogs_assert(hex_payload);

    payload_len = strlen(hex_payload) / 2;
    if (payload_len < 5 || payload_len > (int)sizeof(payload))
        return false;

    ogs_ascii_to_hex(hex_payload, strlen(hex_payload), payload, sizeof(payload));

    if (payload[0] != 0x02 || payload[4] != 0x02)
        return false;

    if (payload_len - 5 != (int)strlen(edhoc_dummy_response))
        return false;

    return memcmp(payload + 5, edhoc_dummy_response,
            strlen(edhoc_dummy_response)) == 0;
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
    OpenAPI_confirmation_data_t *ConfirmationData = NULL;
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
        if (!edhoc_dummy_response_matches(res_star_string)) {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
        } else {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
            ogs_info("EDHOC: dummy authentication response accepted for UE[%s]",
                    ausf_ue->suci);
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
