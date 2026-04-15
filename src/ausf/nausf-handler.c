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
#include <stdint.h>
#include <time.h>
#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
#define OGS_HAVE_CPU_CYCLES 1
#else
#define OGS_HAVE_CPU_CYCLES 0
#endif

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#define EDHOC_EAP_NOTIFICATION_TYPE 0x02
#define EDHOC_EXPORTER_LABEL_MSK 26
#define EDHOC_EXPORTER_LABEL_EMSK 27
#define EDHOC_EXPORTER_KEY_LEN 64

typedef struct edhoc_cred_resolver_ctx_s {
    const uint8_t *kid;
    size_t kid_len;
    const uint8_t *cred;
    size_t cred_len;
} edhoc_cred_resolver_ctx_t;

static inline uint64_t ogs_crypto_now_ns(void)
{
    struct timespec ts;

    ogs_assert(clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

#if OGS_HAVE_CPU_CYCLES
static inline uint64_t ogs_crypto_now_cycles(void)
{
    unsigned int aux;

    return __rdtscp(&aux);
}
#endif

static void ogs_log_edhoc_crypto(
        const char *label, uint64_t elapsed_ns, uint64_t elapsed_cycles,
        const char *suci)
{
#if OGS_HAVE_CPU_CYCLES
    ogs_info("EDHOC_CRYPTO: %s %llu ns %llu cycles UE[%s]",
            label,
            (unsigned long long)elapsed_ns,
            (unsigned long long)elapsed_cycles,
            suci);
#else
    (void)elapsed_cycles;
    ogs_info("EDHOC_CRYPTO: %s %llu ns N/A cycles UE[%s]",
            label, (unsigned long long)elapsed_ns, suci);
#endif
}

static bool edhoc_extract_kid_from_id_cred(
        const IdCred *id_cred_i, const uint8_t **kid, size_t *kid_len)
{
    const uint8_t *b = NULL;
    size_t len = 0;

    ogs_assert(id_cred_i);
    ogs_assert(kid);
    ogs_assert(kid_len);

    *kid = NULL;
    *kid_len = 0;

    b = id_cred_i->bytes.content;
    len = id_cred_i->bytes.len;
    if (!b || len < 3)
        return false;

    /* Expect full ID_CRED map form: {4: ...} */
    if (b[0] != 0xa1 || b[1] != 0x04)
        return false;

    /* CBOR byte string (preferred for ByReference kid) */
    if ((b[2] & 0xe0) == 0x40) {
        size_t n = b[2] & 0x1f;
        if (b[2] > 0x57 || len != (size_t)3 + n)
            return false;
        *kid = b + 3;
        *kid_len = n;
        return true;
    }

    /* Accept compact int encoding as a 1-byte kid for robustness. */
    if (b[2] <= 0x17 && len == 3) {
        *kid = b + 2;
        *kid_len = 1;
        return true;
    }

    return false;
}

static int8_t edhoc_resolve_cred_i(
        const IdCred *id_cred_i, CredentialC *cred_out, void *context)
{
    edhoc_cred_resolver_ctx_t *ctx = context;
    const uint8_t *kid = NULL;
    size_t kid_len = 0;

    ogs_assert(id_cred_i);
    ogs_assert(cred_out);
    ogs_assert(ctx);
    ogs_assert(ctx->kid);
    ogs_assert(ctx->kid_len);
    ogs_assert(ctx->cred);
    ogs_assert(ctx->cred_len);

    if (!edhoc_extract_kid_from_id_cred(id_cred_i, &kid, &kid_len)) {
        ogs_error("EDHOC: resolver failed to parse ID_CRED_I");
        return -1;
    }

    if (kid_len != ctx->kid_len || memcmp(kid, ctx->kid, kid_len) != 0) {
        ogs_error("EDHOC: unknown kid in ID_CRED_I [len=%zu]", kid_len);
        return -1;
    }

    /* Demo resolver: one local kid->credential mapping.
     * FIXME: replace this local mapping with UDM/UDR subscriber credential lookup. */
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
    if (payload[0] != 0x02 || payload[4] != EDHOC_EAP_NOTIFICATION_TYPE)
        return false;

    if ((payload_len - 5) < 0 ||
        (payload_len - 5) > (int)sizeof(message->content))
        return false;

    if (eap_id)
        *eap_id = payload[1];

    message->len = payload_len - 5;
    if (message->len > 0)
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
    eap_packet[4] = EDHOC_EAP_NOTIFICATION_TYPE; /* EAP Notification */
    memcpy(eap_packet + 5, message->content, message->len);

    *hex_payload = ogs_malloc((eap_packet_len * 2) + 1);
    ogs_assert(*hex_payload);
    ogs_hex_to_ascii(eap_packet, eap_packet_len,
            *hex_payload, (eap_packet_len * 2) + 1);

    return true;
}

static int edhoc_derive_kausf_from_exporter(ausf_ue_t *ausf_ue)
{
    uint8_t emsk[EDHOC_EXPORTER_KEY_LEN];
    int8_t edhoc_rc;
    uint64_t t0_ns, t1_ns;
#if OGS_HAVE_CPU_CYCLES
    uint64_t t0_cycles, t1_cycles;
#endif

    ogs_assert(ausf_ue);

    memset(emsk, 0, sizeof(emsk));

    /* This PoC runs EDHOC_PSK and only reuses EAP framing as an N1 carrier.
     * It does not implement the standardized EAP-EDHOC method, so there is
     * no real EAP-EDHOC type code to bind into the exporter context.
     *
     * For that reason the exporter context is left empty here, keeping EMSK
     * tied to the EDHOC transcript itself rather than to the temporary EAP
     * Notification wrapper used to relay bytes between UE and AMF/AUSF. */
    t0_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
    t0_cycles = ogs_crypto_now_cycles();
#endif
    edhoc_rc = responder_edhoc_exporter(
            &ausf_ue->edhoc_responder,
            EDHOC_EXPORTER_LABEL_EMSK,
            NULL, 0,
            emsk, sizeof(emsk));
    t1_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
    t1_cycles = ogs_crypto_now_cycles();
    ogs_log_edhoc_crypto("responder_edhoc_exporter", t1_ns - t0_ns,
            t1_cycles - t0_cycles, ausf_ue->suci);
#else
    ogs_log_edhoc_crypto("responder_edhoc_exporter", t1_ns - t0_ns,
            0, ausf_ue->suci);
#endif
    if (edhoc_rc != 0) {
        ogs_error("EDHOC: EMSK export failed for UE[%s] [rc=%d]",
                ausf_ue->suci, edhoc_rc);
        return OGS_ERROR;
    }

    memcpy(ausf_ue->kausf, emsk, OGS_SHA256_DIGEST_SIZE);

    ogs_info("EDHOC: derived KAUSF from exporter for UE[%s]", ausf_ue->suci);
    return OGS_OK;
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
    ausf_ue->edhoc_waiting_message4_ack = false;
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
    char *eap_payload_string = NULL;
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

    if (ausf_ue->auth_type == OpenAPI_auth_type_EDHOC_PSK) {
        EdhocMessageBuffer message_from_ue;
        EdhocMessageBuffer message_2;
        EdhocMessageBuffer message_4;
        CredentialC cred_r;
        EadItemsC ead_1;
        EadItemsC ead_2;
        EadItemsC ead_3;
        EadItemsC ead_4;
        IdCred id_cred_i;
        CredentialC cred_i_expected;
        uint8_t prk_out[SHA256_DIGEST_LEN];
        edhoc_cred_resolver_ctx_t resolver_ctx;
        uint8_t c_i = 0;
        uint8_t c_r = 0;
        uint8_t eap_id = 0;
        char *message_2_hex = NULL;
        char *message_4_hex = NULL;
        int8_t edhoc_rc;

        eap_payload_string = ConfirmationData->eap_payload;
        if (!eap_payload_string) {
            ogs_error("[%s] No ConfirmationData.eapPayload", ausf_ue->suci);
            ogs_assert(true ==
                ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                    recvmsg, "No ConfirmationData.eapPayload", ausf_ue->suci, NULL));
            return false;
        }

        if (!edhoc_extract_message_from_eap(
                    eap_payload_string, &message_from_ue, &eap_id)) {
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
        } else {
            if (!ausf_ue->edhoc_in_progress) {
                /* First EDHOC leg: parse message_1 and return message_2 with
                 * AUTHENTICATION_ONGOING so AMF relays it to UE. */
                ogs_time_t leg1_start = ogs_time_now();
                uint64_t t0_ns, t1_ns;
#if OGS_HAVE_CPU_CYCLES
                uint64_t t0_cycles, t1_cycles;
#endif
                memset(&ead_1, 0, sizeof(ead_1));
                memset(&ead_2, 0, sizeof(ead_2));
                memset(&message_2, 0, sizeof(message_2));
                memset(&cred_r, 0, sizeof(cred_r));

                edhoc_rc = responder_new(&ausf_ue->edhoc_responder);
                if (edhoc_rc == 0) {
                    t0_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                    t0_cycles = ogs_crypto_now_cycles();
#endif
                    edhoc_rc = responder_process_message_1(
                            &ausf_ue->edhoc_responder,
                            &message_from_ue, &c_i, &ead_1);
                    t1_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                    t1_cycles = ogs_crypto_now_cycles();
                    ogs_log_edhoc_crypto("responder_process_message_1",
                            t1_ns - t0_ns, t1_cycles - t0_cycles,
                            ausf_ue->suci);
#else
                    ogs_log_edhoc_crypto("responder_process_message_1",
                            t1_ns - t0_ns, 0, ausf_ue->suci);
#endif
                }

                if (edhoc_rc == 0)
                    edhoc_rc = credential_new_symmetric(&cred_r,
                            ausf_self()->edhoc.credential,
                            ausf_self()->edhoc.credential_len);
                if (edhoc_rc == 0) {
                    t0_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                    t0_cycles = ogs_crypto_now_cycles();
#endif
                    edhoc_rc = responder_prepare_message_2(
                            &ausf_ue->edhoc_responder,
                            (const BytesP256ElemLen *)ausf_self()->edhoc.private_key,
                            &cred_r, ByReference,
                            &c_r, &ead_2, &message_2);
                    t1_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                    t1_cycles = ogs_crypto_now_cycles();
                    ogs_log_edhoc_crypto("responder_prepare_message_2",
                            t1_ns - t0_ns, t1_cycles - t0_cycles,
                            ausf_ue->suci);
#else
                    ogs_log_edhoc_crypto("responder_prepare_message_2",
                            t1_ns - t0_ns, 0, ausf_ue->suci);
#endif
                }
                if (edhoc_rc == 0)
                    edhoc_rc = edhoc_build_eap_request_hex(
                            (uint8_t)(eap_id + 1),
                            &message_2, &message_2_hex) ? 0 : -1;
                ogs_info("EDHOC_TIMING: leg1_m1_m2 %lld us UE[%s]",
                    (long long)(ogs_time_now() - leg1_start),
                    ausf_ue->suci);

                if (edhoc_rc != 0) {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                    ogs_error("EDHOC: failed to generate message_2 for UE[%s] [rc=%d]",
                            ausf_ue->suci, edhoc_rc);
                } else {
                    ausf_ue->edhoc_in_progress = true;
                    ausf_ue->edhoc_waiting_message4_ack = false;
                    ausf_ue->edhoc_c_i = c_i;
                    ausf_ue->edhoc_c_r = c_r;

                    memset(&ConfirmationDataResponse, 0, sizeof(ConfirmationDataResponse));
                    ConfirmationDataResponse.auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_ONGOING;
                    ConfirmationDataResponse.edhoc_eap_payload = message_2_hex;
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
            } else if (!ausf_ue->edhoc_waiting_message4_ack) {
                /* Second EDHOC leg: parse message_3 and generate message_4.
                 * message_4 is relayed in AUTHENTICATION_ONGOING. */
                ogs_time_t leg2_start = ogs_time_now();
                uint64_t t0_ns, t1_ns;
#if OGS_HAVE_CPU_CYCLES
                uint64_t t0_cycles, t1_cycles;
#endif
                memset(&ead_3, 0, sizeof(ead_3));
                memset(&ead_4, 0, sizeof(ead_4));
                memset(&message_4, 0, sizeof(message_4));
                memset(&id_cred_i, 0, sizeof(id_cred_i));
                memset(&cred_i_expected, 0, sizeof(cred_i_expected));
                memset(prk_out, 0, sizeof(prk_out));
                memset(&resolver_ctx, 0, sizeof(resolver_ctx));
                if (!ausf_ue->edhoc_cred_i.kid_len ||
                    !ausf_ue->edhoc_cred_i.cred_i_len) {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                    ogs_error("EDHOC: missing initiator credential data from UDM for UE[%s]",
                            ausf_ue->suci);
                    r = ausf_sbi_discover_and_send(
                            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
                            ausf_nudm_ueau_build_result_confirmation_inform,
                            ausf_ue, stream, NULL);
                    ogs_expect(r == OGS_OK);
                    ogs_assert(r != OGS_ERROR);
                    return true;
                }
                resolver_ctx.kid = ausf_ue->edhoc_cred_i.kid;
                resolver_ctx.kid_len = ausf_ue->edhoc_cred_i.kid_len;
                resolver_ctx.cred = ausf_ue->edhoc_cred_i.cred_i;
                resolver_ctx.cred_len = ausf_ue->edhoc_cred_i.cred_i_len;
                if (message_from_ue.len < 1) {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                    ogs_error("EDHOC: message_3 too short for UE[%s] [len=%zu]",
                            ausf_ue->suci, (size_t)message_from_ue.len);
                } else {
                    t0_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                    t0_cycles = ogs_crypto_now_cycles();
#endif
                    edhoc_rc = responder_parse_message_3_with_cred_resolver(
                            &ausf_ue->edhoc_responder,
                            &message_from_ue, &id_cred_i, &ead_3,
                            edhoc_resolve_cred_i, &resolver_ctx);
                    t1_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                    t1_cycles = ogs_crypto_now_cycles();
                    ogs_log_edhoc_crypto("responder_parse_message_3",
                            t1_ns - t0_ns, t1_cycles - t0_cycles,
                            ausf_ue->suci);
#else
                    ogs_log_edhoc_crypto("responder_parse_message_3",
                            t1_ns - t0_ns, 0, ausf_ue->suci);
#endif

                    if (edhoc_rc != 0) {
                        ausf_ue->auth_result =
                            OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                        ogs_error("EDHOC: failed to parse message_3 for UE[%s] [rc=%d]",
                                ausf_ue->suci, edhoc_rc);
                    } else {
                        edhoc_rc = credential_new_symmetric(
                                &cred_i_expected,
                                resolver_ctx.cred, resolver_ctx.cred_len);
                        if (edhoc_rc == 0) {
                            t0_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                            t0_cycles = ogs_crypto_now_cycles();
#endif
                            edhoc_rc = responder_verify_message_3(
                                    &ausf_ue->edhoc_responder,
                                    &cred_i_expected, &prk_out);
                            t1_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                            t1_cycles = ogs_crypto_now_cycles();
                            ogs_log_edhoc_crypto("responder_verify_message_3",
                                    t1_ns - t0_ns, t1_cycles - t0_cycles,
                                    ausf_ue->suci);
#else
                            ogs_log_edhoc_crypto("responder_verify_message_3",
                                    t1_ns - t0_ns, 0, ausf_ue->suci);
#endif
                        }
                        if (edhoc_rc == 0) {
                            t0_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                            t0_cycles = ogs_crypto_now_cycles();
#endif
                            edhoc_rc = responder_prepare_message_4(
                                &ausf_ue->edhoc_responder, &ead_4, &message_4);
                            t1_ns = ogs_crypto_now_ns();
#if OGS_HAVE_CPU_CYCLES
                            t1_cycles = ogs_crypto_now_cycles();
                            ogs_log_edhoc_crypto("responder_prepare_message_4",
                                    t1_ns - t0_ns, t1_cycles - t0_cycles,
                                    ausf_ue->suci);
#else
                            ogs_log_edhoc_crypto("responder_prepare_message_4",
                                    t1_ns - t0_ns, 0, ausf_ue->suci);
#endif
                        }
                        if (edhoc_rc == 0)
                            edhoc_rc = edhoc_build_eap_request_hex(
                                    (uint8_t)(eap_id + 1),
                                    &message_4, &message_4_hex) ? 0 : -1;
                        if (edhoc_rc == 0)
                            edhoc_rc = edhoc_derive_kausf_from_exporter(
                                    ausf_ue) == OGS_OK ? 0 : -1;

                        if (edhoc_rc == 0) {
                            memset(&ConfirmationDataResponse, 0,
                                    sizeof(ConfirmationDataResponse));
                            ConfirmationDataResponse.auth_result =
                                OpenAPI_auth_result_AUTHENTICATION_ONGOING;
                            ConfirmationDataResponse.edhoc_eap_payload = message_4_hex;
                            ConfirmationDataResponse.supi = ausf_ue->supi;

                            memset(&sendmsg, 0, sizeof(sendmsg));
                            sendmsg.ConfirmationDataResponse =
                                &ConfirmationDataResponse;

                            response = ogs_sbi_build_response(
                                    &sendmsg, OGS_SBI_HTTP_STATUS_OK);
                            ogs_assert(response);
                            ogs_assert(true == ogs_sbi_server_send_response(
                                        stream, response));

                            ausf_ue->edhoc_waiting_message4_ack = true;
                            ogs_info("EDHOC_TIMING: leg2_m3_m4_kausf %lld us UE[%s]",
                                (long long)(ogs_time_now() - leg2_start),
                                ausf_ue->suci);
                            ogs_info("EDHOC: generated message_4 for UE[%s] [m3_len=%zu,m4_len=%zu]",
                                    ausf_ue->suci, (size_t)message_from_ue.len,
                                    (size_t)message_4.len);
                            ogs_free(message_4_hex);
                            return true;
                        }

                        ausf_ue->auth_result =
                            OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                        ogs_error("EDHOC: failed to generate message_4 for UE[%s] [rc=%d]",
                                ausf_ue->suci, edhoc_rc);
                        ogs_info("EDHOC: parsed message_3 for UE[%s] [len=%zu]",
                                ausf_ue->suci, (size_t)message_from_ue.len);
                    }
                }
            } else {
                /* Third EDHOC leg: UE acknowledges message_4 relay.
                 * An empty EAP-Response acknowledges protected success. */
                if (message_from_ue.len == 0) {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
                    ausf_ue->edhoc_in_progress = false;
                    ausf_ue->edhoc_waiting_message4_ack = false;
                    ogs_info("EDHOC: received empty message_4 ACK for UE[%s]",
                            ausf_ue->suci);
                } else {
                    ausf_ue->auth_result =
                        OpenAPI_auth_result_AUTHENTICATION_FAILURE;
                    ogs_error("EDHOC: expected empty message_4 ACK for UE[%s] [len=%zu]",
                            ausf_ue->suci, (size_t)message_from_ue.len);
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

    res_star_string = ConfirmationData->res_star;
    if (!res_star_string) {
        ogs_error("[%s] No ConfirmationData.resStar", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "No ConfirmationData.resStar", ausf_ue->suci, NULL));
        return false;
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
