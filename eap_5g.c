#include "ie_constants.h"
#include "eap_5g.h"

#include <daemon.h>
#include <library.h>
#include <mqueue.h>

#define NAS_MSG "I am a test NAS packet"

typedef struct private_eap_5g_t private_eap_5g_t;

/**
 * Private data of an eap_5g_t object.
 */
struct private_eap_5g_t
{

	/**
	 * Public authenticator_t interface.
	 */
	eap_5g_t public;

	/**
	 * ID of the server
	 */
	identification_t *server;

	/**
	 * ID of the peer
	 */
	identification_t *peer;

	/**
	 * EAP message identififier
	 */
	uint8_t identifier;
};

METHOD(eap_method_t, initiate_peer, status_t,
	   private_eap_5g_t *this, eap_payload_t **out)
{
	/* peer never initiates */
	return FAILED;
}

#define SETTYPEPLUSID(addr)                    \
	*(uint32_t *)addr =                        \
		htonl(((uint32_t)EAP_EXPANDED << 24) | \
			  (VENDOR_ID))

#define MSGQUEUE_NAME "/testqueue"
#define MSGQUEUE_FLAG (O_RDWR)

#define QERRFAIL(msg)       \
	do                      \
	{                       \
		DBG1(DBG_IKE, msg); \
		return FAILED;      \
	} while (0)

METHOD(eap_method_t, initiate_server, status_t,
	   private_eap_5g_t *this, eap_payload_t **out)
{
	eap_5g_header_t *req;
	size_t len;

	len = sizeof(eap_5g_header_t) + strlen(NAS_MSG);
	req = alloca(len);
	req->length = htons(len);
	req->code = EAP_REQUEST;
	req->identifier = this->identifier;
	SETTYPEPLUSID(&req->type);
	req->vendor_type = htonl(VENDOR_TYPE);
	memcpy(req->data, NAS_MSG, strlen(NAS_MSG));

	*out = eap_payload_create_data(chunk_create((void *)req, len));

	return NEED_MORE;
}

size_t set_AN_parameter(an_parameter_t *an_ptr, enum an_parameter_type type, size_t value_length, uint8_t *value_part)
{
	size_t an_len = sizeof(an_parameter_t) + value_length;
	an_ptr = calloc(an_len, sizeof(uint8_t)); // excluding length and type, GUAMI using 7 byte

	an_ptr->type = type;
	an_ptr->length = value_length;
	memcpy(an_ptr->value, value_part, value_length);

	return an_len;
}

METHOD(eap_method_t, process_peer, status_t,
	   private_eap_5g_t *this, eap_payload_t *in, eap_payload_t **out)
{
	eap_5g_header_t *res;
	size_t len, data_len;
	int offset = 0;

	chunk_t msg = chunk_skip(in->get_data(in), 12);
	char *str = calloc(msg.len + 1, sizeof(char));
	memcpy(str, msg.ptr, msg.len);

	data_len = msg.len;

	DBG1(DBG_IKE, "Get msg: %s\n", str);

	eap_code_t code = in->get_code(in);
	uint8_t MessageID;

	MessageID = str[0];

	DBG1(DBG_IKE, "EAP-5G Code: %d\tMSG-ID: %d\n", code, MessageID);

	// [TS 23502] 4.12.2.2-1 Registration via untrusted non-3GPP access
	// Define call flow of registration between UE and AMF

	// [TS 24502] 9.3.2.2.2 EAP-Response/5G-NAS message
	// Define EAP-Response/5G-NAS message and AN-Parameters Format.

	// [TS 24501] 8.2.6.1.1  REGISTRATION REQUEST message content
	// For dealing with EAP-5G start, return EAP-5G response including "AN-Parameters and NASPDU of Registration Request"

	if (code == EAP_REQUEST && MessageID == 1)
	{
		DBG1(DBG_IKE, "Recieve EAP-5G Start\n");

		// [TS 24.502] 9.3.2.2.2.3
		// AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
		// Thus, IEI of AN-parameter is not needed to be included.

		// return EAP-Res/ 5G-NAS/
		an_parameter_t *guami, *ec, *plmnid, *nssai;

		uint8_t guami_value_part[] = {0x02, 0xf8, 0x39, 0xca, 0xfe, 0x0};
		size_t GUAMI_Len = set_AN_parameter(&guami, ANP_Type_GUAMI, ANP_Value_Length_GUAMI, guami_value_part);

		uint8_t ec_value_part[] = {EC_MO_Data};
		size_t EstablishmentCauseLen = set_AN_parameter(&ec, ANP_Type_EstablishmentCause, ANP_Value_Length_EstablishmentCause, ec_value_part);

		uint8_t plmnid_value_part[] = {0x03, 0x02, 0xf8, 0x39};
		size_t PLMNID_Len = set_AN_parameter(&plmnid, ANP_Type_SelectedPLMNID, ANP_Value_Length_PLMNID, plmnid_value_part);

		// [TS 24.501-g30]
		// The NSSAI is a type 4 information element with a minimum length of 4 octets
		// and a maximum length of 146 octets.

		size_t All_SNSSAI_Len = 1 + 2 * (ANP_Value_Length_SNSSAI_SST_SD + 1); // Add 1 since length of SNSSAI occupy 1 byte.
		uint8_t nssai_value_part[] = {All_SNSSAI_Len, ANP_Value_Length_SNSSAI_SST_SD, 0x01, 0x01, 0x02, 0x03, ANP_Value_Length_SNSSAI_SST_SD, 0x01, 0x11, 0x22, 0x33};
		size_t NSSAI_Len = set_AN_parameter(&nssai, ANP_Type_RequestedNSSAI, All_SNSSAI_Len, nssai_value_part);

		size_t AnMsgLen = GUAMI_Len + EstablishmentCauseLen + PLMNID_Len + NSSAI_Len;
		eap_5g_data_t *AN = calloc(sizeof(eap_5g_data_t) + AnMsgLen, sizeof(uint8_t));
		// AN->tag = eap_5g_data_type_AN;
		AN->len = AnMsgLen;

		offset = 0;
		memcpy(AN->value + offset, guami, GUAMI_Len);
		offset += GUAMI_Len;

		memcpy(AN->value + offset, ec, EstablishmentCauseLen);
		offset += EstablishmentCauseLen;

		memcpy(AN->value + offset, plmnid, PLMNID_Len);
		offset += PLMNID_Len;

		memcpy(AN->value + offset, nssai, NSSAI_Len);
		offset += NSSAI_Len;


		// Encode NAS-PDU of EAPResponse
		nas_pdu_registration_request_data_t nasData = {
			.ExtendedProtocolDiscriminator = Epd5GSMobilityManagementMessage,
			.SpareHalfOctetAndSecurityHeaderType = INIT_SECURITY_HEADER_TYPE_PLAIN_NAS(SecurityHeaderTypePlainNas),
			.RegistrationRequestMessageIdentity = MsgTypeRegistrationRequest,
			.NgksiAndRegistrationType5GS = INIT_NGKSI_AND_REGISTRATION_TYPE_5GS(0x1, 0x7, RegistrationType5GSInitialRegistration),
			.MobileIdentity5GS = (LV_Buffer *)calloc(2 + 12, sizeof(uint8_t)), // 3 is length of IEI(1 byte) + Length(2 byte)
			.UESecurityCapability = (TLV_Buffer *)calloc(3 + 2, sizeof(uint8_t))};

		uint8_t MobileIdentity5GSValueTmp[] = {0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78};

		nasData.MobileIdentity5GS->len = htons(12);
		memcpy(nasData.MobileIdentity5GS->value, MobileIdentity5GSValueTmp, 12);

		// [TS 24.501] [9.11.3.54]
		// If the UE does not support any security algorithm for AS security over E-UTRA connected to 5GCN,
		// it shall not include octets 5 and 6. The UE shall not include octets 7 to 10.
		nasData.UESecurityCapability->iei = UESecurityCapabilityType;
		nasData.UESecurityCapability->len = htons(2);
		nasData.UESecurityCapability->value[0] = 0x80; //5G-EA0		1000|0000
		nasData.UESecurityCapability->value[1] = 0x20; //128-5G-IA2	0010|0000

		size_t ExtendedProtocolDiscriminatorLen = sizeof(nasData.ExtendedProtocolDiscriminator);
		size_t SpareHalfOctetAndSecurityHeaderTypeLen = sizeof(nasData.SpareHalfOctetAndSecurityHeaderType);
		size_t RegistrationRequestMessageIdentityLen = sizeof(nasData.RegistrationRequestMessageIdentity);
		size_t NgksiAndRegistrationType5GSLen = sizeof(nasData.NgksiAndRegistrationType5GS);
		size_t MobileIdentity5GSLen = sizeof(*nasData.MobileIdentity5GS) + ntohs(nasData.MobileIdentity5GS->len);
		size_t UESecurityCapabilityLen = sizeof(*nasData.UESecurityCapability) + ntohs(nasData.UESecurityCapability->len);

		size_t NASPDU_MsgLen = ExtendedProtocolDiscriminatorLen + SpareHalfOctetAndSecurityHeaderTypeLen + RegistrationRequestMessageIdentityLen + NgksiAndRegistrationType5GSLen + MobileIdentity5GSLen + UESecurityCapabilityLen;

		eap_5g_data_t *NASPDU = calloc(sizeof(eap_5g_data_t) + NASPDU_MsgLen, sizeof(uint8_t));
		//NASPDU->tag = eap_5g_data_type_NASPDU;
		NASPDU->len = htons(NASPDU_MsgLen);

		offset = 0;
		NASPDU->value[offset++] = nasData.ExtendedProtocolDiscriminator;	   //index = 0
		NASPDU->value[offset++] = nasData.SpareHalfOctetAndSecurityHeaderType; //index = 1
		NASPDU->value[offset++] = nasData.RegistrationRequestMessageIdentity;  //index = 2
		NASPDU->value[offset++] = nasData.NgksiAndRegistrationType5GS;		   //index = 3

		memcpy(NASPDU->value + offset, nasData.MobileIdentity5GS, MobileIdentity5GSLen);
		offset += MobileIdentity5GSLen;

		memcpy(NASPDU->value + offset, nasData.UESecurityCapability, UESecurityCapabilityLen);
		offset += UESecurityCapabilityLen;

		// below is useless code
		size_t dataLen = sizeof(eap_5g_data_t) + AnMsgLen + sizeof(eap_5g_data_t) + NASPDU_MsgLen;
		this->identifier = in->get_identifier(in);
		res = alloca(sizeof(eap_5g_header_t) + dataLen);
		res->length = htons(dataLen);
		res->code = EAP_RESPONSE;
		res->identifier = this->identifier;
		SETTYPEPLUSID(&res->type);
		res->vendor_type = htonl(VENDOR_TYPE);
		res->message_id = 0x2;

		offset = 0;

		memcpy(res->data + offset, AN, sizeof(eap_5g_data_t) + AnMsgLen);
		offset += sizeof(eap_5g_data_t) + AnMsgLen;

		memcpy(res->data + offset, NASPDU, sizeof(eap_5g_data_t) + NASPDU_MsgLen);
		offset += sizeof(eap_5g_data_t) + NASPDU_MsgLen;

		*out = eap_payload_create_data(chunk_create((void *)res, sizeof(eap_5g_header_t) + dataLen));
	}
	else if (code == EAP_REQUEST) // deal with EAP-5G NAS
	{
		DBG1(DBG_IKE, "Recieve EAP-5G Start\n");

		unsigned char *tmp = calloc(2, sizeof(unsigned char));
		memcpy(tmp, str[2], 2);
		NASPDU.len = ntohs(*((uint16_t *)tmp));
		NASPDU.ptr = str[2];

		unsigned char *tmp = calloc(2, sizeof(unsigned char));
		memcpy(tmp, str[2], 2);
		NASPDU.len = ntohs(*((uint16_t *)tmp));
		NASPDU.ptr = str[2];

		DBG1(DBG_IKE, "Receive EAP_REQUEST\nNASPDU: len = %d\n ", str);
	}
	else if (code == EAP_RESPONSE)

		if (strcmp(str, "more") == 0)
		{

			len = sizeof(eap_5g_header_t) + strlen(pass2);
			this->identifier = in->get_identifier(in);
			res = alloca(len);
			res->length = htons(len);
			res->code = EAP_RESPONSE;
			res->identifier = this->identifier;
			SETTYPEPLUSID(&res->type);
			res->vendor_type = htonl(VENDOR_TYPE);
			memcpy(res->data, pass2, strlen(pass2));

			*out = eap_payload_create_data(chunk_create((void *)res, len));
		}
		else
		{
			len = sizeof(eap_5g_header_t) + strlen(pass1);
			this->identifier = in->get_identifier(in);
			res = alloca(len);
			res->length = htons(len);
			res->code = EAP_RESPONSE;
			res->identifier = this->identifier;
			SETTYPEPLUSID(&res->type);
			res->vendor_type = htonl(VENDOR_TYPE);
			memcpy(res->data, pass1, strlen(pass1));

			*out = eap_payload_create_data(chunk_create((void *)res, len));
		}

	free(str);

	return NEED_MORE;
}

METHOD(eap_method_t, process_server, status_t,
	   private_eap_5g_t *this, eap_payload_t *in, eap_payload_t **out)
{
	const char magic[] = "10km";

	chunk_t msg = chunk_skip(in->get_data(in), 12);
	char *str = calloc(msg.len + 1, sizeof(char));
	memcpy(str, msg.ptr, msg.len);
	DBG1(DBG_IKE, "Get msg: %s\n", str);

	if (strcmp(str, magic) == 0)
	{
		free(str);
		return SUCCESS;
	}
	else
	{
		eap_5g_header_t *req;
		size_t len;
		ssize_t read_bytes;
		struct mq_attr attr;
		char *more; // recv from queue

		mqd_t mqd = mq_open(MSGQUEUE_NAME, MSGQUEUE_FLAG);
		if (mqd == (mqd_t)-1)
		{
			free(str);
			QERRFAIL("POSIX message queue not exist. Exit.");
		}
		if (mq_getattr(mqd, &attr) == -1)
		{
			free(str);
			QERRFAIL("mq_getattr failed. Exit.");
		}

		if (mq_send(mqd, str, msg.len, 10) == -1)
		{
			free(str);
			QERRFAIL("mq_send failed. Exit.");
		}

		more = calloc(attr.mq_msgsize + 1, sizeof(char));

		read_bytes = mq_receive(mqd, more, attr.mq_msgsize, NULL);
		if (read_bytes == -1)
		{
			free(more);
			free(str);
			QERRFAIL("mq_receive failed. Exit.");
		}

		mq_close(mqd);

		more[read_bytes] = '\0';

		len = sizeof(eap_5g_header_t) + strlen(more);
		req = alloca(len);
		req->length = htons(len);
		req->code = EAP_REQUEST;
		req->identifier = this->identifier;
		SETTYPEPLUSID(&req->type);
		req->vendor_type = htonl(VENDOR_TYPE);
		memcpy(req->data, more, strlen(more));

		*out = eap_payload_create_data(chunk_create((void *)req, len));

		free(more);
		free(str);
		return NEED_MORE;
	}
}

METHOD(eap_method_t, get_type, eap_type_t,
	   private_eap_5g_t *this, uint32_t *vendor)
{
	*vendor = VENDOR_ID;
	return VENDOR_TYPE;
}

METHOD(eap_method_t, get_msk, status_t,
	   private_eap_5g_t *this, chunk_t *msk)
{
	return FAILED;
}

METHOD(eap_method_t, get_identifier, uint8_t,
	   private_eap_5g_t *this)
{
	return this->identifier;
}

METHOD(eap_method_t, set_identifier, void,
	   private_eap_5g_t *this, uint8_t identifier)
{
	this->identifier = identifier;
}

METHOD(eap_method_t, is_mutual, bool,
	   private_eap_5g_t *this)
{
	return FALSE;
}

METHOD(eap_method_t, destroy, void,
	   private_eap_5g_t *this)
{
	this->peer->destroy(this->peer);
	this->server->destroy(this->server);
	free(this);
}

/**
 * Generic constructor
 */
static private_eap_5g_t *eap_5g_create_generic(identification_t *server,
											   identification_t *peer)
{
	private_eap_5g_t *this;

	INIT(this,
		 .public = {
			 .eap_method_interface = {
				 .get_type = _get_type,
				 .is_mutual = _is_mutual,
				 .get_msk = _get_msk,
				 .get_identifier = _get_identifier,
				 .set_identifier = _set_identifier,
				 .destroy = _destroy,
			 },
		 },
		 .peer = peer->clone(peer), .server = server->clone(server), );

	return this;
}

/*
 * see header
 */
eap_5g_t *eap_5g_create_server(identification_t *server, identification_t *peer)
{
	private_eap_5g_t *this = eap_5g_create_generic(server, peer);

	this->public.eap_method_interface.initiate = _initiate_server;
	this->public.eap_method_interface.process = _process_server;

	/* generate a non-zero identifier */
	do
	{
		this->identifier = random();
	} while (!this->identifier);

	return &this->public;
}

/*
 * see header
 */
eap_5g_t *eap_5g_create_peer(identification_t *server, identification_t *peer)
{
	private_eap_5g_t *this = eap_5g_create_generic(server, peer);

	this->public.eap_method_interface.initiate = _initiate_peer;
	this->public.eap_method_interface.process = _process_peer;

	return &this->public;
}
