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
struct private_eap_5g_t {

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

#define SETTYPEPLUSID(addr) \
	*(uint32_t *)addr = \
	htonl(((uint32_t)EAP_EXPANDED << 24) | \
	(VENDOR_ID))

#define MSGQUEUE_NAME "/testqueue"
#define MSGQUEUE_FLAG ( O_RDWR )

#define QERRFAIL(msg) do {                 \
			DBG1(DBG_IKE, msg); \
			return FAILED;     \
		      } while(0)

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

	*out = eap_payload_create_data(chunk_create((void*)req, len));

	return NEED_MORE;
}

METHOD(eap_method_t, process_peer, status_t,
        private_eap_5g_t *this, eap_payload_t *in, eap_payload_t **out)
{
        eap_5g_header_t *res;
        size_t len, data_len;

        chunk_t msg = chunk_skip(in->get_data(in), 12);
        char *str = calloc(msg.len + 1, sizeof(char));
        memcpy(str, msg.ptr, msg.len);

		data_len = msg.len;

        DBG1(DBG_IKE, "Get msg: %s\n", str);


		eap_code_t code = in->get_code(in);
		uint8_t MessageID;


		eap_5g_data_t AN, NASPDU;

		Message_ID = str[0];

		DBG1(DBG_IKE, "EAP-5G Code: %d\tMSG-ID: %d\n", code, MessageID);


		if(code == EAP_REQUEST && MessageID == 1) //deal with EAP-5G start
		{
			DBG1(DBG_IKE, "Recieve EAP-5G Start\n");

			// SEPC 24.502 Table 9.3.2.2.2.3
			// AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
			// Thus, IEI is not needed to be included.

			// return EAP-Res/ 5G-NAS/
			an_parameter_t* guami = calloc(2+ANP_Length_GUAMI, sizeof(uint8_t)); // excluding length and type, GUAMI using 7 byte
			guami->type = ANP_Type_GUAMI;
			guami->length = ANP_Length_GUAMI;

			guami->value[0] = 0x02;
			guami->value[1] = 0xf8;
			guami->value[2] = 0x39;
			guami->value[3] = 0xca;
			guami->value[4] = 0xfe;
			guami->value[5] = 0x0;

			an_parameter_t* ec = calloc(2+ANP_Length_EstablishmentCause, sizeof(uint8_t));
			ec->type = ANP_Type_EstablishmentCause;
			ec->length = ANP_Length_EstablishmentCause;

			ec->value[1] = EC_MO_Data;

			an_parameter_t* plmnid = calloc(2+ANP_Length_PLMNID, sizeof(uint8_t));
			plmnid->type = ANP_Type_EstablishmentCause;
			plmnid->length = ANP_Length_PLMNID;

			plmnid->value[0] = 3; //Length of PLMN ID contents below
			plmnid->value[1] = 0x02;
			plmnid->value[2] = 0xf8;
			plmnid->value[3] = 0x39;

			// SPEC 24.501-g30
			// The NSSAI is a type 4 information element with a minimum length of 4 octets
			// and a maximum length of 146 octets.

			int All_SNSSAI_Length = 2*(ANP_Length_SNSSAI_SST_SD + 1);  // Add 1 since length of SNSSAI occupy 1 byte.

			an_parameter_t* nssai = calloc(2 + ANP_Length_NSSAI_Header + All_SNSSAI_Length, sizeof(uint8_t));

			nssai->type = ANP_Type_EstablishmentCause;
			nssai->length = ANP_Length_PLMNID;

			// Length of NSSAI
			nssai->value[0] = All_SNSSAI_Length;

			// S-NSSAI 1
			nssai->value[1] = ANP_Length_SNSSAI_SST_SD ;  // Length of S-NSSAI
			nssai->value[2] = 1;  // SPEC 23.501 f30 : SST=1 means Slice suitable for the handling of 5G enhanced Mobile Broadband.
			nssai->value[3] = 0x01;
			nssai->value[4] = 0x02;
			nssai->value[5] = 0x03;

			// S-NSSAI 2
			nssai->value[6] = ANP_Length_SNSSAI_SST_SD ;  // Length of S-NSSAI
			nssai->value[7] = 1;
			nssai->value[8] = 0x11;
			nssai->value[9] = 0x22;
			nssai->value[10]= 0x33;

			const char supi[] = "imsi-2089300007487";


			//TODO: Encode NAS-PDU of EAPResponse
			nas_pdu_registration_request_data_t  nasData = {
				.ExtendedProtocolDiscriminator = Epd5GSMobilityManagementMessage,
				.SpareHalfOctetAndSecurityHeaderType = INIT_SECURITY_HEADER_TYPE_PLAIN_NAS(SecurityHeaderTypePlainNas),
				.RegistrationRequestMessageIdentity = MsgTypeRegistrationRequest,
				.NgksiAndRegistrationType5GS = INIT_NGKSI_AND_REGISTRATION_TYPE_5GS(0x1, 0x7, RegistrationType5GSInitialRegistration),
				.MobileIdentity5GS = (TLV_Buffer*)calloc(3+12 ,sizeof(uint8_t)), // 3 is length of IEI(1 byte) + Length(2 byte)
				.UESecurityCapability = (TLV_Buffer*)calloc(3+2 ,sizeof(uint8_t))
			};

			uint8_t MobileIdentity5GSValueTmp[] = {0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78};

			nasData.MobileIdentity5GS->len = 12;
			memcpy(nasData.MobileIdentity5GS->value, MobileIdentity5GSValueTmp, 12);

			// [TS 24.501] [9.11.3.54]
			// If the UE does not support any security algorithm for AS security over E-UTRA connected to 5GCN,
			// it shall not include octets 5 and 6. The UE shall not include octets 7 to 10.
			nasData.UESecurityCapability->iei = UESecurityCapabilityType;
			nasData.UESecurityCapability->len = 2;
			nasData.UESecurityCapability->value[0] = 0x80; //5G-EA0		1000|0000
			nasData.UESecurityCapability->value[1] = 0x40; //128-5G-IA2	0010|0000



			// registrationRequest := nasMessage.NewRegistrationRequest(0)
			// registrationRequest.SetExtendedProtocolDiscriminator(nasMessage.Epd5GSMobilityManagementMessage)
			// registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSecurityHeaderType(nas.SecurityHeaderTypePlainNas)
			// registrationRequest.SpareHalfOctetAndSecurityHeaderType.SetSpareHalfOctet(0x00)
			// registrationRequest.RegistrationRequestMessageIdentity.SetMessageType(nas.MsgTypeRegistrationRequest)
			// registrationRequest.NgksiAndRegistrationType5GS.SetTSC(nasMessage.TypeOfSecurityContextFlagNative)
			// registrationRequest.NgksiAndRegistrationType5GS.SetNasKeySetIdentifiler(0x7)
			// registrationRequest.NgksiAndRegistrationType5GS.SetFOR(1)
			// registrationRequest.NgksiAndRegistrationType5GS.SetRegistrationType5GS(registrationType)
			// registrationRequest.MobileIdentity5GS = mobileIdentity

			// registrationRequest.UESecurityCapability = ueSecurityCapability
			// registrationRequest.Capability5GMM = capability5GMM
			// registrationRequest.RequestedNSSAI = requestedNSSAI
			// registrationRequest.UplinkDataStatus = uplinkDataStatus

			// below is useless code
			len = sizeof(eap_5g_header_t) + strlen(pass2);
			this->identifier = in->get_identifier(in);
			res = alloca(len);
			res->length = htons(len);
			res->code = EAP_RESPONSE;
			res->identifier = this->identifier;
			SETTYPEPLUSID(&res->type);
			res->vendor_type = htonl(VENDOR_TYPE);
			memcpy(res->data, pass2, strlen(pass2));

			*out = eap_payload_create_data(chunk_create((void*)res, len));

		}
		else if(code == EAP_REQUEST ) // deal with EAP-5G NAS
		{
			DBG1(DBG_IKE, "Recieve EAP-5G Start\n");


			unsigned char *tmp = calloc(2 , sizeof(unsigned char));
			memcpy(tmp, str[2], 2);
			NASPDU.len = ntohs(*((uint16_t*)tmp));
			NASPDU.ptr = str[2];

			unsigned char *tmp = calloc(2 , sizeof(unsigned char));
			memcpy(tmp, str[2], 2);
			NASPDU.len = ntohs(*((uint16_t*)tmp));
			NASPDU.ptr = str[2];


			DBG1(DBG_IKE, "Receive EAP_REQUEST\nNASPDU: len = %d\n ", str);




		}
		else if(code == EAP_RESPONSE)




        if(strcmp(str, "more") == 0) {




                len = sizeof(eap_5g_header_t) + strlen(pass2);
                this->identifier = in->get_identifier(in);
                res = alloca(len);
                res->length = htons(len);
                res->code = EAP_RESPONSE;
                res->identifier = this->identifier;
                SETTYPEPLUSID(&res->type);
                res->vendor_type = htonl(VENDOR_TYPE);
                memcpy(res->data, pass2, strlen(pass2));

                *out = eap_payload_create_data(chunk_create((void*)res, len));
        }
        else {
                len = sizeof(eap_5g_header_t) + strlen(pass1);
                this->identifier = in->get_identifier(in);
                res = alloca(len);
                res->length = htons(len);
                res->code = EAP_RESPONSE;
                res->identifier = this->identifier;
                SETTYPEPLUSID(&res->type);
                res->vendor_type = htonl(VENDOR_TYPE);
                memcpy(res->data, pass1, strlen(pass1));

                *out = eap_payload_create_data(chunk_create((void*)res, len));
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

	if(strcmp(str, magic) == 0) {
		free(str);
		return SUCCESS;
	}
	else {
		eap_5g_header_t *req;
		size_t len;
		ssize_t read_bytes;
		struct mq_attr attr;
		char *more;              // recv from queue

		mqd_t mqd = mq_open(MSGQUEUE_NAME, MSGQUEUE_FLAG);
		if(mqd == (mqd_t) -1) {
			free(str);
			QERRFAIL("POSIX message queue not exist. Exit.");
		}
		if(mq_getattr(mqd, &attr) == -1) {
			free(str);
			QERRFAIL("mq_getattr failed. Exit.");
		}

		if(mq_send(mqd, str, msg.len, 10) == -1) {
			free(str);
			QERRFAIL("mq_send failed. Exit.");
		}

		more = calloc(attr.mq_msgsize + 1, sizeof(char));

		read_bytes = mq_receive(mqd, more, attr.mq_msgsize, NULL);
		if(read_bytes == -1) {
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

		*out = eap_payload_create_data(chunk_create((void*)req, len));

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
		.peer = peer->clone(peer),
		.server = server->clone(server),
	);

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
	do {
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
