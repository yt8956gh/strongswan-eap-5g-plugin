#ifndef IE_CONSTANTS
#define IE_CONSTANTS

typedef struct
{
	uint8_t  iei;
	uint16_t len;
	uint8_t  value[];

}__attribute__((__packed__)) TLV_Buffer;

typedef struct
{
	uint8_t  iei;
	uint16_t len;
	uint8_t  octet;

}__attribute__((__packed__)) TLV_Octet;

typedef struct
{
	uint8_t  iei;
	uint8_t  value[6];

}__attribute__((__packed__)) TAI;

typedef struct
{
	uint8_t  iei;
	uint16_t len;
	uint8_t  value[11];

}__attribute__((__packed__)) GUTI;


typedef struct{
	char *Supi;
	uint64_t iRanUeNgapId;
	uint64_t AmfUeNgapId;
	// security.Count ULCount;
	// security.Count DLCount;
	uint8_t  CipheringAlg;
	uint8_t  IntegrityAlg;
	uint8_t  KnasEnc[16];
	uint8_t  KnasInt[16];
	uint8_t *Kamf;
	//models.AuthenticationSubscription AuthenticationSubs
}__attribute__((__packed__)) ran_ue_context_t;


typedef struct{

	uint8_t ExtendedProtocolDiscriminator;
	uint8_t SpareHalfOctetAndSecurityHeaderType;
	uint8_t RegistrationRequestMessageIdentity;
	uint8_t NgksiAndRegistrationType5GS;
	uint8_t NoncurrentNativeNASKeySetIdentifier;

	uint8_t MICOIndication;
	uint8_t NetworkSlicingIndication;

	TAI *LastVisitedRegisteredTAI;
	GUTI *AdditionalGUTI;

	TLV_Octet *UEStatus;
	TLV_Octet *UesUsageSetting;
	TLV_Octet *RequestedDRXParameters;
	TLV_Octet *UpdateType5GS;

	TLV_Buffer *MobileIdentity5GS;
	TLV_Buffer *Capability5GMM; //len=13
	TLV_Buffer *UESecurityCapability;
	TLV_Buffer *RequestedNSSAI;
	TLV_Buffer *S1UENetworkCapability;

	TLV_Buffer *UplinkDataStatus;
	TLV_Buffer *PDUSessionStatus;
	TLV_Buffer *AllowedPDUSessionStatus;

	TLV_Buffer *EPSNASMessageContainer;
	TLV_Buffer *LADNIndication;
	TLV_Buffer *PayloadContainer;
	TLV_Buffer *NASMessageContainer;

}__attribute__((__packed__)) nas_pdu_registration_request_data_t;


typedef struct {

	uint16_t len;
	int tag;
	uint8_t value[];
}__attribute__((__packed__)) eap_5g_data_t;

typedef struct{
	uint8_t type;
	uint8_t length;
	uint8_t value[];

}__attribute__((__packed__)) an_parameter_t;

enum eap_5g_data_type{
	eap_5g_data_type_NASPDU,
	eap_5g_data_type_AN,
	eap_5g_data_type_MAX
};


enum an_parameter_type{
	ANP_Type_GUAMI           = 1,
	ANP_Type_SelectedPLMNID     ,
	ANP_Type_RequestedNSSAI     ,
	ANP_Type_EstablishmentCause ,
	ANP_Type_Max
};


// octect of IEI is not contained
enum an_parameter_fixed_length{
	ANP_Length_GUAMI              = 6,
	ANP_Length_EstablishmentCause = 1,
	ANP_Length_PLMNID             = 4,
	ANP_Length_NSSAI_Header       = 1,
	ANP_Length_SNSSAI_SST_SD      = 4
};

enum n3_establishment_cause{
	EC_Emergency          = 0,
	EC_HighPriorityAccess = 1,
	EC_MO_Signalling      = 3,
	EC_MO_Data            = 4,
	EC_MPS_PriorityAccess = 8,
	EC_MCS_PriorityAccess = 9
};



enum nsa_pdu_registration_request_type {
	NoncurrentNativeNASKeySetIdentifierType  = 0x0C,
	Capability5GMMType                       = 0x10,
	UESecurityCapabilityType                 = 0x2E,
	RequestedNSSAIType                       = 0x2F,
	LastVisitedRegisteredTAIType             = 0x52,
	S1UENetworkCapabilityType                = 0x17,
	UplinkDataStatusType                     = 0x40,
	PDUSessionStatusType                     = 0x50,
	MICOIndicationType                       = 0x0B,
	UEStatusType                             = 0x2B,
	AdditionalGUTIType                       = 0x77,
	AllowedPDUSessionStatusType              = 0x25,
	UesUsageSettingType                      = 0x18,
	RequestedDRXParametersType               = 0x51,
	EPSNASMessageContainerType               = 0x70,
	LADNIndicationType                       = 0x74,
	PayloadContainerType                     = 0x7B,
	NetworkSlicingIndicationType             = 0x09,
	UpdateType5GSType                        = 0x53,
	NASMessageContainerType                  = 0x71
};

enum extended_protocol_discriminator{
	Epd5GSSessionManagementMessage  = 0x2E,
	Epd5GSMobilityManagementMessage = 0x7E
};

enum set_security_header_type{
	SecurityHeaderTypePlainNas                                                 = 0x00,
	SecurityHeaderTypeIntegrityProtected                                       = 0x01,
	SecurityHeaderTypeIntegrityProtectedAndCiphered                            = 0x02,
	SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext            = 0x03,
	SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext = 0x04,
};

enum msg_type{
	MsgTypeRegistrationRequest                               = 65,
	MsgTypeRegistrationAccept                                = 66,
	MsgTypeRegistrationComplete                              = 67,
	MsgTypeRegistrationReject                                = 68,
	MsgTypeDeregistrationRequestUEOriginatingDeregistration  = 69,
	MsgTypeDeregistrationAcceptUEOriginatingDeregistration   = 70,
	MsgTypeDeregistrationRequestUETerminatedDeregistration   = 71,
	MsgTypeDeregistrationAcceptUETerminatedDeregistration    = 72,
	MsgTypeServiceRequest                                    = 76,
	MsgTypeServiceReject                                     = 77,
	MsgTypeServiceAccept                                     = 78,
	MsgTypeConfigurationUpdateCommand                        = 84,
	MsgTypeConfigurationUpdateComplete                       = 85,
	MsgTypeAuthenticationRequest                             = 86,
	MsgTypeAuthenticationResponse                            = 87,
	MsgTypeAuthenticationReject                              = 88,
	MsgTypeAuthenticationFailure                             = 89,
	MsgTypeAuthenticationResult                              = 90,
	MsgTypeIdentityRequest                                   = 91,
	MsgTypeIdentityResponse                                  = 92,
	MsgTypeSecurityModeCommand                               = 93,
	MsgTypeSecurityModeComplete                              = 94,
	MsgTypeSecurityModeReject                                = 95,
	MsgTypeStatus5GMM                                        = 100,
	MsgTypeNotification                                      = 101,
	MsgTypeNotificationResponse                              = 102,
	MsgTypeULNASTransport                                    = 103,
	MsgTypeDLNASTransport                                    = 104
};

enum type_of_security_context_flag{
	TypeOfSecurityContextFlagNative = 0x00,
	TypeOfSecurityContextFlagMapped = 0x01
};

enum registration_type_5GS{
    RegistrationType5GSInitialRegistration          = 0x01,
	RegistrationType5GSMobilityRegistrationUpdating = 0x02,
	RegistrationType5GSPeriodicRegistrationUpdating = 0x03,
	RegistrationType5GSEmergencyRegistration        = 0x04,
	RegistrationType5GSReserved                     = 0x07
};

#endif
