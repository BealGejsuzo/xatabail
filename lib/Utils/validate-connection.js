"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.encodeSignedDeviceIdentity = exports.configureSuccessfulPairing = exports.generateRegistrationNode = exports.generateLoginNode = void 0;
const boom_1 = require("@hapi/boom");
const crypto_1 = require("crypto");
const WAProto_1 = require("../../WAProto");
const Defaults_1 = require("../Defaults");
const WABinary_1 = require("../WABinary");
const crypto_2 = require("./crypto");
const generics_1 = require("./generics");
const signal_1 = require("./signal");

const getUserAgent = (config) => {
    return {
        appVersion: {
            primary: config.version[0],
            secondary: config.version[1],
            tertiary: config.version[2],
        },
        platform: WAProto_1.proto.ClientPayload.UserAgent.Platform.WEB,
        releaseChannel: WAProto_1.proto.ClientPayload.UserAgent.ReleaseChannel.RELEASE,
        osVersion: 'macOS 13.0',
        device: 'Desktop',
        osBuildNumber: '22A380',
        localeLanguageIso6391: 'en',
        mnc: '000',
        mcc: '000',
        localeCountryIso31661Alpha2: config.countryCode || 'US'
    };
};

const PLATFORM_MAP = {
    'Mac OS': WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN,
    'macOS': WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN,
    'Windows': WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.WIN32,
    'Chrome': WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER
};

const getWebInfo = (config) => {
    let webSubPlatform = WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.WEB_BROWSER;
    
    // Deteksi macOS dengan lebih baik
    const browserName = config.browser[0];
    const browserType = config.browser[1];
    
    if (config.syncFullHistory) {
        if (browserName === 'Mac OS' || browserName === 'macOS') {
            webSubPlatform = WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.DARWIN;
        } else if (browserName === 'Windows') {
            webSubPlatform = WAProto_1.proto.ClientPayload.WebInfo.WebSubPlatform.WIN32;
        }
    }
    
    return { webSubPlatform };
};

const getClientPayload = (config) => {
    const payload = {
        connectType: WAProto_1.proto.ClientPayload.ConnectType.WIFI_UNKNOWN,
        connectReason: WAProto_1.proto.ClientPayload.ConnectReason.USER_ACTIVATED,
        userAgent: getUserAgent(config),
    };
    
    payload.webInfo = getWebInfo(config);
    
    return payload;
};

const generateLoginNode = (userJid, config) => {
    const { user, device } = (0, WABinary_1.jidDecode)(userJid);
    const payload = {
        ...getClientPayload(config),
        passive: true,
        pull: true,
        username: typeof user === 'string' ? parseInt(user, 10) : user,
        device: device || 0,
        lidDbMigrated: false
    };
    return WAProto_1.proto.ClientPayload.fromObject(payload);
};
exports.generateLoginNode = generateLoginNode;

const getPlatformType = (platform) => {
    const platformUpper = platform.toUpperCase();
    
    // Mapping khusus untuk macOS
    if (platformUpper.includes('MAC') || platformUpper.includes('DARWIN')) {
        return WAProto_1.proto.DeviceProps.PlatformType.DARWIN;
    }
    
    // Default ke CHROME jika tidak dikenali
    return WAProto_1.proto.DeviceProps.PlatformType[platformUpper] || 
           WAProto_1.proto.DeviceProps.PlatformType.CHROME;
};

const generateRegistrationNode = ({ registrationId, signedPreKey, signedIdentityKey }, config) => {
    const appVersionBuf = (0, crypto_1.createHash)('md5')
        .update(config.version.join('.'))
        .digest();

    // Versi companion yang sesuai untuk macOS
    const companion = {
        os: config.browser[0] === 'Mac OS' ? 'macOS' : config.browser[0],
        platformType: getPlatformType(config.browser[1]),
        requireFullSync: config.syncFullHistory || true, // Default true untuk pairing
        historySyncConfig: {
            storageQuotaMb: 10240,
            inlineInitialPayloadInE2EeMsg: true,
            recentSyncDaysLimit: 90, // Tambahkan limit days
            supportCallLogHistory: true,
            supportBotUserAgentChatHistory: true,
            supportCagReactionsAndPolls: true,
            supportBizHostedMsg: true,
            supportRecentSyncChunkMessageCountTuning: true,
            supportHostedGroupMsg: true,
            supportFbidBotChatHistory: true,
            supportAddOnHistorySyncMigration: true,
            supportMessageAssociation: true,
            supportGroupHistory: true,
            onDemandReady: true,
            supportGuestChat: true
        },
        version: {
            primary: config.version[0],
            secondary: config.version[1],
            tertiary: config.version[2]
        }
    };

    const companionProto = WAProto_1.proto.DeviceProps.encode(companion).finish();

    const registerPayload = {
        ...getClientPayload(config),
        passive: false,
        pull: false,
        devicePairingData: {
            buildHash: appVersionBuf,
            deviceProps: companionProto,
            eRegid: (0, generics_1.encodeBigEndian)(registrationId),
            eKeytype: Defaults_1.KEY_BUNDLE_TYPE,
            eIdent: signedIdentityKey.public,
            eSkeyId: (0, generics_1.encodeBigEndian)(signedPreKey.keyId, 3),
            eSkeyVal: signedPreKey.keyPair.public,
            eSkeySig: signedPreKey.signature,
        },
    };
    
    return WAProto_1.proto.ClientPayload.fromObject(registerPayload);
};
exports.generateRegistrationNode = generateRegistrationNode;

const configureSuccessfulPairing = (stanza, { advSecretKey, signedIdentityKey, signalIdentities }) => {
    const msgId = stanza.attrs.id;
    const pairSuccessNode = (0, WABinary_1.getBinaryNodeChild)(stanza, 'pair-success');
    const deviceIdentityNode = (0, WABinary_1.getBinaryNodeChild)(pairSuccessNode, 'device-identity');
    const platformNode = (0, WABinary_1.getBinaryNodeChild)(pairSuccessNode, 'platform');
    const deviceNode = (0, WABinary_1.getBinaryNodeChild)(pairSuccessNode, 'device');
    const businessNode = (0, WABinary_1.getBinaryNodeChild)(pairSuccessNode, 'biz');

    if (!deviceIdentityNode || !deviceNode) {
        throw new boom_1.Boom('Missing device-identity or device in pair success node', { data: stanza });
    }

    const bizName = businessNode?.attrs?.name;
    const jid = deviceNode.attrs.jid;
    const lid = deviceNode.attrs.lid;

    // Decode dan verifikasi identity
    let decodedIdentity;
    try {
        decodedIdentity = WAProto_1.proto.ADVSignedDeviceIdentityHMAC.decode(deviceIdentityNode.content);
    } catch (error) {
        throw new boom_1.Boom('Failed to decode device identity', { data: error });
    }

    const { details, hmac, accountType } = decodedIdentity;

    let hmacPrefix = Buffer.from([]);
    if (accountType === WAProto_1.proto.ADVEncryptionType.HOSTED) {
        hmacPrefix = Buffer.from([0x06, 0x05]);
    }

    const advSign = (0, crypto_2.hmacSign)(
        Buffer.concat([hmacPrefix, details]), 
        Buffer.from(advSecretKey, 'base64')
    );
    
    if (!hmac || Buffer.compare(hmac, advSign) !== 0) {
        throw new boom_1.Boom('Invalid account signature - HMAC mismatch');
    }

    let account;
    try {
        account = WAProto_1.proto.ADVSignedDeviceIdentity.decode(details);
    } catch (error) {
        throw new boom_1.Boom('Failed to decode account details', { data: error });
    }

    const { accountSignatureKey, accountSignature, details: deviceDetails } = account;

    let deviceIdentity;
    try {
        deviceIdentity = WAProto_1.proto.ADVDeviceIdentity.decode(deviceDetails);
    } catch (error) {
        throw new boom_1.Boom('Failed to decode device details', { data: error });
    }

    // Verifikasi signature dengan prefix yang tepat
    const accountSignaturePrefix = deviceIdentity.deviceType === WAProto_1.proto.ADVEncryptionType.HOSTED 
        ? Buffer.from([0x06, 0x05])
        : Buffer.from([0x06, 0x00]);
    
    const accountMsg = Buffer.concat([accountSignaturePrefix, deviceDetails, signedIdentityKey.public]);
    
    if (!accountSignatureKey || !accountSignature) {
        throw new boom_1.Boom('Missing account signature or key');
    }

    const isValid = (0, crypto_2.Curve.verify)(accountSignatureKey, accountMsg, accountSignature);
    if (!isValid) {
        throw new boom_1.Boom('Failed to verify account signature - invalid curve signature');
    }

    // Buat device signature
    const deviceMsg = Buffer.concat([
        Buffer.from([0x06, 0x01]),
        deviceDetails,
        signedIdentityKey.public,
        accountSignatureKey
    ]);
    
    account.deviceSignature = (0, crypto_2.Curve.sign)(signedIdentityKey.private, deviceMsg);

    // Buat signal identity
    let identity;
    try {
        identity = (0, signal_1.createSignalIdentity)(jid, accountSignatureKey);
    } catch (error) {
        throw new boom_1.Boom('Failed to create signal identity', { data: error });
    }

    const accountEnc = (0, exports.encodeSignedDeviceIdentity)(account, false);

    const reply = {
        tag: 'iq',
        attrs: {
            to: WABinary_1.S_WHATSAPP_NET,
            type: 'result',
            id: msgId,
        },
        content: [
            {
                tag: 'pair-device-sign',
                attrs: {},
                content: [
                    {
                        tag: 'device-identity',
                        attrs: { 'key-index': deviceIdentity.keyIndex?.toString() || '0' },
                        content: accountEnc
                    }
                ]
            }
        ]
    };

    const authUpdate = {
        account,
        me: { 
            id: jid, 
            name: bizName, 
            lid: lid || jid 
        },
        signalIdentities: [
            ...(signalIdentities || []),
            identity
        ],
        platform: platformNode?.attrs?.name || 'macOS'
    };

    return {
        creds: authUpdate,
        reply
    };
};
exports.configureSuccessfulPairing = configureSuccessfulPairing;

const encodeSignedDeviceIdentity = (account, includeSignatureKey) => {
    account = { ...account };
    
    // Hapus accountSignatureKey jika tidak diminta
    if (!includeSignatureKey) {
        account.accountSignatureKey = null;
    }
    
    // Pastikan semua field yang diperlukan ada
    if (!account.details || !account.accountSignature) {
        throw new boom_1.Boom('Invalid account data for encoding');
    }
    
    return WAProto_1.proto.ADVSignedDeviceIdentity
        .encode(account)
        .finish();
};
exports.encodeSignedDeviceIdentity = encodeSignedDeviceIdentity;
