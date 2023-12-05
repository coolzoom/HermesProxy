using Framework.Cryptography;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace HermesProxy.World.Client
{
    public interface LegacyWorldCrypt
    {
        public void Initialize(byte[] sessionKey);
        public void Decrypt(byte[] data, int len);
        public void Encrypt(byte[] data, int len);

    }
    public class VanillaWorldCrypt : LegacyWorldCrypt
    {
        public const uint CRYPTED_SEND_LEN = 6;
        public const uint CRYPTED_RECV_LEN = 4;

        public void Initialize(byte[] sessionKey)
        {
            SetKey(sessionKey);
            m_send_i = m_send_j = m_recv_i = m_recv_j = 0;
            m_isInitialized = true;
        }

        public void Decrypt(byte[] data, int len)
        {
            if (len < CRYPTED_RECV_LEN)
                return;

            for (byte t = 0; t < CRYPTED_RECV_LEN; t++)
            {
                m_recv_i %= (byte)m_key.Count();
                byte x = (byte)((data[t] - m_recv_j) ^ m_key[m_recv_i]);
                ++m_recv_i;
                m_recv_j = data[t];
                data[t] = x;
            }
        }

        public void Encrypt(byte[] data, int len)
        {
            if (!m_isInitialized)
                return;

            if (len < CRYPTED_SEND_LEN)
                return;

            for (byte t = 0; t < CRYPTED_SEND_LEN; t++)
            {
                m_send_i %= (byte)m_key.Count();
                byte x = (byte)((data[t] ^ m_key[m_send_i]) + m_send_j);
                ++m_send_i;
                data[t] = m_send_j = x;
            }
        }

        public void SetKey(byte[] key)
        {
            System.Diagnostics.Trace.Assert(key.Length != 0);

            m_key = key.ToArray();
        }

        byte[] m_key;
        byte m_send_i, m_send_j, m_recv_i, m_recv_j;
        bool m_isInitialized;
    }

    public class TbcWorldCrypt : LegacyWorldCrypt
    {
        public const uint CRYPTED_SEND_LEN = 6;
        public const uint CRYPTED_RECV_LEN = 4;

        public void Initialize(byte[] sessionKey)
        {
            /*
             case BUILD_243:
            {
                _send_i = _send_j = _recv_i = _recv_j = 0;

                static uint8 seed[SEED_KEY_SIZE] = { 0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2, 0xAA };
                _key = Trinity::Crypto::HMAC_SHA1::GetDigestOf(seed, K);
                break;
            }
             
             */
            byte[] recvSeed = new byte[16] { 0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2, 0xAA };
            HmacHash recvHash = new HmacHash(recvSeed);
            recvHash.Finish(sessionKey, sessionKey.Count());
            m_key = recvHash.Digest.ToArray();

            m_send_i = m_send_j = m_recv_i = m_recv_j = 0;
            m_isInitialized = true;
        }

        public void Decrypt(byte[] data, int len)
        {
            if (len < CRYPTED_RECV_LEN)
                return;

            for (byte t = 0; t < CRYPTED_RECV_LEN; t++)
            {
                m_recv_i %= (byte)m_key.Count();
                byte x = (byte)((data[t] - m_recv_j) ^ m_key[m_recv_i]);
                ++m_recv_i;
                m_recv_j = data[t];
                data[t] = x;
            }
        }

        public void Encrypt(byte[] data, int len)
        {
            if (!m_isInitialized)
                return;

            if (len < CRYPTED_SEND_LEN)
                return;

            for (byte t = 0; t < CRYPTED_SEND_LEN; t++)
            {
                m_send_i %= (byte)m_key.Count();
                byte x = (byte)((data[t] ^ m_key[m_send_i]) + m_send_j);
                ++m_send_i;
                data[t] = m_send_j = x;
            }
        }

        byte[] m_key;
        byte m_send_i, m_send_j, m_recv_i, m_recv_j;
        bool m_isInitialized;
    }

    public class WlkWorldCrypt : LegacyWorldCrypt
    {
        public const uint CRYPTED_SEND_LEN = 6;
        public const uint CRYPTED_RECV_LEN = 4;

        public void Initialize(byte[] sessionKey)
        {

            /*

AuthCrypt::AuthCrypt(ClientBuild build) :
   _initialized(false), clientBuild(build)
{ }

void AuthCrypt::Init(SessionKey const& K)
{
    switch(clientBuild)
    {
#ifdef LICH_KING_CLIENT
        case BUILD_335:
        {
            _serverEncrypt = std::make_unique<Trinity::Crypto::ARC4>();
            _clientDecrypt = std::make_unique<Trinity::Crypto::ARC4>();

            static uint8 ServerEncryptionKey[SEED_KEY_SIZE] = { 0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57 };
            _serverEncrypt->Init(Trinity::Crypto::HMAC_SHA1::GetDigestOf(ServerEncryptionKey, K));
            static uint8 ServerDecryptionKey[SEED_KEY_SIZE] = { 0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE };
            _clientDecrypt->Init(Trinity::Crypto::HMAC_SHA1::GetDigestOf(ServerDecryptionKey, K));

            // Drop first 1024 bytes, as WoW uses ARC4-drop1024.
            std::array<uint8, 1024> syncBuf;
            _serverEncrypt->UpdateData(syncBuf);
            _clientDecrypt->UpdateData(syncBuf);

            _initialized = true;
            break;
        }
#else
        case BUILD_243:
        {
            _send_i = _send_j = _recv_i = _recv_j = 0;

            static uint8 seed[SEED_KEY_SIZE] = { 0x38, 0xA7, 0x83, 0x15, 0xF8, 0x92, 0x25, 0x30, 0x71, 0x98, 0x67, 0xB1, 0x8C, 0x4, 0xE2, 0xAA };
            _key = Trinity::Crypto::HMAC_SHA1::GetDigestOf(seed, K);
            break;
        }
#endif
        default:
            TC_LOG_ERROR("network", "AuthCrypt::Init, wrong build %u given, cannot initialize", uint32(clientBuild));
            return;
    }
    _initialized = true;
}

void AuthCrypt::DecryptRecv(uint8* data, size_t len)
{
    ASSERT(_initialized);

#ifdef LICH_KING_CLIENT
    _clientDecrypt->UpdateData(data, len);
#else
    if (len < CRYPTED_SEND_LEN) 
        return;

    for (size_t t = 0; t < CRYPTED_RECV_LEN; t++)
    {
        _recv_i %= _key.size();
        uint8 x = uint8((data[t] - _recv_j) ^ _key[_recv_i]); // calc can overflow uint8, seems to work though
        ++_recv_i;
        _recv_j = data[t];
        data[t] = x;
    }
#endif
}

void AuthCrypt::EncryptSend(uint8 *data, size_t len)
{
    ASSERT(_initialized);

#ifdef LICH_KING_CLIENT
    _serverEncrypt->UpdateData(data, len);
#else
    if (len < CRYPTED_SEND_LEN) 
        return;

    for (size_t t = 0; t < CRYPTED_SEND_LEN; t++)
    {
        _send_i %= _key.size();
        uint8 x = uint8((data[t] ^ _key[_send_i]) + _send_j); // calc can overflow uint8, seems to work though
        ++_send_i;
        data[t] = _send_j = x;
    }
#endif
}

                        
             */

            byte[] ServerEncryptionKey = new byte[16] { 0xCC, 0x98, 0xAE, 0x04, 0xE8, 0x97, 0xEA, 0xCA, 0x12, 0xDD, 0xC0, 0x93, 0x42, 0x91, 0x53, 0x57 };
            _serverEncrypt = new SARC4();
            _serverEncrypt.PrepareKey(ServerEncryptionKey);
            byte[] ServerDecryptionKey = new byte[16] { 0xC2, 0xB3, 0x72, 0x3C, 0xC6, 0xAE, 0xD9, 0xB5, 0x34, 0x3C, 0x53, 0xEE, 0x2F, 0x43, 0x67, 0xCE };
            _clientDecrypt = new SARC4();
            _clientDecrypt.PrepareKey(ServerDecryptionKey);

            byte[] syncBuf = new byte[1024];
            _serverEncrypt.ProcessBuffer(syncBuf,1024);
            _clientDecrypt.ProcessBuffer(syncBuf, 1024);


            m_isInitialized = true;
        }

        public void Decrypt(byte[] data, int len)
        {
            _clientDecrypt.ProcessBuffer(data, len);
        }

        public void Encrypt(byte[] data, int len)
        {
            _serverEncrypt.ProcessBuffer(data, len);
        }

        byte[] m_key;
        byte m_send_i, m_send_j, m_recv_i, m_recv_j;
        bool m_isInitialized;

        SARC4 _clientDecrypt;
        SARC4 _serverEncrypt;
    }
}
