#include "se05x_spake2p.h"
#include "SE05xCommissionableDataProvider.h"

namespace chip {
namespace DeviceLayer {

CommissionableDataProvider * 
SE05xCommissionableDataProvider::GetInstance(void)
{
    static SE05xCommissionableDataProvider instance;
    return &instance;
}

CHIP_ERROR SE05xCommissionableDataProvider::GetSetupDiscriminator(uint16_t &setupDiscriminator)
{
    setupDiscriminator = 3840;  // TODO
    return CHIP_NO_ERROR;
}

CHIP_ERROR SE05xCommissionableDataProvider::GetSetupPasscode(uint32_t &setupPasscode)
{
    uint32_t passcode = 0;
    int err = se05x_spake2p_get_passcode(SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM, &passcode);
    if (err) {
        return CHIP_ERROR_INTERNAL;
    }
    setupPasscode = passcode;

    return CHIP_NO_ERROR;
}

CHIP_ERROR SE05xCommissionableDataProvider::GetSpake2pIterationCount(uint32_t &iterationCount)
{
    uint32_t count = 0;
    int err = se05x_spake2p_get_iter_count(SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM, &count);
    if (err) {
        return CHIP_ERROR_INTERNAL;
    }
    iterationCount = count;

    return CHIP_NO_ERROR;
}

CHIP_ERROR SE05xCommissionableDataProvider::GetSpake2pSalt(chip::MutableByteSpan & saltBuf)
{
    size_t saltSize = saltBuf.size();
    int err = se05x_spake2p_get_salt(SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM,
                                     saltBuf.data(), &saltSize);
    if (err) {
        return CHIP_ERROR_INTERNAL;
    }
    if (saltSize > saltBuf.size()) {
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }
    saltBuf = chip::MutableByteSpan(saltBuf.data(), saltSize);

    return CHIP_NO_ERROR;
}

CHIP_ERROR SE05xCommissionableDataProvider::GetSpake2pVerifier(chip::MutableByteSpan & verifierBuf,
                                                               size_t & outVerifierLen)
{
    uint8_t w0[SE05X_SPAKE2P_W0_SIZE];
    uint8_t L[SE05X_SPAKE2P_L_SIZE];

    int err = se05x_spake2p_get_verifier(SE05X_SPAKE2P_PASSCODE_TYPE_CUSTOM, w0, L);
    if (err) {
        return CHIP_ERROR_INTERNAL;
    }

    constexpr size_t kVerifierLen = SE05X_SPAKE2P_W0_SIZE + SE05X_SPAKE2P_L_SIZE;
    if (verifierBuf.size() < kVerifierLen) {
        outVerifierLen = kVerifierLen;
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }
    // verifier = w0 || L
    memcpy(verifierBuf.data(), w0, SE05X_SPAKE2P_W0_SIZE);
    memcpy(verifierBuf.data() + SE05X_SPAKE2P_W0_SIZE, L, SE05X_SPAKE2P_L_SIZE);

    outVerifierLen = kVerifierLen;

    verifierBuf = chip::MutableByteSpan(verifierBuf.data(), kVerifierLen);

    return CHIP_NO_ERROR;
}

} // namespace DeviceLayer
} // namespace chip
