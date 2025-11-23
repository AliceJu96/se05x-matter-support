#pragma once

#include <platform/CommissionableDataProvider.h>

namespace chip {
namespace DeviceLayer {

class SE05xCommissionableDataProvider : public CommissionableDataProvider
{
public:
    static CommissionableDataProvider *GetInstance(void);

    CHIP_ERROR GetSetupDiscriminator(uint16_t & setupDiscriminator) override;
    CHIP_ERROR SetSetupDiscriminator(uint16_t setupDiscriminator) override {
        (void)setupDiscriminator;
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }

    CHIP_ERROR GetSetupPasscode(uint32_t & setupPasscode) override;
    CHIP_ERROR SetSetupPasscode(uint32_t setupPasscode) override {
        (void)setupPasscode;
        return CHIP_ERROR_NOT_IMPLEMENTED;
    }

    CHIP_ERROR GetSpake2pIterationCount(uint32_t & iterationCount) override;

    CHIP_ERROR GetSpake2pSalt(chip::MutableByteSpan & saltBuf) override;

    CHIP_ERROR GetSpake2pVerifier(chip::MutableByteSpan & verifierBuf,
                                  size_t & outVerifierLen) override;

private:
    SE05xCommissionableDataProvider()  = default;
    ~SE05xCommissionableDataProvider() = default;

    SE05xCommissionableDataProvider(const SE05xCommissionableDataProvider &)            = delete;
    SE05xCommissionableDataProvider & operator=(const SE05xCommissionableDataProvider &) = delete;
};

} // namespace DeviceLayer
} // namespace chip
