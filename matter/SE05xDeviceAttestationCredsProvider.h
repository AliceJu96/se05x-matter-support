#pragma once

#include <credentials/DeviceAttestationCredsProvider.h>

namespace chip {
namespace Credentials {

class SE05xDeviceAttestationCredentialsProvider : public DeviceAttestationCredentialsProvider
{
public:
    static DeviceAttestationCredentialsProvider *GetInstance(void);

    CHIP_ERROR GetCertificationDeclaration(MutableByteSpan & out_cd_buffer) override;
    CHIP_ERROR GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer) override;
    CHIP_ERROR GetDeviceAttestationCert(MutableByteSpan & out_dac_buffer) override;
    CHIP_ERROR GetProductAttestationIntermediateCert(MutableByteSpan & out_pai_buffer) override;
    CHIP_ERROR SignWithDeviceAttestationKey(const ByteSpan & message_to_sign,
                                            MutableByteSpan & out_signature_buffer) override;

private:
    SE05xDeviceAttestationCredentialsProvider()  = default;
    ~SE05xDeviceAttestationCredentialsProvider() = default;

    SE05xDeviceAttestationCredentialsProvider(const SE05xDeviceAttestationCredentialsProvider &)            = delete;
    SE05xDeviceAttestationCredentialsProvider & operator=(const SE05xDeviceAttestationCredentialsProvider &) = delete;
};

} // namespace Credentials
} // namespace chip
