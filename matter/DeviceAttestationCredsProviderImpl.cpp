#include <lib/core/CHIPError.h>
#include <lib/support/Span.h>

#include "DeviceAttestationCredsProviderImpl.h"
#include "se051h/se05x_attestation.h"

using chip::ByteSpan;
using chip::MutableByteSpan;

namespace chip {
namespace Credentials {

DeviceAttestationCredentialsProviderImpl &
DeviceAttestationCredentialsProviderImpl::GetInstance()
{
    static DeviceAttestationCredentialsProviderImpl sInstance;
    return sInstance;
}

CHIP_ERROR DeviceAttestationCredentialsProviderImpl::GetCertificationDeclaration(
    MutableByteSpan & out_cd_buffer)
{
    size_t capacity  = out_cd_buffer.size();
    size_t size = capacity;

    int err = se05x_attestation_get_cd(out_cd_buffer.data(), &size);
    if (err)
    {
        return CHIP_ERROR_INTERNAL;
    }

    if (size > capacity)
    {
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }

    out_cd_buffer.reduce_size(size);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceAttestationCredentialsProviderImpl::GetFirmwareInformation(
    MutableByteSpan & out_firmware_info_buffer)
{
    out_firmware_info_buffer.reduce_size(0);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceAttestationCredentialsProviderImpl::GetDeviceAttestationCert(
    MutableByteSpan & out_dac_buffer)
{
    size_t capacity  = out_dac_buffer.size();
    size_t size = capacity;

    int err = se05x_attestation_get_device_cert(out_dac_buffer.data(), &size);
    if (err != 0)
    {
        return CHIP_ERROR_INTERNAL;
    }

    if (size > capacity)
    {
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }

    out_dac_buffer.reduce_size(size);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceAttestationCredentialsProviderImpl::GetProductAttestationIntermediateCert(
    MutableByteSpan & out_pai_buffer)
{
    size_t capacity  = out_pai_buffer.size();
    size_t size = capacity;

    int err = se05x_attestation_get_intermediate_cert(out_pai_buffer.data(), &size);
    if (err != 0)
    {
        return CHIP_ERROR_INTERNAL;
    }

    if (size > capacity)
    {
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }

    out_pai_buffer.reduce_size(size);

    return CHIP_NO_ERROR;
}

CHIP_ERROR DeviceAttestationCredentialsProviderImpl::SignWithDeviceAttestationKey(
    const ByteSpan & message_to_sign, MutableByteSpan & out_signature_buffer)
{
    size_t capacity  = out_signature_buffer.size();
    size_t size = capacity;

    int err = se05x_attestation_sign(
        message_to_sign.data(), message_to_sign.size(),
        out_signature_buffer.data(), &size);
    if (err != 0)
    {
        return CHIP_ERROR_INTERNAL;
    }

    if (size > capacity)
    {
        return CHIP_ERROR_BUFFER_TOO_SMALL;
    }

    out_signature_buffer.reduce_size(size);

    return CHIP_NO_ERROR;
}

} // namespace Credentials
} // namespace chip