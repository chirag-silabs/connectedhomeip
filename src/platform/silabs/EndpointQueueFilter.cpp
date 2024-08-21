#include "EndpointQueueFilter.h"
#include <string.h>
#include <lib/support/BytesToHex.h>
#include <support/CodeUtils.h>
#include <support/logging/CHIPLogging.h>
namespace chip {
namespace Inet {

using FilterOutcome = EndpointQueueFilter::FilterOutcome;

namespace {

bool IsValidMdnsHostName(const CharSpan & hostName)
{
    for (size_t i = 0; i < hostName.size(); ++i)
    {
        char ch_data = *(hostName.data() + i);
        if (!((ch_data >= '0' && ch_data <= '9') || (ch_data >= 'A' && ch_data <= 'F')))
        {
            return false;
        }
    }
    return true;
}

bool IsMdnsBroadcastPacket(const IPPacketInfo & pktInfo, const System::PacketBufferHandle & pktPayload)
{
    // if the packet is not a broadcast packet to mDNS port, drop it.
    VerifyOrReturnValue(pktInfo.DestPort == 5353, false);
#if INET_CONFIG_ENABLE_IPV4
    ip_addr_t mdnsIPv4BroadcastAddr = IPADDR4_INIT_BYTES(224, 0, 0, 251);
    if(pktInfo.DestAddress == Inet::IPAddress(mdnsIPv4BroadcastAddr))
    {
        return true;
    }
#endif
    ip_addr_t mdnsIPv6BroadcastAddr = IPADDR6_INIT_HOST(0xFF020000, 0, 0, 0xFB);
    if(pktInfo.DestAddress == Inet::IPAddress(mdnsIPv6BroadcastAddr))
    {
        return true;
    }
    return false;
}

static bool CaseInsensitiveCompare(const CharSpan & buffer1, const CharSpan & buffer2, size_t size)
{
    for (size_t i = 0; i < size; ++i)
    {
        char byte1 = (*(buffer1.data() + i) >= 'A' && *(buffer1.data() + i) <= 'Z') ? *(buffer1.data() + i) - 'A' + 'a' : *(buffer1.data() + i);
        char byte2 = (*(buffer2.data() + i) >= 'A' && *(buffer2.data() + i) <= 'Z') ? *(buffer2.data() + i) - 'A' + 'a' : *(buffer2.data() + i);
        if (byte1 != byte2)
        {
            return false;
        }
    }
    return true;
}

bool PayloadContainsCaseInsensitive(const System::PacketBufferHandle & payload, const ByteSpan & pattern)
{
    if (payload->TotalLength() == 0 || pattern.size() == 0)
    {
        return false;
    }

    if (payload->HasChainedBuffer() || payload->TotalLength() < pattern.size())
    {
        return false;
    }

    CharSpan payloadView(reinterpret_cast<char *>(payload->Start()), payload->TotalLength());
    CharSpan patternView((char *)(pattern.data()), pattern.size());

    for (size_t i = 0; i <= payloadView.size() - patternView.size(); ++i)
    {
        if (CaseInsensitiveCompare(payloadView.SubSpan(i, patternView.size()), patternView, patternView.size()))
        {
            return true;
        }
    }
    return false;
}

} // namespace

FilterOutcome HostNameFilter::Filter(const void * endpoint, const IPPacketInfo & pktInfo,
                                     const System::PacketBufferHandle & pktPayload)
{
    // Drop the mDNS packets which don't contain 'matter' or '<device-hostname>'.
    const uint8_t matterBytes[] = { 'm', 'a', 't', 't', 'e', 'r' };
    if (PayloadContainsCaseInsensitive(pktPayload, ByteSpan(matterBytes)) ||
        PayloadContainsCaseInsensitive(pktPayload, ByteSpan(mHostName)))
    {
        return FilterOutcome::kAllowPacket;
    }
    return FilterOutcome::kDropPacket;
}

CHIP_ERROR HostNameFilter::SetHostName(const CharSpan & hostName)
{
    ReturnErrorCodeIf(!IsValidMdnsHostName(hostName), CHIP_ERROR_INVALID_ARGUMENT);
    memcpy(mHostName, hostName.data(), hostName.size());
    return CHIP_NO_ERROR;
}

namespace SilabsEndpointQueueFilter {

EndpointQueueFilter::EndpointQueueFilter() : mTooManyFilter(kDefaultAllowedQueuedPackets) {}

EndpointQueueFilter::EndpointQueueFilter(size_t maxAllowedQueuedPackets) : mTooManyFilter(maxAllowedQueuedPackets) {}

FilterOutcome EndpointQueueFilter::FilterBeforeEnqueue(const void * endpoint, const IPPacketInfo & pktInfo,
                                                       const System::PacketBufferHandle & pktPayload)
{
    VerifyOrReturnError(FilterOutcome::kAllowPacket == mTooManyFilter.FilterBeforeEnqueue(endpoint, pktInfo, pktPayload),
                        FilterOutcome::kDropPacket);

    if (!IsMdnsBroadcastPacket(pktInfo, pktPayload))
    {
        return FilterOutcome::kAllowPacket;
    }
    return mHostNameFilter.Filter(endpoint, pktInfo, pktPayload);
}

FilterOutcome EndpointQueueFilter::FilterAfterDequeue(const void * endpoint, const IPPacketInfo & pktInfo,
                                                      const System::PacketBufferHandle & pktPayload)
{
    return mTooManyFilter.FilterAfterDequeue(endpoint, pktInfo, pktPayload);
}

} // namespace SilabsEndpointQueueFilter
} // namespace Inet
} // namespace chip
