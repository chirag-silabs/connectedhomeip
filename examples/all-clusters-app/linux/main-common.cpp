/*
 *
 *    Copyright (c) 2020 Project CHIP Authors
 *    All rights reserved.
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include "AllClustersCommandDelegate.h"
#include "AppOptions.h"
#include "ValveControlDelegate.h"
#include "WindowCoveringManager.h"
#include "air-quality-instance.h"
#include "app-common/zap-generated/ids/Clusters.h"
#include "camera-av-settings-user-level-management-instance.h"
#include "dishwasher-mode.h"
#include "include/diagnostic-logs-provider-delegate-impl.h"
#include "include/tv-callbacks.h"
#include "laundry-dryer-controls-delegate-impl.h"
#include "laundry-washer-controls-delegate-impl.h"
#include "laundry-washer-mode.h"
#include "microwave-oven-mode.h"
#include "operational-state-delegate-impl.h"
#include "oven-modes.h"
#include "oven-operational-state-delegate.h"
#include "push-av-stream-transport-delegate-impl.h"
#include "resource-monitoring-delegates.h"
#include "rvc-modes.h"
#include "rvc-operational-state-delegate-impl.h"
#include "tcc-mode.h"
#include "thermostat-delegate-impl.h"

#include <Options.h>
#include <app-common/zap-generated/attributes/Accessors.h>
#include <app/CommandHandler.h>
#include <app/clusters/diagnostic-logs-server/diagnostic-logs-server.h>
#include <app/clusters/identify-server/identify-server.h>
#include <app/clusters/laundry-dryer-controls-server/laundry-dryer-controls-server.h>
#include <app/clusters/laundry-washer-controls-server/laundry-washer-controls-server.h>
#include <app/clusters/mode-base-server/mode-base-server.h>
#include <app/clusters/push-av-stream-transport-server/CodegenIntegration.h>
#include <app/clusters/thermostat-server/thermostat-server.h>
#include <app/clusters/time-synchronization-server/time-synchronization-server.h>
#include <app/clusters/unit-localization-server/unit-localization-server.h>
#include <app/clusters/valve-configuration-and-control-server/valve-configuration-and-control-server.h>
#include <app/server/Server.h>
#include <app/util/attribute-storage.h>
#include <lib/support/CHIPMem.h>
#include <platform/DeviceInstanceInfoProvider.h>
#include <platform/DiagnosticDataProvider.h>
#include <platform/PlatformManager.h>
#include <static-supported-modes-manager.h>
#include <static-supported-temperature-levels.h>
#include <system/SystemPacketBuffer.h>
#include <transport/SessionManager.h>
#include <transport/raw/PeerAddress.h>

#include <string>

using namespace chip;
using namespace chip::app;
using namespace chip::DeviceLayer;

using chip::Protocols::InteractionModel::Status;

namespace {

LowPowerManager sLowPowerManager;
NamedPipeCommands sChipNamedPipeCommands;
AllClustersCommandDelegate sAllClustersCommandDelegate;
Clusters::WindowCovering::WindowCoveringManager sWindowCoveringManager;

Clusters::TemperatureControl::AppSupportedTemperatureLevelsDelegate sAppSupportedTemperatureLevelsDelegate;
Clusters::ModeSelect::StaticSupportedModesManager sStaticSupportedModesManager;
Clusters::ValveConfigurationAndControl::ValveControlDelegate sValveDelegate;
Clusters::TimeSynchronization::ExtendedTimeSyncDelegate sTimeSyncDelegate;
Clusters::PushAvStreamTransport::PushAvStreamTransportManager gPushAvStreamTransportManager;

// Please refer to https://github.com/CHIP-Specifications/connectedhomeip-spec/blob/master/src/namespaces
constexpr const uint8_t kNamespaceCommon   = 7;
constexpr const uint8_t kNamespaceSwitches = 0x43;

// Common Number Namespace: 7, tag 0 (Zero)
constexpr const uint8_t kTagCommonZero = 0;
// Common Number Namespace: 7, tag 1 (One)
constexpr const uint8_t kTagCommonOne = 1;
// Common Number Namespace: 7, tag 2 (Two)
constexpr const uint8_t kTagCommonTwo = 2;
// Switches namespace: 0x43, tag = 0x03 (Up)
constexpr const uint8_t kTagSwitchesUp = 0x03;
// Switches namespace: 0x43, tag = 0x04 (Down)
constexpr const uint8_t kTagSwitchesDown = 0x04;

constexpr const uint8_t kNamespacePosition = 8;
// Common Position Namespace: 8, tag: 0 (Left)
constexpr const uint8_t kTagPositionLeft = 0;
// Common Position Namespace: 8, tag: 1 (Right)
constexpr const uint8_t kTagPositionRight = 1;
// Common Position Namespace: 8, tag: 3 (Bottom)
constexpr const uint8_t kTagPositionBottom                                 = 3;
const Clusters::Descriptor::Structs::SemanticTagStruct::Type gEp0TagList[] = {
    { .namespaceID = kNamespaceCommon, .tag = kTagCommonZero }, { .namespaceID = kNamespacePosition, .tag = kTagPositionBottom }
};
const Clusters::Descriptor::Structs::SemanticTagStruct::Type gEp1TagList[] = {
    { .namespaceID = kNamespaceCommon, .tag = kTagCommonOne }, { .namespaceID = kNamespacePosition, .tag = kTagPositionLeft }
};
const Clusters::Descriptor::Structs::SemanticTagStruct::Type gEp2TagList[] = {
    { .namespaceID = kNamespaceCommon, .tag = kTagCommonTwo }, { .namespaceID = kNamespacePosition, .tag = kTagPositionRight }
};
// Endpoints 3 and 4 are an action switch and a non-action switch. On the device, they're tagged as up and down because why not.
const Clusters::Descriptor::Structs::SemanticTagStruct::Type gEp3TagList[] = { { .namespaceID = kNamespaceSwitches,
                                                                                 .tag         = kTagSwitchesUp } };
const Clusters::Descriptor::Structs::SemanticTagStruct::Type gEp4TagList[] = { { .namespaceID = kNamespaceSwitches,
                                                                                 .tag         = kTagSwitchesDown } };

} // namespace

#ifdef MATTER_DM_PLUGIN_DISHWASHER_ALARM_SERVER
extern void MatterDishwasherAlarmServerInit();
#endif

void OnIdentifyStart(::Identify *)
{
    ChipLogProgress(Zcl, "OnIdentifyStart");
}

void OnIdentifyStop(::Identify *)
{
    ChipLogProgress(Zcl, "OnIdentifyStop");
}

void OnTriggerEffect(::Identify * identify)
{
    switch (identify->mCurrentEffectIdentifier)
    {
    case Clusters::Identify::EffectIdentifierEnum::kBlink:
        ChipLogProgress(Zcl, "Clusters::Identify::EffectIdentifierEnum::kBlink");
        break;
    case Clusters::Identify::EffectIdentifierEnum::kBreathe:
        ChipLogProgress(Zcl, "Clusters::Identify::EffectIdentifierEnum::kBreathe");
        break;
    case Clusters::Identify::EffectIdentifierEnum::kOkay:
        ChipLogProgress(Zcl, "Clusters::Identify::EffectIdentifierEnum::kOkay");
        break;
    case Clusters::Identify::EffectIdentifierEnum::kChannelChange:
        ChipLogProgress(Zcl, "Clusters::Identify::EffectIdentifierEnum::kChannelChange");
        break;
    default:
        ChipLogProgress(Zcl, "No identifier effect");
        return;
    }
}

static Identify gIdentify0 = {
    chip::EndpointId{ 0 }, OnIdentifyStart, OnIdentifyStop, Clusters::Identify::IdentifyTypeEnum::kVisibleIndicator,
    OnTriggerEffect,
};

static Identify gIdentify1 = {
    chip::EndpointId{ 1 }, OnIdentifyStart, OnIdentifyStop, Clusters::Identify::IdentifyTypeEnum::kVisibleIndicator,
    OnTriggerEffect,
};

void ApplicationInit()
{
    std::string path = std::string(LinuxDeviceOptions::GetInstance().app_pipe);
    if ((!path.empty()) and (sChipNamedPipeCommands.Start(path, &sAllClustersCommandDelegate) != CHIP_NO_ERROR))
    {
        ChipLogError(NotSpecified, "Failed to start CHIP NamedPipeCommands");
        sChipNamedPipeCommands.Stop();
    }

#ifdef MATTER_DM_PLUGIN_DISHWASHER_ALARM_SERVER
    MatterDishwasherAlarmServerInit();
#endif
    Clusters::TemperatureControl::SetInstance(&sAppSupportedTemperatureLevelsDelegate);
    Clusters::ModeSelect::setSupportedModesManager(&sStaticSupportedModesManager);

    Clusters::ValveConfigurationAndControl::SetDefaultDelegate(chip::EndpointId(1), &sValveDelegate);
    Clusters::TimeSynchronization::SetDefaultDelegate(&sTimeSyncDelegate);

    Clusters::UnitLocalization::TempUnitEnum supportedUnits[2] = { Clusters::UnitLocalization::TempUnitEnum::kFahrenheit,
                                                                   Clusters::UnitLocalization::TempUnitEnum::kCelsius };
    DataModel::List<Clusters::UnitLocalization::TempUnitEnum> unitsList(supportedUnits);
    VerifyOrDie(Clusters::UnitLocalization::UnitLocalizationServer::Instance().SetSupportedTemperatureUnits(unitsList) ==
                CHIP_NO_ERROR);
    VerifyOrDie(Clusters::UnitLocalization::UnitLocalizationServer::Instance().SetTemperatureUnit(
                    Clusters::UnitLocalization::TempUnitEnum::kFahrenheit) == CHIP_NO_ERROR);

    Clusters::PushAvStreamTransport::SetDelegate(chip::EndpointId(1), &gPushAvStreamTransportManager);

    SetTagList(/* endpoint= */ 0, Span<const Clusters::Descriptor::Structs::SemanticTagStruct::Type>(gEp0TagList));
    SetTagList(/* endpoint= */ 1, Span<const Clusters::Descriptor::Structs::SemanticTagStruct::Type>(gEp1TagList));
    SetTagList(/* endpoint= */ 2, Span<const Clusters::Descriptor::Structs::SemanticTagStruct::Type>(gEp2TagList));
    SetTagList(/* endpoint= */ 3, Span<const Clusters::Descriptor::Structs::SemanticTagStruct::Type>(gEp3TagList));
    SetTagList(/* endpoint= */ 4, Span<const Clusters::Descriptor::Structs::SemanticTagStruct::Type>(gEp4TagList));
}

void ApplicationShutdown()
{
    // These may have been initialised via the emberAfXxxClusterInitCallback methods. We need to destroy them before shutdown.
    Clusters::DishwasherMode::Shutdown();
    Clusters::LaundryWasherMode::Shutdown();
    Clusters::RvcCleanMode::Shutdown();
    Clusters::RvcRunMode::Shutdown();
    Clusters::MicrowaveOvenMode::Shutdown();
    Clusters::RefrigeratorAndTemperatureControlledCabinetMode::Shutdown();
    Clusters::HepaFilterMonitoring::Shutdown();
    Clusters::ActivatedCarbonFilterMonitoring::Shutdown();

    Clusters::AirQuality::Shutdown();
    Clusters::OperationalState::Shutdown();
    Clusters::RvcOperationalState::Shutdown();
    Clusters::OvenMode::Shutdown();
    Clusters::OvenCavityOperationalState::Shutdown();

    if (sChipNamedPipeCommands.Stop() != CHIP_NO_ERROR)
    {
        ChipLogError(NotSpecified, "Failed to stop CHIP NamedPipeCommands");
    }
}

using namespace chip::app::Clusters::LaundryWasherControls;
void emberAfLaundryWasherControlsClusterInitCallback(EndpointId endpoint)
{
    LaundryWasherControlsServer::SetDefaultDelegate(endpoint, &LaundryWasherControlDelegate::getLaundryWasherControlDelegate());
}

using namespace chip::app::Clusters::LaundryDryerControls;
void emberAfLaundryDryerControlsClusterInitCallback(EndpointId endpoint)
{
    LaundryDryerControlsServer::SetDefaultDelegate(endpoint, &LaundryDryerControlDelegate::getLaundryDryerControlDelegate());
}

void emberAfLowPowerClusterInitCallback(EndpointId endpoint)
{
    ChipLogProgress(NotSpecified, "Setting LowPower default delegate to global manager");
    Clusters::LowPower::SetDefaultDelegate(endpoint, &sLowPowerManager);
}

void emberAfWindowCoveringClusterInitCallback(chip::EndpointId endpoint)
{
    sWindowCoveringManager.Init(endpoint);
    Clusters::WindowCovering::SetDefaultDelegate(endpoint, &sWindowCoveringManager);
    Clusters::WindowCovering::ConfigStatusUpdateFeatures(endpoint);
}

using namespace chip::app::Clusters::DiagnosticLogs;
void emberAfDiagnosticLogsClusterInitCallback(chip::EndpointId endpoint)
{
    auto & logProvider = LogProvider::GetInstance();
    logProvider.SetEndUserSupportLogFilePath(AppOptions::GetEndUserSupportLogFilePath());
    logProvider.SetNetworkDiagnosticsLogFilePath(AppOptions::GetNetworkDiagnosticsLogFilePath());
    logProvider.SetCrashLogFilePath(AppOptions::GetCrashLogFilePath());

    DiagnosticLogsServer::Instance().SetDiagnosticLogsProviderDelegate(endpoint, &logProvider);
}

using namespace chip::app::Clusters::Thermostat;
void emberAfThermostatClusterInitCallback(EndpointId endpoint)
{
    // Register the delegate for the Thermostat
    auto & delegate = ThermostatDelegate::GetInstance();

    SetDefaultDelegate(endpoint, &delegate);
}

Status emberAfExternalAttributeReadCallback(EndpointId endpoint, ClusterId clusterId,
                                            const EmberAfAttributeMetadata * attributeMetadata, uint8_t * buffer,
                                            uint16_t maxReadLength)
{

    VerifyOrReturnValue(clusterId == Clusters::UnitTesting::Id, Status::Failure);
    VerifyOrReturnValue(attributeMetadata != nullptr, Status::Failure);

    if (attributeMetadata->attributeId == Clusters::UnitTesting::Attributes::FailureInt32U::Id)
    {
        uint8_t forced_code = 0;
        Status status;

        status = Clusters::UnitTesting::Attributes::ReadFailureCode::Get(endpoint, &forced_code);
        if (status == Status::Success)
        {
            status = static_cast<Status>(forced_code);
        }
        return status;
    }

    // Finally we just do not support external attributes in all-clusters at this point
    return Status::Failure;
}
