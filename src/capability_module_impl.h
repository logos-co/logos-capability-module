#ifndef CAPABILITY_MODULE_IMPL_H
#define CAPABILITY_MODULE_IMPL_H

#include <QString>

#include "logos_provider_object.h"

class CapabilityModuleImpl : public LogosProviderBase
{
    LOGOS_PROVIDER(CapabilityModuleImpl, "capability_module", "1.0.0")

public:
    LOGOS_METHOD QString requestModule(const QString& fromModuleName, const QString& moduleName);
};

#endif // CAPABILITY_MODULE_IMPL_H
