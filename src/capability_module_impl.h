#ifndef CAPABILITY_MODULE_IMPL_H
#define CAPABILITY_MODULE_IMPL_H

#include <QHash>
#include <QSet>
#include <QString>
#include <QStringList>

#include "logos_provider_object.h"

class CapabilityModuleImpl : public LogosProviderBase
{
    LOGOS_PROVIDER(CapabilityModuleImpl, "capability_module", "1.0.0")

public:
    LOGOS_METHOD QString requestModule(const QString& fromModuleName, const QString& moduleName);

    // Register an access restriction: only the listed caller modules may
    // obtain a token for (and therefore call) `targetModule`. Called by
    // core after it parses the access policy.
    //
    // `authToken` must be the trusted core/capability_module auth token —
    // the same gate informModuleToken uses. ModuleProxy::isAuthorized lets
    // ANY loaded module reach this method (it accepts any issued token), so
    // without this explicit check a malicious module could relax or
    // overwrite restrictions to grant itself access. Only core holds the
    // trusted token, so peers cannot forge it. Returns true on success.
    LOGOS_METHOD bool registerRestriction(const QString& authToken, const QString& targetModule, const QStringList& allowedCallers);

private:
    // target module -> set of caller modules allowed to reach it. A target
    // absent from this map is unrestricted (back-compat default). Populated
    // only by registerRestriction; consulted in requestModule.
    QHash<QString, QSet<QString>> m_restrictions;
};

#endif // CAPABILITY_MODULE_IMPL_H
