#ifndef CAPABILITY_MODULE_INTERFACE_H
#define CAPABILITY_MODULE_INTERFACE_H

#include <QString>
#include <QStringList>

#include "interface.h"

// Public API of capability_module. It is internal-layer infrastructure: a
// module developer never calls these directly — requestModule is invoked under
// the hood by the SDK when one module first calls another, and
// registerRestriction is invoked by core when it installs the access policy.
class CapabilityModuleInterface : public PluginInterface
{
public:
    virtual ~CapabilityModuleInterface() = default;

    // Mint an auth token allowing `fromModuleName` to call `moduleName`, inform
    // the target of the new token, and return it to the caller.
    Q_INVOKABLE virtual QString requestModule(const QString& fromModuleName,
                                              const QString& moduleName) = 0;

    // Register an access restriction: only the listed caller modules may obtain
    // a token for (and therefore call) `targetModule`. `authToken` must be the
    // trusted core/capability_module token.
    Q_INVOKABLE virtual bool registerRestriction(const QString& authToken,
                                                 const QString& targetModule,
                                                 const QStringList& allowedCallers) = 0;
};

#define CapabilityModuleInterface_iid "org.logos.CapabilityModuleInterface"
Q_DECLARE_INTERFACE(CapabilityModuleInterface, CapabilityModuleInterface_iid)

#endif // CAPABILITY_MODULE_INTERFACE_H
