#ifndef CAPABILITY_MODULE_LOADER_H
#define CAPABILITY_MODULE_LOADER_H

#include <QObject>

#include "capability_module_impl.h"
#include "interface.h"
#include "logos_provider_object.h"

class CapabilityModuleLoader : public QObject, public PluginInterface, public LogosProviderPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID LogosProviderPlugin_iid FILE "metadata.json")
    Q_INTERFACES(PluginInterface LogosProviderPlugin)

public:
    QString name() const override { return QStringLiteral("capability_module"); }
    QString version() const override { return QStringLiteral("1.0.0"); }
    LogosProviderObject* createProviderObject() override { return new CapabilityModuleImpl(); }
};

#endif // CAPABILITY_MODULE_LOADER_H
